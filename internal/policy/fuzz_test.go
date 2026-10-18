package policy_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/dsse"
	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

// The policies recorded platforms served, with the keys that signed them, so
// the fuzzer starts from envelopes a platform wrote.
func recorded(f *testing.F) ([][]byte, []*ecdsa.PublicKey) {
	f.Helper()
	signers, err := filepath.Glob("../../tests/compatibility/testdata/backend-*/*-signers.pem")
	if err != nil || len(signers) == 0 {
		f.Fatalf("find the recorded signers: %v", err)
	}
	var envelopes [][]byte
	var keys []*ecdsa.PublicKey
	for _, named := range signers {
		content, err := os.ReadFile(named)
		if err != nil {
			f.Fatal(err)
		}
		for block, rest := pem.Decode(content); block != nil; block, rest = pem.Decode(rest) {
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				f.Fatal(err)
			}
			keys = append(keys, parsed.(*ecdsa.PublicKey))
		}
		served, err := os.ReadFile(filepath.Join(filepath.Dir(named), filepath.Base(named[:len(named)-len("-signers.pem")])+"-served.reply.pb"))
		if err != nil {
			f.Fatal(err)
		}
		envelopes = append(envelopes, served)
	}
	return envelopes, keys
}

func FuzzVerify(f *testing.F) {
	envelopes, keys := recorded(f)
	key := signingKey(f)
	held, err := policy.NewVerifier(append(keys, &key.PublicKey))
	if err != nil {
		f.Fatal(err)
	}
	for _, served := range envelopes {
		f.Add(served)
	}
	f.Add(signed(f, named(7, "web-01"), key))
	f.Add(sealed(f, "application/json", []byte(`{"revision": 7}`), key))
	f.Add(signed(f, named(7, "web-01")))
	f.Fuzz(func(t *testing.T, served []byte) {
		verified, err := held.Verify(served)
		if _, again := held.Verify(served); (err == nil) != (again == nil) {
			t.Fatalf("the same envelope was read and then refused: %v, %v", err, again)
		}
		if err != nil {
			if !errors.Is(err, policy.ErrMalformed) && !errors.Is(err, policy.ErrUnsigned) {
				t.Fatalf("a refusal that names no reason: %v", err)
			}
			return
		}
		var envelope policyv1.SignedPolicy
		if err := proto.Unmarshal(served, &envelope); err != nil || envelope.GetPayloadType() != policy.PayloadType {
			t.Fatalf("an envelope of another type was read: %v", err)
		}
		digest := sha256.Sum256(dsse.PAE(policy.PayloadType, envelope.GetPayload()))
		signedByAKey := false
		for _, signature := range envelope.GetSignatures() {
			for _, candidate := range append(keys, &key.PublicKey) {
				signedByAKey = signedByAKey || ecdsa.VerifyASN1(candidate, digest[:], signature.GetSig())
			}
		}
		var payload policyv1.Policy
		whole := sha256.Sum256(served)
		switch {
		case !signedByAKey:
			t.Fatal("a policy no accepted key signed was read")
		case proto.Unmarshal(envelope.GetPayload(), &payload) != nil || !proto.Equal(&payload, verified.Policy):
			t.Fatalf("the agent read %v out of a payload that holds %v", verified.Policy, &payload)
		case verified.Digest != hex.EncodeToString(whole[:]) || !bytes.Equal(verified.Envelope, served):
			t.Fatal("the envelope is held as other bytes than were served")
		}
	})
}

func budgetsOf(c config.Config) []int64 {
	return []int64{int64(c.Spool.MaxBytes), int64(c.Spool.MaxAge), int64(c.Transport.MaxBatchBytes), int64(c.Transport.MaxUploadBytesPerSecond),
		int64(c.Transport.MaxEventsPerBatch), int64(c.Transport.MaxInventoryRecordsPerBatch), int64(c.Resources.MemoryLimit),
		int64(c.Resources.MaxScanBytesPerSecond), int64(c.Resources.MaxConcurrentScans), int64(c.Resources.MaxConcurrentUploads)}
}

// Whatever a signed policy sets, the agent runs on its own configuration with
// no budget raised and nothing changed that a policy does not reach.
func FuzzOverlay(f *testing.F) {
	own := local(f, `, "modules": {"authentication": {"enabled": true}, "inventory": {"enabled": true, "interval": "2h"}}`)
	for _, settings := range []*policyv1.Settings{
		{LogLevel: policyv1.LogLevel_LOG_LEVEL_DEBUG},
		{Modules: []*policyv1.ModuleSettings{
			{Module: policyv1.Module_MODULE_AUTHENTICATION, Collection: policyv1.Collection_COLLECTION_DISABLED},
			{Module: policyv1.Module_MODULE_INVENTORY, Interval: durationpb.New(6 * time.Hour)},
			{Module: policyv1.Module_MODULE_FILES, Collection: policyv1.Collection_COLLECTION_ENABLED,
				Paths: &policyv1.Paths{Paths: []string{"/etc", "/usr/bin"}}, Exclude: &policyv1.Paths{Paths: []string{"*.swp"}}},
		}},
		{Budgets: &policyv1.Budgets{SpoolMaxBytes: 64 << 20, MaxEventsPerBatch: 100, MemoryLimitBytes: 1 << 40, SpoolMaxAge: durationpb.New(time.Hour)}},
		{Assessment: &assessmentv1.Checklist{Checks: []*assessmentv1.Check{{CheckId: "ssh-root-login"}}}},
	} {
		content, err := proto.Marshal(settings)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(content)
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		var settings policyv1.Settings
		if proto.Unmarshal(content, &settings) != nil {
			return
		}
		before, err := own.Encode()
		if err != nil {
			t.Fatal(err)
		}
		made, kept, err := policy.Overlay(own, &settings)
		if after, _ := own.Encode(); !bytes.Equal(before, after) {
			t.Fatalf("laying a policy over the configuration changed the configuration itself")
		}
		if err != nil {
			if !errors.Is(err, policy.ErrMalformed) && !errors.Is(err, policy.ErrInapplicable) {
				t.Fatalf("a refusal that names no reason: %v", err)
			}
			return
		}
		for i, budget := range budgetsOf(made) {
			if budget > budgetsOf(own)[i] {
				t.Fatalf("budget %d was raised from %d to %d", i, budgetsOf(own)[i], budget)
			}
		}
		switch {
		case !reflect.DeepEqual(made.Identity, own.Identity), !reflect.DeepEqual(made.Server, own.Server),
			!reflect.DeepEqual(made.Updates, own.Updates), !reflect.DeepEqual(made.Policy, own.Policy), !reflect.DeepEqual(made.Reporting, own.Reporting),
			made.Transport.ConnectTimeout != own.Transport.ConnectTimeout, made.Transport.RequestTimeout != own.Transport.RequestTimeout,
			made.Transport.MaxResponseBytes != own.Transport.MaxResponseBytes, made.Logging.Format != own.Logging.Format,
			made.Resources.ShutdownTimeout != own.Resources.ShutdownTimeout:
			t.Fatalf("a policy reached a setting it does not set: %+v", made)
		}
		for _, held := range kept {
			if held.Own == "" || held.Asked == "" || held.Setting == "" {
				t.Fatalf("a budget kept says %+v", held)
			}
		}
		if _, err := config.Validated(made); err != nil {
			t.Fatalf("the configuration a policy made is not one the agent runs on: %v", err)
		}
	})
}

// Whatever the file the agent kept its policy in holds, what reads back is
// written back as what reads the same, and anything else is refused as damaged
// or newer.
func FuzzStore(f *testing.F) {
	for _, seed := range []string{
		`{"format":1,"revision":7,"digest_sha256":"ab","applied_at":"2026-10-10T12:00:00Z","envelope":"ZW52ZWxvcGU="}`,
		`{"format":1,"revision":7,"digest_sha256":"ab","applied_at":"2026-10-10T14:00:00+02:00","envelope":"ZW52ZWxvcGU="}` + "\n",
		`{"format":2}`,
		`{"format":1,"revision":0,"digest_sha256":"ab","applied_at":"2026-10-10T12:00:00Z","envelope":"ZW52ZWxvcGU="}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		store, directory := opened(t)
		if err := os.WriteFile(filepath.Join(directory, "policy.json"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		held, found, err := store.Read()
		if err != nil {
			if !errors.Is(err, policy.ErrDamaged) && !errors.Is(err, policy.ErrNewer) {
				t.Fatalf("a refusal that names no reason: %v", err)
			}
			return
		}
		if !found {
			t.Fatal("a policy kept was not found")
		}
		if _, err := store.Keep(policy.Verified{Policy: &policyv1.Policy{Revision: held.Revision}, Digest: held.Digest, Envelope: held.Envelope}, held.AppliedAt); err != nil {
			t.Fatalf("a policy read back cannot be kept again: %v", err)
		}
		again, found, err := store.Read()
		if err != nil || !found || again.Revision != held.Revision || again.Digest != held.Digest || !again.AppliedAt.Equal(held.AppliedAt) || !bytes.Equal(again.Envelope, held.Envelope) {
			t.Fatalf("a policy read as %+v reads as %+v once kept again: %v", held, again, err)
		}
	})
}
