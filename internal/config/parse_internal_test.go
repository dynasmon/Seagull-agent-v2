package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

func certificatePEM(t testing.TB, authority bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "platform"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0),
		BasicConstraintsValid: true, IsCA: authority}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func publicKeyPEM(t testing.TB) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func refusedWithin(t *testing.T, err error, sentinels ...error) {
	t.Helper()
	if len(err.Error()) > 1<<10 {
		t.Fatalf("a refusal of %d bytes: %.200s", len(err.Error()), err)
	}
	for _, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			return
		}
	}
	if len(sentinels) > 0 {
		t.Fatalf("a refusal that names no reason the agent reports: %v", err)
	}
}

// Whatever the file holds, the agent reads it as settings it writes back the
// same way, or refuses it as a configuration that is not one or is newer.
func FuzzParse(f *testing.F) {
	shipped, err := os.ReadFile("../../packaging/linux/agent.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(shipped)
	written, err := defaults().Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(written)
	for _, seed := range []string{
		`{"format": 1, "logging": {"level": "debug"}, "spool": {"max_bytes": "64MiB", "max_age": "36h"}}`,
		`{"format": 1, "modules": {"files": {"enabled": true, "paths": ["/etc"], "exclude": ["*.swp"], "interval": "30m"}}}`,
		`{"format": 1, "format": 1}`,
		`{"format": 2}`,
		`{"format": 1, "server": null}`,
		`{"format": 1} {"format": 1}`,
		`{"format": 1, "transport": {"max_batch_bytes": "999999999999999GiB"}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		settings, err := parse(content)
		if err != nil {
			refusedWithin(t, err, ErrInvalid, ErrNewer)
			return
		}
		encoded, err := settings.Encode()
		if err != nil {
			t.Fatalf("settings that were read cannot be written: %v", err)
		}
		again, err := parse(encoded)
		if err != nil {
			t.Fatalf("settings were written as %s, which does not read: %v", encoded, err)
		}
		if rewritten, err := again.Encode(); err != nil || !bytes.Equal(rewritten, encoded) {
			t.Fatalf("settings were written as %s, and once read again as %s: %v", encoded, rewritten, err)
		}
	})
}

func FuzzAddress(f *testing.F) {
	for _, seed := range []string{"https://gateway.example:8443", "https://[2001:db8::1]:8446/seagull/", "https://user:secret@gateway.example", "http://gateway.example",
		"https://gateway.example/a/../b", "https://gateway.example?query", "https://%zz", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		reached, err := address("server.ingest_url", raw)
		if err != nil {
			refusedWithin(t, err)
			return
		}
		if again, err := address("server.ingest_url", reached); err != nil || again != reached {
			t.Fatalf("%q was taken as %q, which is taken as %q: %v", raw, reached, again, err)
		}
	})
}

func FuzzAuthorities(f *testing.F) {
	authority, leaf := certificatePEM(f, true), certificatePEM(f, false)
	f.Add(authority)
	f.Add(append(append([]byte{}, authority...), authority...))
	f.Add(leaf)
	f.Add(append([]byte("# the platform's authorities\n"), authority...))
	f.Add(publicKeyPEM(f))
	f.Fuzz(func(t *testing.T, content []byte) {
		held, err := authorities(content)
		if err != nil {
			refusedWithin(t, err)
			return
		}
		var written []byte
		for _, certificate := range held {
			if !certificate.BasicConstraintsValid || !certificate.IsCA {
				t.Fatalf("%s, which is not an authority, was trusted", certificate.Subject)
			}
			written = append(written, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
		}
		again, err := authorities(written)
		if err != nil || len(again) != len(held) {
			t.Fatalf("the authorities read were written back as a bundle that reads as %d: %v", len(again), err)
		}
		for i := range held {
			if !again[i].Equal(held[i]) {
				t.Fatalf("authority %d reads as another once written back", i)
			}
		}
	})
}

func FuzzPublicKeys(f *testing.F) {
	key := publicKeyPEM(f)
	f.Add(key)
	f.Add(append(append([]byte{}, key...), publicKeyPEM(f)...))
	f.Add(append(append([]byte{}, key...), key...))
	f.Add(certificatePEM(f, true))
	f.Fuzz(func(t *testing.T, content []byte) {
		held, err := publicKeys(content)
		if err != nil {
			refusedWithin(t, err)
			return
		}
		var written []byte
		for _, key := range held {
			if key.Curve != elliptic.P256() {
				t.Fatalf("a key over %s was accepted", key.Curve.Params().Name)
			}
			der, err := x509.MarshalPKIXPublicKey(key)
			if err != nil {
				t.Fatal(err)
			}
			written = append(written, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})...)
		}
		again, err := publicKeys(written)
		if err != nil || len(again) != len(held) {
			t.Fatalf("the keys read were written back as a file that reads as %d: %v", len(again), err)
		}
		for i := range held {
			if !again[i].Equal(held[i]) {
				t.Fatalf("key %d reads as another once written back", i)
			}
		}
	})
}
