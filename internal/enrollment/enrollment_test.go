package enrollment_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func TestARequestIsMadeWithAKeyOfItsOwnAndKeptAcrossRestarts(t *testing.T) {
	held := install(t)
	asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	if asked.AgentID != "web-01" || asked.Again {
		t.Fatalf("asked %+v", asked)
	}
	requested := parseRequest(t, asked.Request)
	if requested.Subject.CommonName != "web-01" || digest(requested.RawSubjectPublicKeyInfo) != asked.KeyID {
		t.Fatalf("the request asks to be %s with key %s, the installation asked with %s",
			requested.Subject.CommonName, digest(requested.RawSubjectPublicKeyInfo), asked.KeyID)
	}
	if _, err := held.keys.Open(asked.KeyID); err != nil {
		t.Fatalf("the key of the request does not open: %v", err)
	}

	held = held.reopen(t)
	if pending, ok := held.installation.Pending(); !ok || pending.AgentID != "web-01" || pending.KeyID != asked.KeyID || pending.RequestedAt.IsZero() {
		t.Fatalf("after a restart the installation asks for %+v (%t)", pending, ok)
	}
}

func TestAskingAgainForTheSameAgentMakesTheSameRequest(t *testing.T) {
	held := install(t)
	first, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	held = held.reopen(t)
	again, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask again: %v", err)
	}
	if !again.Again || again.KeyID != first.KeyID || digest(parseRequest(t, again.Request).RawSubjectPublicKeyInfo) != first.KeyID {
		t.Fatalf("asked again as %+v, first as %+v", again, first)
	}
	if keys := held.keysHeld(t); len(keys) != 1 {
		t.Fatalf("asking twice drew %d keys", len(keys))
	}
}

func TestAskingForAnotherAgentDrawsAnotherKey(t *testing.T) {
	held := install(t)
	first, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask to be web-01: %v", err)
	}
	other, err := enrollment.Request(held.installation, held.keys, "web-02", time.Now())
	if err != nil {
		t.Fatalf("ask to be web-02: %v", err)
	}
	if other.KeyID == first.KeyID || other.Again {
		t.Fatalf("asked to be web-02 with %+v, and to be web-01 with %+v", other, first)
	}
	if pending, _ := held.installation.Pending(); pending.AgentID != "web-02" || pending.KeyID != other.KeyID {
		t.Fatalf("the installation asks for %+v", pending)
	}
}

func TestARequestTheInstallationMayNotMakeDrawsNoKey(t *testing.T) {
	signing := newPlatform(t, "Seagull agents")
	held := install(t)
	for _, agentID := range []string{"", "web 01", "-web-01", strings.Repeat("w", 65)} {
		if _, err := enrollment.Request(held.installation, held.keys, agentID, time.Now()); !errors.Is(err, identity.ErrUnasked) {
			t.Errorf("asking to be %q returned %v", agentID, err)
		}
	}
	if keys := held.keysHeld(t); len(keys) != 0 {
		t.Fatalf("refused requests drew %d keys", len(keys))
	}

	held.enroll(t, signing, "web-01")
	if _, err := enrollment.Request(held.installation, held.keys, "db-07", time.Now()); !errors.Is(err, identity.ErrUnasked) {
		t.Fatalf("an installation enrolled as web-01 asked to be db-07: %v", err)
	}
	if keys := held.keysHeld(t); len(keys) != 1 {
		t.Fatalf("the refused request drew a key: the installation holds %d", len(keys))
	}
}

func TestARequestWhoseKeyIsGoneIsMadeAgainWithAnotherKey(t *testing.T) {
	signing := newPlatform(t, "Seagull agents")
	for name, lose := range map[string]func(path string) error{
		"a key that is missing": os.Remove,
		"a key that is damaged": func(path string) error { return os.WriteFile(path, []byte("damaged"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			held := install(t)
			lost, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
			if err != nil {
				t.Fatalf("ask for a certificate: %v", err)
			}
			if err := lose(filepath.Join(held.directory, "keys", lost.KeyID+".pem")); err != nil {
				t.Fatalf("lose the key: %v", err)
			}
			asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
			if err != nil {
				t.Fatalf("ask again without the key: %v", err)
			}
			if asked.Again || asked.KeyID == lost.KeyID || asked.Abandoned != lost.KeyID {
				t.Fatalf("asked again as %+v after losing key %s", asked, lost.KeyID)
			}
			if _, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), signing.issue(t, lost.Request, nil, nil), time.Now()); !errors.Is(err, enrollment.ErrMismatched) {
				t.Fatalf("the certificate issued for the lost key was imported: %v", err)
			}
			if _, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), signing.issue(t, asked.Request, nil, nil), time.Now()); err != nil {
				t.Fatalf("import the certificate issued for the new key: %v", err)
			}
		})
	}
}

func TestARequestWhoseKeyOthersCouldReadIsNotMadeAgain(t *testing.T) {
	held := install(t)
	asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	if err := os.Chmod(filepath.Join(held.directory, "keys", asked.KeyID+".pem"), 0o644); err != nil {
		t.Fatalf("expose the key: %v", err)
	}
	if _, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now()); !errors.Is(err, pki.ErrKeyInsecure) {
		t.Fatalf("asking again with a key others could read returned %v", err)
	}
}

func TestTheCertificateIssuedForTheRequestBecomesTheFirstGeneration(t *testing.T) {
	signing := newPlatform(t, "Seagull agents")
	held := install(t)
	asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	issued := signing.issue(t, asked.Request, nil, nil)
	imported, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), issued, time.Now())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	leaf := issuedLeaf(t, issued)
	want := identity.Enrollment{AgentID: "web-01", Generation: 1, KeyID: asked.KeyID, Certificate: identity.Certificate{
		Subject:           "web-01",
		Serial:            hex.EncodeToString(leaf.SerialNumber.Bytes()),
		FingerprintSHA256: digest(leaf.Raw),
		NotBefore:         leaf.NotBefore.UTC(),
		NotAfter:          leaf.NotAfter.UTC(),
	}}
	if imported.Already || imported.Issuer != "Seagull agents" || len(imported.Unheld) != 0 || !equal(imported.Enrollment, want) {
		t.Fatalf("imported %+v, want %+v", imported, want)
	}

	held = held.reopen(t)
	if active, ok := held.installation.Enrollment(); !ok || !equal(active, want) {
		t.Fatalf("after a restart the active generation is %+v (%t)", active, ok)
	}
	if pending, ok := held.installation.Pending(); ok {
		t.Fatalf("the installation still asks for %+v", pending)
	}
	credential, err := pki.OpenCredential(held.keys, held.certificates, want.KeyID, want.Certificate.FingerprintSHA256)
	if err != nil {
		t.Fatalf("open the credential of the generation: %v", err)
	}
	if !slices.EqualFunc(credential.Chain, [][]byte{leaf.Raw, signing.certificate.Raw}, bytes.Equal) {
		t.Fatal("the generation presents another chain than the one issued")
	}
}

func TestAnEnrolledInstallationMovesToTheGenerationItAskedFor(t *testing.T) {
	signing := newPlatform(t, "Seagull agents")
	held := install(t)
	first := held.enroll(t, signing, "web-01")
	asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask for the next certificate: %v", err)
	}
	if asked.KeyID == first.KeyID {
		t.Fatal("the next certificate was asked for with the key of the active one")
	}
	imported, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), signing.issue(t, asked.Request, nil, nil), time.Now())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imported.Enrollment.Generation != 2 || imported.Enrollment.KeyID != asked.KeyID {
		t.Fatalf("imported %+v", imported.Enrollment)
	}
	if _, err := held.keys.Open(first.KeyID); err != nil {
		t.Fatalf("the key of the first generation is gone: %v", err)
	}
}

func TestImportingTheActiveCertificateAgainChangesNothingButItsFile(t *testing.T) {
	signing := newPlatform(t, "Seagull agents")
	held := install(t)
	asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	issued := signing.issue(t, asked.Request, nil, nil)
	first, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), issued, time.Now())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	state := held.state(t)
	stored := filepath.Join(held.directory, "certificates", first.Enrollment.Certificate.FingerprintSHA256+".pem")
	if err := os.Remove(stored); err != nil {
		t.Fatalf("lose the certificate: %v", err)
	}

	again, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), issued, time.Now())
	if err != nil {
		t.Fatalf("import again: %v", err)
	}
	if !again.Already || !equal(again.Enrollment, first.Enrollment) || held.state(t) != state {
		t.Fatalf("importing the active certificate again made %+v and changed the state", again)
	}
	if _, err := pki.OpenCredential(held.keys, held.certificates, first.Enrollment.KeyID, first.Enrollment.Certificate.FingerprintSHA256); err != nil {
		t.Fatalf("importing again did not restore the certificate: %v", err)
	}
}

func TestAnImportInterruptedBeforeItsActivationIsCompletedByRunningItAgain(t *testing.T) {
	signing := newPlatform(t, "Seagull agents")
	held := install(t)
	asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	issued := signing.issue(t, asked.Request, nil, nil)
	verified, err := enrollment.Verify(issued, enrollment.Expected{AgentID: "web-01", KeyID: asked.KeyID}, signing.trusted(), time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := held.certificates.Store(verified.Chain); err != nil {
		t.Fatalf("store the chain as an import does before it activates: %v", err)
	}

	held = held.reopen(t)
	if active, ok := held.installation.Enrollment(); ok {
		t.Fatalf("a certificate stored and never activated is active: %+v", active)
	}
	imported, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), issued, time.Now())
	if err != nil || imported.Already || imported.Enrollment.Generation != 1 {
		t.Fatalf("importing again returned %+v, %v", imported, err)
	}
}

func TestOnlyTheCertificateIssuedForThePendingRequestIsActivated(t *testing.T) {
	signing, impostor := newPlatform(t, "Seagull agents"), newPlatform(t, "Impostor")
	now := time.Now()
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a key the installation does not hold: %v", err)
	}
	cases := []struct {
		name  string
		issue func(t *testing.T, requested []byte) []byte
		want  error
	}{
		{
			name: "a certificate for a key the installation does not hold",
			issue: func(t *testing.T, _ []byte) []byte {
				return signing.issue(t, requestWith(t, stranger, "web-01"), nil, nil)
			},
			want: enrollment.ErrMismatched,
		},
		{
			name: "a certificate for another agent",
			issue: func(t *testing.T, requested []byte) []byte {
				return signing.issue(t, requested, func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "db-07"} }, nil)
			},
			want: enrollment.ErrMismatched,
		},
		{
			name:  "a certificate from an authority the agent does not trust",
			issue: func(t *testing.T, requested []byte) []byte { return impostor.issue(t, requested, nil, nil) },
			want:  enrollment.ErrUntrusted,
		},
		{
			name: "a certificate for a server",
			issue: func(t *testing.T, requested []byte) []byte {
				return signing.issue(t, requested, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, nil)
			},
			want: enrollment.ErrUntrusted,
		},
		{
			name: "a certificate whose key may not sign",
			issue: func(t *testing.T, requested []byte) []byte {
				return signing.issue(t, requested, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyAgreement }, nil)
			},
			want: enrollment.ErrUntrusted,
		},
		{
			name: "the certificate of an authority",
			issue: func(t *testing.T, requested []byte) []byte {
				return signing.issue(t, requested, func(c *x509.Certificate) {
					c.IsCA, c.KeyUsage = true, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign
				}, nil)
			},
			want: enrollment.ErrUntrusted,
		},
		{
			name: "a certificate that expired",
			issue: func(t *testing.T, requested []byte) []byte {
				return signing.issue(t, requested, func(c *x509.Certificate) { c.NotBefore, c.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour) }, nil)
			},
			want: enrollment.ErrNotCurrent,
		},
		{
			name: "a certificate that is not valid yet",
			issue: func(t *testing.T, requested []byte) []byte {
				return signing.issue(t, requested, func(c *x509.Certificate) { c.NotBefore, c.NotAfter = now.Add(time.Hour), now.Add(2*time.Hour) }, nil)
			},
			want: enrollment.ErrNotCurrent,
		},
		{
			name: "what the platform recorded is another certificate",
			issue: func(t *testing.T, requested []byte) []byte {
				return signing.issue(t, requested, nil, func(recorded *agentv1.Identity) { recorded.FingerprintSha256 = strings.Repeat("ab", 32) })
			},
			want: enrollment.ErrUntrusted,
		},
		{
			name: "what the platform recorded is another serial",
			issue: func(t *testing.T, requested []byte) []byte {
				return signing.issue(t, requested, nil, func(recorded *agentv1.Identity) { recorded.Serial = "01" })
			},
			want: enrollment.ErrUntrusted,
		},
		{
			name: "what the platform recorded is another validity",
			issue: func(t *testing.T, requested []byte) []byte {
				return signing.issue(t, requested, nil, func(recorded *agentv1.Identity) {
					recorded.ExpiresAt = timestamppb.New(recorded.GetExpiresAt().AsTime().Add(time.Hour))
				})
			},
			want: enrollment.ErrUntrusted,
		},
		{
			name: "an answer that records nothing",
			issue: func(t *testing.T, requested []byte) []byte {
				return reencode(t, signing.issue(t, requested, nil, nil), func(answer *agentv1.IssuedCertificate) { answer.Identity = nil })
			},
			want: enrollment.ErrUnreadable,
		},
		{
			name: "the certificate alone, as PEM",
			issue: func(t *testing.T, requested []byte) []byte {
				return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuedLeaf(t, signing.issue(t, requested, nil, nil)).Raw})
			},
			want: enrollment.ErrUnreadable,
		},
		{
			name:  "nothing at all",
			issue: func(*testing.T, []byte) []byte { return nil },
			want:  enrollment.ErrUnreadable,
		},
		{
			name:  "bytes that are no message",
			issue: func(*testing.T, []byte) []byte { return []byte{0x0a, 0xff, 0x01} },
			want:  enrollment.ErrUnreadable,
		},
		{
			name: "an answer larger than one the platform gives",
			issue: func(t *testing.T, requested []byte) []byte {
				return append(signing.issue(t, requested, nil, nil), bytes.Repeat([]byte{0x9a, 0x3f, 0x00}, enrollment.MaxIssuedBytes/3)...)
			},
			want: enrollment.ErrUnreadable,
		},
		{
			name: "two certificates where one is issued",
			issue: func(t *testing.T, requested []byte) []byte {
				return reencode(t, signing.issue(t, requested, nil, nil), func(answer *agentv1.IssuedCertificate) {
					answer.CertificatePem = append(answer.CertificatePem, answer.CertificatePem...)
				})
			},
			want: enrollment.ErrUnreadable,
		},
		{
			name: "a chain that holds a certificate that is no authority",
			issue: func(t *testing.T, requested []byte) []byte {
				return reencode(t, signing.issue(t, requested, nil, nil), func(answer *agentv1.IssuedCertificate) {
					answer.ChainPem = append(answer.ChainPem, answer.CertificatePem...)
				})
			},
			want: enrollment.ErrUnreadable,
		},
		{
			name: "a published bundle that holds no authority",
			issue: func(t *testing.T, requested []byte) []byte {
				return reencode(t, signing.issue(t, requested, nil, nil), func(answer *agentv1.IssuedCertificate) { answer.TrustBundlePem = nil })
			},
			want: enrollment.ErrUnreadable,
		},
		{
			name: "a published bundle that holds a key",
			issue: func(t *testing.T, requested []byte) []byte {
				return reencode(t, signing.issue(t, requested, nil, nil), func(answer *agentv1.IssuedCertificate) {
					answer.TrustBundlePem = append(answer.TrustBundlePem, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("a key")})...)
				})
			},
			want: enrollment.ErrUnreadable,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			held := install(t)
			asked, err := enrollment.Request(held.installation, held.keys, "web-01", now)
			if err != nil {
				t.Fatalf("ask for a certificate: %v", err)
			}
			state := held.state(t)
			_, err = enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), c.issue(t, asked.Request), now)
			if !errors.Is(err, c.want) {
				t.Fatalf("import returned %v, want %v", err, c.want)
			}
			if held.state(t) != state {
				t.Fatal("a refused import changed the installation state")
			}
			if stored, err := os.ReadDir(filepath.Join(held.directory, "certificates")); err != nil || len(stored) != 0 {
				t.Fatalf("a refused import kept %v: %v", stored, err)
			}
			if pending, ok := held.installation.Pending(); !ok || pending.KeyID != asked.KeyID {
				t.Fatalf("a refused import ended the request: %+v (%t)", pending, ok)
			}
		})
	}
}

func TestNothingIsImportedWithoutARequestForIt(t *testing.T) {
	signing := newPlatform(t, "Seagull agents")
	held := install(t)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	unasked := signing.issue(t, requestWith(t, stranger, "web-01"), nil, nil)
	if _, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), unasked, time.Now()); !errors.Is(err, enrollment.ErrNotAsked) {
		t.Fatalf("an installation that asked for nothing imported a certificate: %v", err)
	}

	active := held.enroll(t, signing, "web-01")
	key, err := held.keys.Open(active.KeyID)
	if err != nil {
		t.Fatalf("open the active key: %v", err)
	}
	reissued, err := pki.Request(key, "web-01")
	if err != nil {
		t.Fatalf("make a request with the active key: %v", err)
	}
	if _, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), signing.issue(t, reissued, nil, nil), time.Now()); !errors.Is(err, enrollment.ErrNotAsked) {
		t.Fatalf("an installation that asked for nothing since it was enrolled imported another certificate for its key: %v", err)
	}
}

func TestAChainThroughAnIntermediateIsKeptAsIssued(t *testing.T) {
	root := newPlatform(t, "Seagull root")
	intermediate := root.subordinate(t, "Seagull agents 2026")
	held := install(t)
	asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	issued := intermediate.issue(t, asked.Request, nil, nil)
	imported, err := enrollment.Import(held.installation, held.keys, held.certificates, root.trusted(), issued, time.Now())
	if err != nil {
		t.Fatalf("import a certificate an intermediate issued: %v", err)
	}
	credential, err := pki.OpenCredential(held.keys, held.certificates, imported.Enrollment.KeyID, imported.Enrollment.Certificate.FingerprintSHA256)
	if err != nil {
		t.Fatalf("open the credential: %v", err)
	}
	want := [][]byte{issuedLeaf(t, issued).Raw, intermediate.certificate.Raw, root.certificate.Raw}
	if !slices.EqualFunc(credential.Chain, want, bytes.Equal) || imported.Issuer != "Seagull agents 2026" {
		t.Fatalf("kept a chain of %d certificates issued by %s", len(credential.Chain), imported.Issuer)
	}
}

func TestTheAuthoritiesThePlatformPublishesAreReportedAndNeverTrusted(t *testing.T) {
	signing, next := newPlatform(t, "Seagull agents"), newPlatform(t, "Seagull agents next")
	signing.published = append(signing.published, next.certificate)
	next.published = signing.published
	held := install(t)
	asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	if _, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), next.issue(t, asked.Request, nil, nil), time.Now()); !errors.Is(err, enrollment.ErrUntrusted) {
		t.Fatalf("a certificate from an authority only the answer names was imported: %v", err)
	}
	imported, err := enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), signing.issue(t, asked.Request, nil, nil), time.Now())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(imported.Unheld) != 1 || !imported.Unheld[0].Equal(next.certificate) {
		t.Fatalf("reported %d authorities the agent does not trust, want the next one", len(imported.Unheld))
	}
}

// What a refusal may carry of an answer: enough to say what is wrong with it,
// and never enough for the answer to decide how long a log line is.
func TestNothingAnAnswerHoldsDecidesHowLongARefusalIs(t *testing.T) {
	marker := strings.Repeat("written", 36) + "-marker-tail"
	signing := newPlatform(t, "Seagull agents")
	for name, change := range map[string]func(t *testing.T, requested []byte) []byte{
		"an agent named at length": func(t *testing.T, requested []byte) []byte {
			return signing.issue(t, requested, func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: marker} }, nil)
		},
		"a block of another type": func(t *testing.T, requested []byte) []byte {
			return reencode(t, signing.issue(t, requested, nil, nil), func(answer *agentv1.IssuedCertificate) {
				answer.ChainPem = pem.EncodeToMemory(&pem.Block{Type: marker, Bytes: []byte("a block")})
			})
		},
		"a certificate that is not one": func(t *testing.T, requested []byte) []byte {
			return reencode(t, signing.issue(t, requested, nil, nil), func(answer *agentv1.IssuedCertificate) {
				answer.CertificatePem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte(marker)})
			})
		},
		"a record of another subject": func(t *testing.T, requested []byte) []byte {
			return signing.issue(t, requested, nil, func(recorded *agentv1.Identity) { recorded.Subject = marker })
		},
	} {
		t.Run(name, func(t *testing.T) {
			held := install(t)
			asked, err := enrollment.Request(held.installation, held.keys, "web-01", time.Now())
			if err != nil {
				t.Fatalf("ask for a certificate: %v", err)
			}
			_, err = enrollment.Import(held.installation, held.keys, held.certificates, signing.trusted(), change(t, asked.Request), time.Now())
			if err == nil {
				t.Fatal("imported it")
			}
			if strings.Contains(err.Error(), "-marker-tail") || len(err.Error()) > 4<<10 {
				t.Fatalf("the refusal carries what the answer held:\n%v", err)
			}
		})
	}
}

// Whatever an answer holds, verifying it never fails in any other way than
// refusing it, and what it accepts is a certificate for the agent and key
// expected that chains to the authority trusted.
func FuzzVerify(f *testing.F) {
	signing := newPlatform(f, "Seagull agents")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("draw a key: %v", err)
	}
	keyID, err := pki.KeyID(key.Public())
	if err != nil {
		f.Fatalf("name the key: %v", err)
	}
	issued := signing.issue(f, requestWith(f, key, "web-01"), nil, nil)
	f.Add(issued)
	f.Add(issued[:len(issued)/2])
	f.Add(slices.Concat(issued, issued))
	f.Add([]byte{})
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuedLeaf(f, issued).Raw}))
	expected := enrollment.Expected{AgentID: "web-01", KeyID: keyID}
	f.Fuzz(func(t *testing.T, content []byte) {
		verified, err := enrollment.Verify(content, expected, signing.trusted(), time.Now())
		if err != nil {
			if !slices.ContainsFunc([]error{enrollment.ErrUnreadable, enrollment.ErrMismatched, enrollment.ErrUntrusted, enrollment.ErrNotCurrent},
				func(kind error) bool { return errors.Is(err, kind) }) {
				t.Fatalf("refused with %v, which says nothing of why", err)
			}
			return
		}
		leaf, err := x509.ParseCertificate(verified.Chain[0])
		if err != nil {
			t.Fatalf("accepted a chain whose leaf does not parse: %v", err)
		}
		certified, err := pki.KeyID(leaf.PublicKey)
		if err != nil || certified != keyID || leaf.Subject.CommonName != "web-01" || verified.Certificate.FingerprintSHA256 != digest(leaf.Raw) {
			t.Fatalf("accepted a certificate for %s with key %s", leaf.Subject.CommonName, certified)
		}
		if err := leaf.CheckSignatureFrom(signing.certificate); err != nil {
			t.Fatalf("accepted a certificate the trusted authority did not sign: %v", err)
		}
	})
}

type installed struct {
	directory    string
	installation *identity.Installation
	keys         *pki.KeyFiles
	certificates *pki.CertificateFiles
}

func install(t *testing.T) *installed {
	t.Helper()
	return open(t, filepath.Join(t.TempDir(), "state"))
}

func open(t *testing.T, directory string) *installed {
	t.Helper()
	installation, err := identity.Open(directory)
	if err != nil {
		t.Fatalf("open the installation: %v", err)
	}
	t.Cleanup(func() { _ = installation.Close() })
	keyDirectory, err := installation.Directory("keys")
	if err != nil {
		t.Fatalf("open the keys: %v", err)
	}
	keys, err := pki.OpenKeyFiles(keyDirectory)
	if err != nil {
		t.Fatalf("open the keys: %v", err)
	}
	certificateDirectory, err := installation.Directory("certificates")
	if err != nil {
		t.Fatalf("open the certificates: %v", err)
	}
	certificates, err := pki.OpenCertificateFiles(certificateDirectory)
	if err != nil {
		t.Fatalf("open the certificates: %v", err)
	}
	return &installed{directory: directory, installation: installation, keys: keys, certificates: certificates}
}

func (i *installed) reopen(t *testing.T) *installed {
	t.Helper()
	if err := i.installation.Close(); err != nil {
		t.Fatalf("close the installation: %v", err)
	}
	return open(t, i.directory)
}

func (i *installed) enroll(t *testing.T, signing *platform, agentID string) identity.Enrollment {
	t.Helper()
	asked, err := enrollment.Request(i.installation, i.keys, agentID, time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	imported, err := enrollment.Import(i.installation, i.keys, i.certificates, signing.trusted(), signing.issue(t, asked.Request, nil, nil), time.Now())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return imported.Enrollment
}

func (i *installed) state(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(i.directory, "installation.json"))
	if err != nil {
		t.Fatalf("read the installation state: %v", err)
	}
	return string(content)
}

func (i *installed) keysHeld(t *testing.T) []os.DirEntry {
	t.Helper()
	held, err := os.ReadDir(filepath.Join(i.directory, "keys"))
	if err != nil {
		t.Fatalf("list the keys: %v", err)
	}
	return held
}

// A platform that signs as the recorded platform's authority signs: the agent
// the request names and the key it carries, a random serial, a minute of
// backdating, only a digital signature for client authentication, and an
// answer carrying its chain and the authorities it publishes.
type platform struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	chain       []*x509.Certificate
	published   []*x509.Certificate
}

func newPlatform(t testing.TB, name string) *platform {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of %s: %v", name, err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return &platform{certificate: certificate, key: key, chain: []*x509.Certificate{certificate}, published: []*x509.Certificate{certificate}}
}

func (p *platform) subordinate(t *testing.T, name string) *platform {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of %s: %v", name, err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, p.certificate, key.Public(), p.key)
	if err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return &platform{certificate: certificate, key: key, chain: []*x509.Certificate{certificate, p.certificate}, published: p.published}
}

func (p *platform) trusted() []*x509.Certificate { return []*x509.Certificate{p.published[0]} }

func (p *platform) issue(t testing.TB, requested []byte, change func(*x509.Certificate), record func(*agentv1.Identity)) []byte {
	t.Helper()
	asked := parseRequest(t, requested)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatalf("draw a serial: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)
	if expires.After(p.certificate.NotAfter) {
		expires = p.certificate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: asked.Subject.CommonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              expires,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if change != nil {
		change(template)
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, p.certificate, asked.PublicKey, p.key)
	if err != nil {
		t.Fatalf("issue the certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatalf("parse the certificate: %v", err)
	}
	recorded := &agentv1.Identity{
		Subject:           certificate.Subject.CommonName,
		Serial:            hex.EncodeToString(certificate.SerialNumber.Bytes()),
		FingerprintSha256: digest(signed),
		IssuedAt:          timestamppb.New(certificate.NotBefore),
		ExpiresAt:         timestamppb.New(certificate.NotAfter),
	}
	if record != nil {
		record(recorded)
	}
	encoded, err := proto.Marshal(&agentv1.IssuedCertificate{
		CertificatePem: encode(certificate),
		ChainPem:       encode(p.chain...),
		TrustBundlePem: encode(p.published...),
		Identity:       recorded,
	})
	if err != nil {
		t.Fatalf("encode the answer: %v", err)
	}
	return encoded
}

func encode(certificates ...*x509.Certificate) []byte {
	var written []byte
	for _, certificate := range certificates {
		written = append(written, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return written
}

func reencode(t *testing.T, issued []byte, change func(*agentv1.IssuedCertificate)) []byte {
	t.Helper()
	var answer agentv1.IssuedCertificate
	if err := proto.Unmarshal(issued, &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	change(&answer)
	encoded, err := proto.Marshal(&answer)
	if err != nil {
		t.Fatalf("encode the answer: %v", err)
	}
	return encoded
}

func issuedLeaf(t testing.TB, issued []byte) *x509.Certificate {
	t.Helper()
	var answer agentv1.IssuedCertificate
	if err := proto.Unmarshal(issued, &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	block, _ := pem.Decode(answer.GetCertificatePem())
	if block == nil {
		t.Fatal("the answer carries no certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the certificate: %v", err)
	}
	return leaf
}

func requestWith(t testing.TB, key *ecdsa.PrivateKey, agentID string) []byte {
	t.Helper()
	signed, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID}}, key)
	if err != nil {
		t.Fatalf("make a request: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: signed})
}

func parseRequest(t testing.TB, requested []byte) *x509.CertificateRequest {
	t.Helper()
	block, rest := pem.Decode(requested)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) > 0 {
		t.Fatalf("the request is not one PEM certificate request:\n%s", requested)
	}
	asked, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse the request: %v", err)
	}
	if err := asked.CheckSignature(); err != nil {
		t.Fatalf("the request is not signed by the key it carries: %v", err)
	}
	return asked
}

func digest(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func equal(a, b identity.Enrollment) bool {
	return a.AgentID == b.AgentID && a.Generation == b.Generation && a.KeyID == b.KeyID &&
		a.Certificate.Subject == b.Certificate.Subject && a.Certificate.Serial == b.Certificate.Serial &&
		a.Certificate.FingerprintSHA256 == b.Certificate.FingerprintSHA256 &&
		a.Certificate.NotBefore.Equal(b.Certificate.NotBefore) && a.Certificate.NotAfter.Equal(b.Certificate.NotAfter)
}
