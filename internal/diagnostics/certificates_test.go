package diagnostics_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/diagnostics"
)

type signer struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

func authority(t *testing.T, name string) signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatal(err)
	}
	return signer{certificate: certificate, key: key}
}

func (s signer) issue(t *testing.T, usage x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x0a1b2c3d),
		Subject:      pkix.Name{CommonName: "web-01"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(30 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, s.certificate, key.Public(), s.key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func TestTheCredentialIsDescribedByWhatItsCertificatesSayInPublic(t *testing.T) {
	platform := authority(t, "Seagull platform")
	leaf, key := platform.issue(t, x509.ExtKeyUsageClientAuth)
	presented := diagnostics.Presented("/var/lib/seagull-agent/certificates/leaf.pem", [][]byte{leaf.Raw, platform.certificate.Raw},
		[]*x509.Certificate{platform.certificate}, time.Now())
	if presented.Unread != "" || len(presented.Chain) != 2 || presented.From != "/var/lib/seagull-agent/certificates/leaf.pem" {
		t.Fatalf("the credential was described as %+v", presented)
	}
	fingerprint, spki := sha256.Sum256(leaf.Raw), sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	described := presented.Chain[0]
	if described.Subject != "CN=web-01" || described.Issuer != "CN=Seagull platform" || described.Serial != "0a1b2c3d" ||
		described.Fingerprint != diagnostics.Text(hex.EncodeToString(fingerprint[:])) || described.KeyID != diagnostics.Text(hex.EncodeToString(spki[:])) ||
		described.Key != "ECDSA P-256" || described.Signature != "ECDSA-SHA256" || described.Authority ||
		!slices.Equal(described.Usages, []diagnostics.Text{"digital_signature", "client_authentication"}) ||
		!described.NotAfter.Equal(leaf.NotAfter) || !described.NotBefore.Equal(leaf.NotBefore) {
		t.Errorf("the leaf was described as %+v", described)
	}
	if issuer := presented.Chain[1]; !issuer.Authority || issuer.Subject != "CN=Seagull platform" {
		t.Errorf("the authority was described as %+v", issuer)
	}
	if !strings.Contains(string(presented.Verification), "the chain authenticates the agent, as a client, to whoever trusts the 1 authority the agent trusts") {
		t.Errorf("the credential was verified as %q", presented.Verification)
	}
	encoded, err := json.Marshal(presented)
	if err != nil {
		t.Fatal(err)
	}
	private, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), hex.EncodeToString(private)) {
		t.Errorf("the description of a credential holds its key: %s", encoded)
	}
}

func TestAChainThatDoesNotAuthenticateTheAgentSaysWhy(t *testing.T) {
	platform, impostor := authority(t, "Seagull platform"), authority(t, "Another platform")
	leaf, _ := platform.issue(t, x509.ExtKeyUsageClientAuth)
	server, _ := platform.issue(t, x509.ExtKeyUsageServerAuth)
	chain := [][]byte{leaf.Raw, platform.certificate.Raw}
	for name, verified := range map[string]struct {
		presented diagnostics.Credential
		said      string
	}{
		"another platform's authority": {diagnostics.Presented("leaf", chain, []*x509.Certificate{impostor.certificate}, time.Now()), "unknown authority"},
		"no authority at all":          {diagnostics.Presented("leaf", chain, nil, time.Now()), "the 0 authorities"},
		"after it expired":             {diagnostics.Presented("leaf", chain, []*x509.Certificate{platform.certificate}, leaf.NotAfter.Add(time.Minute)), "expired"},
		"a server's certificate":       {diagnostics.Presented("leaf", [][]byte{server.Raw}, []*x509.Certificate{platform.certificate}, time.Now()), "key usage"},
	} {
		if said := string(verified.presented.Verification); !strings.Contains(said, "does not authenticate the agent") || !strings.Contains(said, verified.said) {
			t.Errorf("%s: the credential was verified as %q", name, said)
		}
	}
	for name, chain := range map[string][][]byte{"nothing": nil, "something else": {[]byte("not a certificate")}} {
		if presented := diagnostics.Presented("leaf", chain, []*x509.Certificate{platform.certificate}, time.Now()); presented.Unread == "" || presented.Verification != "" {
			t.Errorf("a chain of %s was described as %+v", name, presented)
		}
	}
}

func TestTheAuthoritiesTheAgentTrustsAreNamedByTheirDigest(t *testing.T) {
	first, second := authority(t, "Seagull platform"), authority(t, "Seagull platform next")
	held := diagnostics.Trusting("/etc/seagull-agent/platform-ca.pem", strings.Repeat("ab", 32), []*x509.Certificate{first.certificate, second.certificate})
	if held.From != "/etc/seagull-agent/platform-ca.pem" || held.Digest != diagnostics.Text(strings.Repeat("ab", 32)) || len(held.Authorities) != 2 ||
		held.Authorities[1].Subject != "CN=Seagull platform next" || !held.Authorities[0].Authority {
		t.Errorf("the authorities were described as %+v", held)
	}
}
