package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
)

func TestAdoptedAuthoritiesOpenAsTheyWerePublishedAfterARestart(t *testing.T) {
	directory := authoritiesDirectory(t)
	published := []*x509.Certificate{newAuthority(t).certificate, newAuthority(t).certificate}
	digest, err := openAuthorities(t, directory).Store(published)
	if err != nil {
		t.Fatalf("keep the authorities: %v", err)
	}
	if digest != pki.Digest(published) || digest == pki.Digest([]*x509.Certificate{published[1], published[0]}) {
		t.Fatalf("kept the authorities as %s", digest)
	}
	if described, err := os.Lstat(filepath.Join(directory, digest+".pem")); err != nil || described.Mode().Perm() != 0o600 {
		t.Fatalf("the authorities were written as %v: %v", described, err)
	}
	opened, err := openAuthorities(t, directory).Open(digest)
	if err != nil {
		t.Fatalf("open the authorities after a restart: %v", err)
	}
	if !slices.EqualFunc(opened, published, (*x509.Certificate).Equal) {
		t.Fatal("the authorities opened are not the ones kept")
	}
}

func TestOnlyAuthoritiesAreKeptAsAuthorities(t *testing.T) {
	directory := authoritiesDirectory(t)
	authorities := openAuthorities(t, directory)
	signing := newAuthority(t)
	leaf := signing.issue(t, "web-01", create(t, openKeys(t, keysDirectory(t))).Public(), x509.ExtKeyUsageClientAuth)
	for name, published := range map[string][]*x509.Certificate{
		"a certificate of an agent": {signing.certificate, leaf},
		"no authority":              nil,
	} {
		if _, err := authorities.Store(published); err == nil {
			t.Errorf("kept %s", name)
		}
	}
	if held, err := os.ReadDir(directory); err != nil || len(held) != 0 {
		t.Fatalf("refused authorities left %v: %v", held, err)
	}
}

func TestDamagedAuthoritiesAreRefused(t *testing.T) {
	directory := authoritiesDirectory(t)
	authorities := openAuthorities(t, directory)
	signing := newAuthority(t)
	digest, err := authorities.Store([]*x509.Certificate{signing.certificate})
	if err != nil {
		t.Fatalf("keep the authorities: %v", err)
	}
	path := filepath.Join(directory, digest+".pem")
	leaf := signing.issue(t, "web-01", create(t, openKeys(t, keysDirectory(t))).Public(), x509.ExtKeyUsageClientAuth)
	for name, content := range map[string][]byte{
		"another authority under its name":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newAuthority(t).certificate.Raw}),
		"a certificate that is no authority": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		"something other than PEM":           []byte("\x00\x01"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatalf("damage the authorities: %v", err)
			}
			if _, err := authorities.Open(digest); !errors.Is(err, pki.ErrCertificateDamaged) {
				t.Fatalf("open returned %v", err)
			}
		})
	}
	if _, err := authorities.Open(strings.Repeat("ab", 32)); !errors.Is(err, pki.ErrCertificateMissing) {
		t.Fatalf("opening authorities that were never kept returned %v", err)
	}
	if _, err := authorities.Open("../" + digest); err == nil || errors.Is(err, pki.ErrCertificateMissing) {
		t.Fatalf("opening a name that is no digest returned %v", err)
	}
}

func TestAuthoritiesAreReadWithoutChangingTheirDirectory(t *testing.T) {
	directory := authoritiesDirectory(t)
	published := []*x509.Certificate{newAuthority(t).certificate}
	digest, err := openAuthorities(t, directory).Store(published)
	if err != nil {
		t.Fatalf("keep the authorities: %v", err)
	}
	writing := filepath.Join(directory, "."+strings.Repeat("ab", 32)+".pem.tmp")
	if err := os.WriteFile(writing, []byte("being written"), 0o600); err != nil {
		t.Fatalf("leave a write in progress: %v", err)
	}
	read, err := pki.ReadAuthorities(root(t, directory), digest)
	if err != nil || !slices.EqualFunc(read, published, (*x509.Certificate).Equal) {
		t.Fatalf("read the authorities as %d certificates: %v", len(read), err)
	}
	if _, err := os.Lstat(writing); err != nil {
		t.Fatalf("reading the authorities discarded a write in progress: %v", err)
	}
}

func authoritiesDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "trust")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	return directory
}

func openAuthorities(t *testing.T, directory string) *pki.AuthorityFiles {
	t.Helper()
	authorities, err := pki.OpenAuthorityFiles(root(t, directory))
	if err != nil {
		t.Fatalf("open the authorities in %s: %v", directory, err)
	}
	return authorities
}
