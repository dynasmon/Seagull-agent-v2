package pki_test

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
)

const childCertificates = "SEAGULL_PKI_TEST_CERTIFICATES"

func storeUntilKilled(directory string) int {
	root, err := os.OpenRoot(directory)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	certificates, err := pki.OpenCertificateFiles(root)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "agents"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	for serial := range int64(10000) {
		template.SerialNumber = big.NewInt(serial + 1)
		signed, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			fmt.Println("failed", err)
			return 1
		}
		stored, err := certificates.Store([][]byte{signed})
		if err != nil {
			fmt.Println("failed", err)
			return 1
		}
		fmt.Println("stored", stored)
	}
	return 0
}

func TestAStoredChainOpensAsItWasIssuedAfterARestart(t *testing.T) {
	directory := certificatesDirectory(t)
	chain := issuedChain(t, create(t, openKeys(t, keysDirectory(t))))
	fingerprint, err := openCertificates(t, directory).Store(chain)
	if err != nil {
		t.Fatalf("store the chain: %v", err)
	}
	if fingerprint != digest(chain[0]) {
		t.Fatalf("stored the chain as %s, its leaf is %s", fingerprint, digest(chain[0]))
	}
	described, err := os.Lstat(filepath.Join(directory, fingerprint+".pem"))
	if err != nil || described.Mode().Perm() != 0o600 {
		t.Fatalf("the chain was written as %v: %v", described, err)
	}
	opened, err := openCertificates(t, directory).Open(fingerprint)
	if err != nil {
		t.Fatalf("open the chain after a restart: %v", err)
	}
	if !slices.EqualFunc(opened, chain, bytes.Equal) {
		t.Fatal("the chain opened is not the one stored")
	}
}

func TestStoringAChainAgainLeavesItsFileAsItWas(t *testing.T) {
	directory := certificatesDirectory(t)
	certificates := openCertificates(t, directory)
	chain := issuedChain(t, create(t, openKeys(t, keysDirectory(t))))
	fingerprint, err := certificates.Store(chain)
	if err != nil {
		t.Fatalf("store the chain: %v", err)
	}
	path := filepath.Join(directory, fingerprint+".pem")
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("inspect %s: %v", path, err)
	}
	again, err := certificates.Store(chain)
	if err != nil || again != fingerprint {
		t.Fatalf("storing the chain again returned %s, %v", again, err)
	}
	if after, err := os.Lstat(path); err != nil || !os.SameFile(before, after) {
		t.Fatalf("storing the chain again rewrote its file: %v", err)
	}
}

func TestAStoredChainReplacesWhateverElseItsFileHeld(t *testing.T) {
	directory := certificatesDirectory(t)
	certificates := openCertificates(t, directory)
	chain := issuedChain(t, create(t, openKeys(t, keysDirectory(t))))
	path := filepath.Join(directory, digest(chain[0])+".pem")
	for name, held := range map[string][]byte{
		"a truncated chain": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0][:len(chain[0])/2]}),
		"the leaf alone":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0]}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, held, 0o644); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
			if _, err := certificates.Store(chain); err != nil {
				t.Fatalf("store the chain over %s: %v", name, err)
			}
			opened, err := certificates.Open(digest(chain[0]))
			if err != nil || !slices.EqualFunc(opened, chain, bytes.Equal) {
				t.Fatalf("the stored chain did not replace %s: %v", name, err)
			}
			if described, err := os.Lstat(path); err != nil || described.Mode().Perm() != 0o600 {
				t.Fatalf("the chain was written as %v: %v", described, err)
			}
		})
	}
}

func TestOnlyAChainOfCertificatesIsStored(t *testing.T) {
	directory := certificatesDirectory(t)
	certificates := openCertificates(t, directory)
	chain := issuedChain(t, create(t, openKeys(t, keysDirectory(t))))
	long := slices.Repeat([][]byte{chain[1]}, pki.MaxChain)
	for name, stored := range map[string][][]byte{
		"no certificate":                 nil,
		"a block that is no certificate": {chain[0][:100]},
		"more than a chain holds":        append([][]byte{chain[0]}, long...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := certificates.Store(stored); err == nil {
				t.Fatal("stored it")
			}
		})
	}
	if held, err := os.ReadDir(directory); err != nil || len(held) != 0 {
		t.Fatalf("a refused chain left %v in the directory: %v", held, err)
	}
}

func TestAMissingCertificateIsReportedAsMissing(t *testing.T) {
	certificates := openCertificates(t, certificatesDirectory(t))
	if _, err := certificates.Open(strings.Repeat("ab", 32)); !errors.Is(err, pki.ErrCertificateMissing) {
		t.Fatalf("opening a chain that was never stored returned %v", err)
	}
	for _, fingerprint := range []string{"", "../certificates", strings.Repeat("AB", 32), strings.Repeat("ab", 32) + ".pem", strings.Repeat("ab", 31)} {
		if _, err := certificates.Open(fingerprint); err == nil || errors.Is(err, pki.ErrCertificateMissing) {
			t.Errorf("opening %q returned %v, want a refusal of the fingerprint", fingerprint, err)
		}
	}
}

func TestDamagedCertificatesAreRefusedAndLeftAsTheyWere(t *testing.T) {
	directory := certificatesDirectory(t)
	certificates := openCertificates(t, directory)
	keys := openKeys(t, keysDirectory(t))
	chain, other := issuedChain(t, create(t, keys)), issuedChain(t, create(t, keys))
	fingerprint, err := certificates.Store(chain)
	if err != nil {
		t.Fatalf("store the chain: %v", err)
	}
	path := filepath.Join(directory, fingerprint+".pem")
	whole, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	encoded := func(blocks ...*pem.Block) []byte {
		var written []byte
		for _, block := range blocks {
			written = append(written, pem.EncodeToMemory(block)...)
		}
		return written
	}
	cases := map[string][]byte{
		"an empty file":                nil,
		"a truncated chain":            whole[:len(whole)/2],
		"something other than PEM":     []byte("\x00\x01\x02"),
		"another chain under its name": encoded(&pem.Block{Type: "CERTIFICATE", Bytes: other[0]}, &pem.Block{Type: "CERTIFICATE", Bytes: other[1]}),
		"the chain followed by more":   append(slices.Clone(whole), "more"...),
		"the chain after something":    append([]byte("before\n"), whole...),
		"a key beside the chain":       append(slices.Clone(whole), encoded(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("a key")})...),
		"a block with headers":         encoded(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Issued": "yes"}, Bytes: chain[0]}),
		"a block that is not one":      encoded(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}),
		"more than a chain holds":      bytes.Repeat(whole, pki.MaxChain),
		"a file too large for a chain": append(slices.Clone(whole), bytes.Repeat([]byte("\n"), 64<<10)...),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatalf("damage the chain: %v", err)
			}
			for attempt := range 2 {
				if _, err := certificates.Open(fingerprint); !errors.Is(err, pki.ErrCertificateDamaged) {
					t.Fatalf("open %d returned %v", attempt+1, err)
				}
			}
			if kept, err := os.ReadFile(path); err != nil || !bytes.Equal(kept, content) {
				t.Fatalf("the damaged chain was rewritten as %q: %v", kept, err)
			}
		})
	}

	for name, prepare := range map[string]func() error{
		"a directory": func() error { return os.Mkdir(path, 0o700) },
		"a symbolic link to another chain": func() error {
			stored, err := certificates.Store(other)
			if err != nil {
				return err
			}
			return os.Symlink(stored+".pem", path)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.RemoveAll(path); err != nil {
				t.Fatalf("remove %s: %v", path, err)
			}
			if err := prepare(); err != nil {
				t.Fatalf("prepare %s: %v", name, err)
			}
			if _, err := certificates.Open(fingerprint); !errors.Is(err, pki.ErrCertificateDamaged) {
				t.Fatalf("open returned %v", err)
			}
		})
	}
}

func TestCertificatesOthersCanReachAreRefused(t *testing.T) {
	t.Run("a chain its group can change", func(t *testing.T) {
		directory := certificatesDirectory(t)
		certificates := openCertificates(t, directory)
		fingerprint, err := certificates.Store(issuedChain(t, create(t, openKeys(t, keysDirectory(t)))))
		if err != nil {
			t.Fatalf("store the chain: %v", err)
		}
		if err := os.Chmod(filepath.Join(directory, fingerprint+".pem"), 0o660); err != nil {
			t.Fatalf("chmod the chain: %v", err)
		}
		if _, err := certificates.Open(fingerprint); !errors.Is(err, pki.ErrCertificateInsecure) {
			t.Fatalf("open returned %v", err)
		}
		if _, err := pki.OpenCertificateFiles(root(t, directory)); !errors.Is(err, pki.ErrCertificateInsecure) {
			t.Fatalf("opening the certificates after a restart returned %v", err)
		}
	})
	t.Run("a directory others can list", func(t *testing.T) {
		directory := certificatesDirectory(t)
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatalf("chmod the directory: %v", err)
		}
		if _, err := pki.OpenCertificateFiles(root(t, directory)); !errors.Is(err, pki.ErrCertificateInsecure) {
			t.Fatalf("opening the certificates returned %v", err)
		}
	})
}

func TestTheLeftoversOfAnInterruptedStoreAreDiscarded(t *testing.T) {
	directory := certificatesDirectory(t)
	chain := issuedChain(t, create(t, openKeys(t, keysDirectory(t))))
	fingerprint, err := openCertificates(t, directory).Store(chain)
	if err != nil {
		t.Fatalf("store the chain: %v", err)
	}
	interrupted := strings.Repeat("ab", 32)
	for _, name := range []string{"." + interrupted + ".pem.tmp", "." + fingerprint + ".pem.tmp"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("-----BEGIN CERT"), 0o600); err != nil {
			t.Fatalf("leave an interrupted store: %v", err)
		}
	}
	certificates := openCertificates(t, directory)
	if held, err := os.ReadDir(directory); err != nil || len(held) != 1 || held[0].Name() != fingerprint+".pem" {
		t.Fatalf("after a restart the directory holds %v: %v", held, err)
	}
	if _, err := certificates.Open(fingerprint); err != nil {
		t.Fatalf("the chain stored before the interruption no longer opens: %v", err)
	}
	if _, err := certificates.Store(chain); err != nil {
		t.Fatalf("store the chain again: %v", err)
	}
}

func TestAChainIsReadWithoutChangingItsDirectory(t *testing.T) {
	directory := certificatesDirectory(t)
	chain := issuedChain(t, create(t, openKeys(t, keysDirectory(t))))
	fingerprint, err := openCertificates(t, directory).Store(chain)
	if err != nil {
		t.Fatalf("store the chain: %v", err)
	}
	writing := filepath.Join(directory, "."+strings.Repeat("ab", 32)+".pem.tmp")
	if err := os.WriteFile(writing, []byte("being written"), 0o600); err != nil {
		t.Fatalf("leave a write in progress: %v", err)
	}
	read, err := pki.ReadCertificates(root(t, directory), fingerprint)
	if err != nil || !slices.EqualFunc(read, chain, bytes.Equal) {
		t.Fatalf("read the chain as %d certificates: %v", len(read), err)
	}
	if _, err := os.Lstat(writing); err != nil {
		t.Fatalf("reading the chain discarded a write in progress: %v", err)
	}
	if _, err := pki.ReadCertificates(root(t, directory), strings.Repeat("cd", 32)); !errors.Is(err, pki.ErrCertificateMissing) {
		t.Fatalf("reading a chain that was never kept returned %v", err)
	}
}

func TestChainsSurviveAnAgentKilledWhileStoringThem(t *testing.T) {
	directory := certificatesDirectory(t)
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
	child.Env = append(os.Environ(), childCertificates+"="+directory)
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatalf("attach to the child's output: %v", err)
	}
	if err := child.Start(); err != nil {
		t.Fatalf("start the child: %v", err)
	}
	reports := make(chan string)
	go func() {
		defer close(reports)
		for lines := bufio.NewScanner(output); lines.Scan(); {
			select {
			case reports <- lines.Text():
			case <-t.Context().Done():
				return
			}
		}
	}()
	var reported []string
	timeout := time.After(30 * time.Second)
	for len(reported) < 24 {
		select {
		case report, open := <-reports:
			stored, found := strings.CutPrefix(report, "stored ")
			if !open || !found {
				t.Fatalf("the child reported %q", report)
			}
			reported = append(reported, stored)
		case <-timeout:
			t.Fatalf("the child stored %d chains within 30s", len(reported))
		}
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatalf("kill the child: %v", err)
	}
	for range reports {
	}
	_ = child.Wait()

	certificates := openCertificates(t, directory)
	held, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("list %s: %v", directory, err)
	}
	for _, fingerprint := range reported {
		if _, err := certificates.Open(fingerprint); err != nil {
			t.Errorf("chain %s was reported stored and does not open: %v", fingerprint, err)
		}
	}
	for _, entry := range held {
		fingerprint, named := strings.CutSuffix(entry.Name(), ".pem")
		if !named {
			t.Errorf("the killed child left %s", entry.Name())
			continue
		}
		if _, err := certificates.Open(fingerprint); err != nil {
			t.Errorf("the killed child left a chain that does not open: %v", err)
		}
	}
}

func TestACredentialIsAKeyAndTheChainIssuedForIt(t *testing.T) {
	keys := openKeys(t, keysDirectory(t))
	certificates := openCertificates(t, certificatesDirectory(t))
	key, other := create(t, keys), create(t, keys)
	chain := issuedChain(t, key)
	fingerprint, err := certificates.Store(chain)
	if err != nil {
		t.Fatalf("store the chain: %v", err)
	}
	held, err := pki.OpenCredential(keys, certificates, key.ID(), fingerprint)
	if err != nil {
		t.Fatalf("open the credential: %v", err)
	}
	if held.Key.ID() != key.ID() || !slices.EqualFunc(held.Chain, chain, bytes.Equal) {
		t.Fatalf("opened key %s with another chain, want key %s", held.Key.ID(), key.ID())
	}

	foreign, err := certificates.Store(issuedChain(t, other))
	if err != nil {
		t.Fatalf("store the chain of another key: %v", err)
	}
	for name, c := range map[string]struct {
		key, fingerprint string
		want             error
	}{
		"a chain issued for another key": {key: key.ID(), fingerprint: foreign, want: pki.ErrCertificateDamaged},
		"a key that is missing":          {key: strings.Repeat("ab", 32), fingerprint: fingerprint, want: pki.ErrKeyMissing},
		"a chain that is missing":        {key: key.ID(), fingerprint: strings.Repeat("ab", 32), want: pki.ErrCertificateMissing},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pki.OpenCredential(keys, certificates, c.key, c.fingerprint); !errors.Is(err, c.want) {
				t.Fatalf("opened the credential with %v, want %v", err, c.want)
			}
		})
	}
}

func TestNothingACertificateFileHoldsDecidesHowLongARefusalIs(t *testing.T) {
	marker := strings.Repeat("written", 36) + "-marker-tail"
	directory := certificatesDirectory(t)
	certificates := openCertificates(t, directory)
	fingerprint, err := certificates.Store(issuedChain(t, create(t, openKeys(t, keysDirectory(t)))))
	if err != nil {
		t.Fatalf("store the chain: %v", err)
	}
	for name, content := range map[string][]byte{
		"a block that is not a certificate": pem.EncodeToMemory(&pem.Block{Type: marker, Bytes: []byte("not a certificate")}),
		"a block that holds none":           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte(marker)}),
		"something other than PEM":          []byte(marker),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(directory, fingerprint+".pem"), content, 0o600); err != nil {
				t.Fatalf("damage the chain: %v", err)
			}
			_, err := certificates.Open(fingerprint)
			if !errors.Is(err, pki.ErrCertificateDamaged) {
				t.Fatalf("open returned %v", err)
			}
			bounded(t, err)
		})
	}
	if _, err := certificates.Open(marker); err == nil {
		t.Fatal("a fingerprint that is not one was opened")
	} else {
		bounded(t, err)
	}
}

func certificatesDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "certificates")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	return directory
}

func openCertificates(t *testing.T, directory string) *pki.CertificateFiles {
	t.Helper()
	certificates, err := pki.OpenCertificateFiles(root(t, directory))
	if err != nil {
		t.Fatalf("open the certificates in %s: %v", directory, err)
	}
	return certificates
}

// What the platform issues an agent: its certificate, and the authority that
// signed it.
func issuedChain(t *testing.T, key pki.Key) [][]byte {
	t.Helper()
	signing := newAuthority(t)
	leaf := signing.issue(t, "web-01", key.Public(), x509.ExtKeyUsageClientAuth)
	return [][]byte{leaf.Raw, signing.certificate.Raw}
}
