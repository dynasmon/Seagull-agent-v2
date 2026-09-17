package pki_test

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
)

const childKeys = "SEAGULL_PKI_TEST_KEYS"

var keyFile = regexp.MustCompile(`^([0-9a-f]{64})\.pem$`)

// A child creates keys in the directory it is given until it is killed, and
// reports each key only once Create has returned it.
func TestMain(m *testing.M) {
	if directory, ok := os.LookupEnv(childKeys); ok {
		os.Exit(createUntilKilled(directory))
	}
	os.Exit(m.Run())
}

func createUntilKilled(directory string) int {
	root, err := os.OpenRoot(directory)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	keys, err := pki.OpenKeyFiles(root)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	for range 10000 {
		created, err := keys.Create()
		if err != nil {
			fmt.Println("failed", err)
			return 1
		}
		fmt.Println("created", created.ID())
	}
	return 0
}

func TestACreatedKeyIsPrivateAndSignsAfterARestart(t *testing.T) {
	directory := keysDirectory(t)
	created, err := openKeys(t, directory).Create()
	if err != nil {
		t.Fatalf("create a key: %v", err)
	}
	if !keyFile.MatchString(created.ID() + ".pem") {
		t.Fatalf("created a key named %q", created.ID())
	}
	described, err := os.Lstat(filepath.Join(directory, created.ID()+".pem"))
	if err != nil || described.Mode().Perm() != 0o600 {
		t.Fatalf("the key was written as %v: %v", described, err)
	}

	reopened, err := openKeys(t, directory).Open(created.ID())
	if err != nil {
		t.Fatalf("open the key after a restart: %v", err)
	}
	public, ok := created.Public().(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() || !public.Equal(reopened.Public()) {
		t.Fatalf("created %T and reopened a key with another public half", created.Public())
	}
	digest := sha256.Sum256([]byte("installation"))
	signature, err := reopened.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(public, digest[:], signature) {
		t.Fatalf("the reopened key did not sign for the created one: %v", err)
	}
}

func TestEveryKeyIsDrawnAfresh(t *testing.T) {
	directory := keysDirectory(t)
	keys := openKeys(t, directory)
	drawn := map[string]bool{}
	for range 16 {
		created, err := keys.Create()
		if err != nil {
			t.Fatalf("create a key: %v", err)
		}
		if drawn[created.ID()] {
			t.Fatalf("two keys of one installation are %s", created.ID())
		}
		drawn[created.ID()] = true
	}
	if held := heldKeys(t, directory); len(held) != len(drawn) {
		t.Fatalf("the directory holds %d keys, %d were created", len(held), len(drawn))
	}
}

func TestAMissingKeyIsReportedAsMissing(t *testing.T) {
	keys := openKeys(t, keysDirectory(t))
	if _, err := keys.Open(strings.Repeat("ab", 32)); !errors.Is(err, pki.ErrKeyMissing) {
		t.Fatalf("opening a key that was never created returned %v", err)
	}
	for _, id := range []string{"", "../keys", strings.Repeat("AB", 32), strings.Repeat("ab", 32) + ".pem", strings.Repeat("ab", 31)} {
		if _, err := keys.Open(id); err == nil || errors.Is(err, pki.ErrKeyMissing) {
			t.Errorf("opening %q returned %v, want a refusal of the identifier", id, err)
		}
	}
}

func TestDamagedKeysAreRefusedAndLeftAsTheyWere(t *testing.T) {
	directory := keysDirectory(t)
	keys := openKeys(t, directory)
	first, second := create(t, keys), create(t, keys)
	firstKey, secondKey := readKey(t, directory, first.ID()), readKey(t, directory, second.ID())
	drawn := decodeKey(t, firstKey)
	sec1, err := x509.MarshalECPrivateKey(drawn)
	if err != nil {
		t.Fatalf("encode the key as SEC 1: %v", err)
	}
	pkcs8, _ := pem.Decode(firstKey)

	cases := map[string][]byte{
		"an empty file":               nil,
		"a truncated key":             firstKey[:len(firstKey)/2],
		"something other than PEM":    []byte("\x00\x01\x02"),
		"another key under its name":  secondKey,
		"two keys":                    append(append([]byte{}, firstKey...), secondKey...),
		"a key followed by more":      append(append([]byte{}, firstKey...), "more"...),
		"an encrypted key":            pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: pkcs8.Bytes}),
		"a SEC 1 key":                 pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		"a PKCS #8 block that is not": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")}),
		"a P-384 key":                 encodeKey(t, generate(t, func() (any, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) })),
		"an Ed25519 key": encodeKey(t, generate(t, func() (any, error) {
			_, drawn, err := ed25519.GenerateKey(rand.Reader)
			return drawn, err
		})),
		"a file too large to be a key": append(append([]byte{}, firstKey...), strings.Repeat("\n", 4<<10)...),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, first.ID()+".pem")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatalf("damage the key: %v", err)
			}
			for attempt := range 2 {
				_, err := keys.Open(first.ID())
				if !errors.Is(err, pki.ErrKeyDamaged) {
					t.Fatalf("open %d returned %v", attempt+1, err)
				}
				if exposes(err.Error(), firstKey) {
					t.Fatalf("the refusal carries the key: %v", err)
				}
			}
			if kept, err := os.ReadFile(path); err != nil || string(kept) != string(content) {
				t.Fatalf("the damaged key was rewritten as %q: %v", kept, err)
			}
		})
	}
}

func TestAKeyThatIsNotAFileIsDamaged(t *testing.T) {
	for name, prepare := range map[string]func(directory, damaged, other string) error{
		"a directory": func(directory, damaged, _ string) error {
			if err := os.Remove(filepath.Join(directory, damaged+".pem")); err != nil {
				return err
			}
			return os.Mkdir(filepath.Join(directory, damaged+".pem"), 0o700)
		},
		"a symbolic link to another key": func(directory, damaged, other string) error {
			if err := os.Remove(filepath.Join(directory, damaged+".pem")); err != nil {
				return err
			}
			return os.Symlink(other+".pem", filepath.Join(directory, damaged+".pem"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := keysDirectory(t)
			keys := openKeys(t, directory)
			damaged, other := create(t, keys), create(t, keys)
			if err := prepare(directory, damaged.ID(), other.ID()); err != nil {
				t.Fatalf("prepare %s: %v", name, err)
			}
			if _, err := keys.Open(damaged.ID()); !errors.Is(err, pki.ErrKeyDamaged) {
				t.Fatalf("open returned %v", err)
			}
		})
	}
}

func TestKeysOthersCanReachAreRefused(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"a key its group can read": 0o640, "a key anybody can read": 0o644} {
		t.Run(name, func(t *testing.T) {
			directory := keysDirectory(t)
			keys := openKeys(t, directory)
			reachable := create(t, keys)
			if err := os.Chmod(filepath.Join(directory, reachable.ID()+".pem"), mode); err != nil {
				t.Fatalf("chmod the key: %v", err)
			}
			if _, err := keys.Open(reachable.ID()); !errors.Is(err, pki.ErrKeyInsecure) {
				t.Fatalf("open returned %v", err)
			}
			if _, err := pki.OpenKeyFiles(root(t, directory)); !errors.Is(err, pki.ErrKeyInsecure) {
				t.Fatalf("opening the keys after a restart returned %v", err)
			}
		})
	}

	t.Run("a directory its group can list", func(t *testing.T) {
		directory := keysDirectory(t)
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatalf("chmod the directory: %v", err)
		}
		if _, err := pki.OpenKeyFiles(root(t, directory)); !errors.Is(err, pki.ErrKeyInsecure) {
			t.Fatalf("opening the keys returned %v", err)
		}
	})
}

func TestAKeyTheAgentCannotReadIsReportedAsSuch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	directory := keysDirectory(t)
	keys := openKeys(t, directory)
	unreadable := create(t, keys)
	if err := os.Chmod(filepath.Join(directory, unreadable.ID()+".pem"), 0); err != nil {
		t.Fatalf("chmod the key: %v", err)
	}
	_, err := keys.Open(unreadable.ID())
	if !errors.Is(err, fs.ErrPermission) || errors.Is(err, pki.ErrKeyMissing) || errors.Is(err, pki.ErrKeyDamaged) {
		t.Fatalf("opening a key the agent cannot read returned %v", err)
	}
}

func TestTheLeftoversOfAnInterruptedWriteAreDiscarded(t *testing.T) {
	directory := keysDirectory(t)
	kept := create(t, openKeys(t, directory))
	content := readKey(t, directory, kept.ID())
	interrupted := strings.Repeat("ab", 32)
	leftovers := map[string][]byte{
		"." + interrupted + ".pem.tmp": content[:len(content)/2],
		"." + kept.ID() + ".pem.tmp":   content,
	}
	for name, written := range leftovers {
		if err := os.WriteFile(filepath.Join(directory, name), written, 0o600); err != nil {
			t.Fatalf("leave an interrupted write: %v", err)
		}
	}

	keys := openKeys(t, directory)
	for name := range leftovers {
		if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the interrupted write %s is still there: %v", name, err)
		}
	}
	if _, err := keys.Open(kept.ID()); err != nil {
		t.Fatalf("the key written before the interruption no longer opens: %v", err)
	}
	if _, err := keys.Open(interrupted); !errors.Is(err, pki.ErrKeyMissing) {
		t.Fatalf("the interrupted key opened with %v", err)
	}
}

func TestKeysSurviveAnAgentKilledWhileCreatingThem(t *testing.T) {
	directory := keysDirectory(t)
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
	child.Env = append(os.Environ(), childKeys+"="+directory)
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
			id, created := strings.CutPrefix(report, "created ")
			if !open || !created {
				t.Fatalf("the child reported %q", report)
			}
			reported = append(reported, id)
		case <-timeout:
			t.Fatalf("the child created %d keys within 30s", len(reported))
		}
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatalf("kill the child: %v", err)
	}
	for range reports {
	}
	_ = child.Wait()

	keys := openKeys(t, directory)
	held := heldKeys(t, directory)
	for _, id := range reported {
		if !held[id] {
			t.Errorf("key %s was reported created and is gone", id)
		}
	}
	for id := range held {
		if _, err := keys.Open(id); err != nil {
			t.Errorf("the killed child left a key that does not open: %v", err)
		}
	}
}

func keysDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	return directory
}

func root(t *testing.T, directory string) *os.Root {
	t.Helper()
	opened, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened
}

func openKeys(t *testing.T, directory string) *pki.KeyFiles {
	t.Helper()
	keys, err := pki.OpenKeyFiles(root(t, directory))
	if err != nil {
		t.Fatalf("open the keys in %s: %v", directory, err)
	}
	return keys
}

func create(t *testing.T, keys pki.KeyProvider) pki.Key {
	t.Helper()
	created, err := keys.Create()
	if err != nil {
		t.Fatalf("create a key: %v", err)
	}
	return created
}

func heldKeys(t *testing.T, directory string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("list %s: %v", directory, err)
	}
	held := map[string]bool{}
	for _, entry := range entries {
		named := keyFile.FindStringSubmatch(entry.Name())
		if named == nil {
			t.Fatalf("%s holds %s, which is not a key", directory, entry.Name())
		}
		held[named[1]] = true
	}
	return held
}

func readKey(t *testing.T, directory, id string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, id+".pem"))
	if err != nil {
		t.Fatalf("read key %s: %v", id, err)
	}
	return content
}

func decodeKey(t *testing.T, content []byte) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("the key file holds no PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("decode the key file: %v", err)
	}
	decoded, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("the key file holds a %T", parsed)
	}
	return decoded
}

func generate(t *testing.T, draw func() (any, error)) any {
	t.Helper()
	drawn, err := draw()
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}
	return drawn
}

func encodeKey(t *testing.T, drawn any) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(drawn)
	if err != nil {
		t.Fatalf("encode a %T: %v", drawn, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func exposes(text string, key []byte) bool {
	lines := strings.Split(strings.TrimSpace(string(key)), "\n")
	for _, line := range lines[1 : len(lines)-1] {
		if strings.Contains(text, line) {
			return true
		}
	}
	return false
}
