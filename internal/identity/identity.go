package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
)

const (
	format        = 1
	stateFile     = "installation.json"
	replacedDir   = "replaced"
	maxStateBytes = 64 << 10
)

var (
	ErrLocked         = errors.New("another agent process holds the installation state")
	ErrInsecure       = errors.New("the installation state is not private to the account the agent runs as")
	ErrDamaged        = errors.New("the installation state is damaged")
	ErrNewer          = errors.New("the installation state was written by a newer agent")
	ErrNoInstallation = errors.New("there is no installation to replace")
	ErrRefused        = errors.New("the installation refuses the credential generation")
)

var (
	installationIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	agentIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	digestPattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	serialPattern         = regexp.MustCompile(`^(?:[0-9a-f]{2}){1,32}$`)
)

type Certificate struct {
	Subject           string    `json:"subject"`
	Serial            string    `json:"serial"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
}

// The credential generation the installation authenticates with: the agent the
// platform issued it for, the key that proves it and what the certificate says.
// It holds no key and no secret, so a copy of it authenticates nothing.
type Enrollment struct {
	AgentID     string      `json:"agent_id"`
	Generation  uint64      `json:"generation"`
	KeyID       string      `json:"key_id"`
	Certificate Certificate `json:"certificate"`
}

type state struct {
	Format         int         `json:"format"`
	InstallationID string      `json:"installation_id"`
	CreatedAt      time.Time   `json:"created_at"`
	Replaces       string      `json:"replaces,omitempty"`
	Enrollment     *Enrollment `json:"enrollment,omitempty"`
}

type Installation struct {
	directory string
	root      *os.Root
	lock      *os.File
	state     state
	created   bool
}

// Open holds the installation in directory until Close, creating it when the
// directory is new or empty. A directory that holds anything else without an
// installation is damaged, never new: an identity is not recreated in its place.
func Open(directory string) (*Installation, error) {
	installation, err := claim(directory, true)
	if err != nil {
		return nil, err
	}
	loaded, found, err := installation.read()
	switch {
	case err == nil && found:
		installation.state = loaded
	case err == nil:
		err = installation.start()
	}
	if err != nil {
		installation.Close()
		return nil, err
	}
	return installation, nil
}

// Replace discards the installation in directory for a new, unenrolled one,
// even when its state is damaged, missing or newer than this agent reads.
// Everything the replaced installation held is set aside under replaced/, and
// the new installation names the one it replaces whenever that one could be read.
func Replace(directory string) (*Installation, error) {
	installation, err := claim(directory, false)
	if err != nil {
		return nil, err
	}
	previous, found, err := installation.read()
	switch {
	case err == nil && found:
		err = installation.replace(previous.InstallationID)
	case err == nil, errors.Is(err, ErrDamaged), errors.Is(err, ErrNewer), errors.Is(err, ErrInsecure):
		err = installation.replace("")
	}
	if err != nil {
		installation.Close()
		return nil, err
	}
	return installation, nil
}

func (i *Installation) ID() string { return i.state.InstallationID }

func (i *Installation) Replaces() string { return i.state.Replaces }

func (i *Installation) Created() bool { return i.created }

func (i *Installation) Enrollment() (Enrollment, bool) {
	if i.state.Enrollment == nil {
		return Enrollment{}, false
	}
	return *i.state.Enrollment, true
}

func (i *Installation) Activate(next Enrollment) error {
	if err := next.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrRefused, err)
	}
	switch current := i.state.Enrollment; {
	case current == nil && next.Generation != 1:
		return fmt.Errorf("%w: the first credential generation is 1, not %d", ErrRefused, next.Generation)
	case current != nil && next.AgentID != current.AgentID:
		return fmt.Errorf("%w: the installation is enrolled as %q, and enrolling it as %q takes a replacement installation",
			ErrRefused, current.AgentID, next.AgentID)
	case current != nil && next.Generation != current.Generation+1:
		return fmt.Errorf("%w: generation %d is active, so the next one is %d, not %d",
			ErrRefused, current.Generation, current.Generation+1, next.Generation)
	}
	updated := i.state
	updated.Enrollment = &next
	if err := i.write(updated); err != nil {
		return err
	}
	i.state = updated
	return nil
}

func (i *Installation) Close() error {
	return errors.Join(i.lock.Close(), i.root.Close())
}

func claim(directory string, create bool) (*Installation, error) {
	if create {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create the installation state directory: %w", err)
		}
	}
	described, err := os.Lstat(directory)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !create:
		return nil, fmt.Errorf("%w in %s", ErrNoInstallation, directory)
	case err != nil:
		return nil, fmt.Errorf("inspect the installation state directory: %w", err)
	case !described.IsDir():
		return nil, fmt.Errorf("%w: %s is not a directory", ErrInsecure, directory)
	}
	if err := private(directory, described); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open the installation state directory: %w", err)
	}
	lock, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("open the installation state directory: %w", err)
	}
	installation := &Installation{directory: directory, root: root, lock: lock}
	if opened, err := lock.Stat(); err != nil || !os.SameFile(opened, described) {
		installation.Close()
		return nil, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, directory)
	}
	if err := files.Lock(lock); err != nil {
		installation.Close()
		if errors.Is(err, files.ErrLocked) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, directory)
		}
		return nil, err
	}
	if err := installation.discardInterruptedWrites(); err != nil {
		installation.Close()
		return nil, err
	}
	return installation, nil
}

func (i *Installation) read() (state, bool, error) {
	path := i.path(stateFile)
	described, err := i.root.Lstat(stateFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return state{}, false, nil
	case err != nil:
		return state{}, false, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return state{}, false, fmt.Errorf("%w: %s is not a regular file", ErrDamaged, path)
	}
	if err := private(path, described); err != nil {
		return state{}, false, err
	}
	file, err := i.root.Open(stateFile)
	if err != nil {
		return state{}, false, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return state{}, false, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return state{}, false, fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > maxStateBytes {
		return state{}, false, fmt.Errorf("%w: %s is larger than %d bytes", ErrDamaged, path, maxStateBytes)
	}
	decoded, err := decode(content)
	if err != nil {
		kind := ErrDamaged
		if errors.As(err, new(newerFormat)) {
			kind = ErrNewer
		}
		return state{}, false, fmt.Errorf("%w: %s: %v", kind, path, err)
	}
	return decoded, true, nil
}

func (i *Installation) start() error {
	names, err := i.names()
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return fmt.Errorf("%w: %s holds %s but no %s", ErrDamaged, i.directory, names[0], stateFile)
	}
	return i.create("")
}

func (i *Installation) create(replaces string) error {
	fresh := state{Format: format, InstallationID: newInstallationID(), CreatedAt: time.Now().UTC(), Replaces: replaces}
	if err := i.write(fresh); err != nil {
		return err
	}
	i.state, i.created = fresh, true
	return nil
}

func (i *Installation) replace(previous string) error {
	names, err := i.names()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("%w in %s", ErrNoInstallation, i.directory)
	}
	if err := i.root.Mkdir(replacedDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create %s: %w", i.path(replacedDir), err)
	}
	described, err := i.root.Lstat(replacedDir)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", i.path(replacedDir), err)
	}
	if !described.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInsecure, i.path(replacedDir))
	}
	if err := private(i.path(replacedDir), described); err != nil {
		return err
	}
	kept := filepath.Join(replacedDir, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := i.root.Mkdir(kept, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", i.path(kept), err)
	}
	for _, name := range names {
		if name == replacedDir {
			continue
		}
		if err := i.setAside(name, filepath.Join(kept, name)); err != nil {
			return fmt.Errorf("set %s aside as %s: %w", i.path(name), i.path(filepath.Join(kept, name)), err)
		}
	}
	for _, synced := range []string{kept, replacedDir, "."} {
		if err := i.syncDirectory(synced); err != nil {
			return err
		}
	}
	return i.create(previous)
}

func (i *Installation) setAside(name, kept string) error {
	if name == stateFile {
		if described, err := i.root.Lstat(name); err == nil && described.Mode().IsRegular() {
			return i.root.Link(name, kept)
		}
	}
	return i.root.Rename(name, kept)
}

func (i *Installation) write(next state) error {
	if err := next.validate(); err != nil {
		return fmt.Errorf("refuse to write %s: %w", i.path(stateFile), err)
	}
	content, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", i.path(stateFile), err)
	}
	temporary := "." + stateFile + "." + hex.EncodeToString(randomBytes(8)) + ".tmp"
	file, err := i.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", i.path(stateFile), err)
	}
	_, err = file.Write(append(content, '\n'))
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = i.root.Rename(temporary, stateFile)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", i.path(stateFile), err), ignoreMissing(i.root.Remove(temporary)))
	}
	return i.syncDirectory(".")
}

func (i *Installation) syncDirectory(name string) error {
	directory, err := i.root.Open(name)
	if err != nil {
		return fmt.Errorf("open %s: %w", i.path(name), err)
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return fmt.Errorf("sync %s: %w", i.path(name), err)
	}
	return nil
}

func (i *Installation) discardInterruptedWrites() error {
	names, err := i.names()
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.HasPrefix(name, "."+stateFile+".") && strings.HasSuffix(name, ".tmp") {
			if err := i.root.Remove(name); err != nil {
				return fmt.Errorf("discard the interrupted write %s: %w", i.path(name), err)
			}
		}
	}
	return nil
}

func (i *Installation) names() ([]string, error) {
	directory, err := i.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", i.directory, err)
	}
	defer directory.Close()
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", i.directory, err)
	}
	return names, nil
}

func (i *Installation) path(name string) string { return filepath.Join(i.directory, name) }

func decode(content []byte) (state, error) {
	var declared struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(content, &declared); err != nil {
		return state{}, fmt.Errorf("it is not an installation state: %v", err)
	}
	if declared.Format > format {
		return state{}, newerFormat(declared.Format)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var decoded state
	if err := decoder.Decode(&decoded); err != nil {
		return state{}, fmt.Errorf("it is not an installation state: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return state{}, errors.New("it holds more than one document")
	}
	return decoded, decoded.validate()
}

func (s state) validate() error {
	switch {
	case s.Format != format:
		return fmt.Errorf("format %d is not one this agent writes", s.Format)
	case !installationIDPattern.MatchString(s.InstallationID):
		return fmt.Errorf("installation_id %q is not a random UUID", s.InstallationID)
	case s.CreatedAt.IsZero():
		return errors.New("created_at is missing")
	case s.Replaces != "" && !installationIDPattern.MatchString(s.Replaces):
		return fmt.Errorf("replaces %q is not a random UUID", s.Replaces)
	case s.Replaces == s.InstallationID:
		return errors.New("the installation replaces itself")
	case s.Enrollment != nil:
		return s.Enrollment.validate()
	}
	return nil
}

func (e Enrollment) validate() error {
	switch {
	case !agentIDPattern.MatchString(e.AgentID):
		return fmt.Errorf("agent_id %q is not an identifier the platform issues certificates for", e.AgentID)
	case e.Generation == 0:
		return errors.New("generation 0 does not exist: generations count from 1")
	case !digestPattern.MatchString(e.KeyID):
		return fmt.Errorf("key_id %q is not a SHA-256 digest in lower-case hexadecimal", e.KeyID)
	case e.Certificate.Subject != e.AgentID:
		return fmt.Errorf("the certificate names %q, not agent %q", e.Certificate.Subject, e.AgentID)
	case !serialPattern.MatchString(e.Certificate.Serial):
		return fmt.Errorf("the certificate serial %q is not whole bytes of lower-case hexadecimal", e.Certificate.Serial)
	case !digestPattern.MatchString(e.Certificate.FingerprintSHA256):
		return fmt.Errorf("the certificate fingerprint %q is not a SHA-256 digest in lower-case hexadecimal", e.Certificate.FingerprintSHA256)
	case e.Certificate.NotBefore.IsZero() || !e.Certificate.NotAfter.After(e.Certificate.NotBefore):
		return errors.New("the certificate stops being valid before it starts")
	}
	return nil
}

type newerFormat int

func (f newerFormat) Error() string {
	return fmt.Sprintf("format %d, and this agent reads format %d", int(f), format)
}

func private(path string, described fs.FileInfo) error {
	if err := files.Private(described); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return fmt.Errorf("keep installation state in %s: %w", path, err)
		}
		return fmt.Errorf("%w: %s %v", ErrInsecure, path, err)
	}
	return nil
}

func newInstallationID() string {
	drawn := randomBytes(16)
	drawn[6] = drawn[6]&0x0f | 0x40
	drawn[8] = drawn[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", drawn[0:4], drawn[4:6], drawn[6:8], drawn[8:10], drawn[10:])
}

func randomBytes(count int) []byte {
	drawn := make([]byte, count)
	rand.Read(drawn)
	return drawn
}

func ignoreMissing(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
