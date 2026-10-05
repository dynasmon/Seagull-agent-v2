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
	"sync"
	"sync/atomic"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
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
	ErrUnasked        = errors.New("the installation refuses to ask for that certificate")
	ErrUnadopted      = errors.New("the installation refuses to trust those authorities")
)

var (
	installationIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	directoryPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
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

// A Record is what an installation says of itself, which Recorded reads beside
// an agent that holds the installation, without its lock and changing nothing:
// which installation it is and which one it replaced, the credential
// generation it authenticates with, which names the agent the platform issued
// it for, the key that proves it, when that key was drawn and what the
// certificate says, the certificate it asked for and was not issued yet, and
// the authorities the platform published to it over its own credential. None
// holds a key or a secret, so a copy of them authenticates nothing.
type Record struct {
	InstallationID string      `json:"installation_id"`
	CreatedAt      time.Time   `json:"created_at"`
	Replaces       string      `json:"replaces,omitempty"`
	Enrollment     *Enrollment `json:"enrollment,omitempty"`
	Request        *Request    `json:"request,omitempty"`
	Trust          *Trust      `json:"trust,omitempty"`
}

type Enrollment struct {
	AgentID     string      `json:"agent_id"`
	Generation  uint64      `json:"generation"`
	KeyID       string      `json:"key_id"`
	KeyDrawnAt  time.Time   `json:"key_drawn_at,omitzero"`
	Certificate Certificate `json:"certificate"`
}

type Request struct {
	AgentID     string    `json:"agent_id"`
	KeyID       string    `json:"key_id"`
	RequestedAt time.Time `json:"requested_at"`
}

type Trust struct {
	Authorities string    `json:"authorities_sha256"`
	Configured  string    `json:"configured_sha256"`
	AdoptedAt   time.Time `json:"adopted_at"`
}

type state struct {
	Format int `json:"format"`
	Record
}

type Installation struct {
	directory   string
	root        *os.Root
	lock        *os.File
	mu          sync.Mutex
	state       atomic.Pointer[state]
	created     bool
	directories []*os.Root
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
		installation.state.Store(&loaded)
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

func (i *Installation) ID() string { return i.state.Load().InstallationID }

func (i *Installation) Replaces() string { return i.state.Load().Replaces }

func (i *Installation) Created() bool { return i.created }

func (i *Installation) Enrollment() (Enrollment, bool) {
	if held := i.state.Load().Enrollment; held != nil {
		return *held, true
	}
	return Enrollment{}, false
}

func (i *Installation) Pending() (Request, bool) {
	if held := i.state.Load().Request; held != nil {
		return *held, true
	}
	return Request{}, false
}

func (i *Installation) Trust() (Trust, bool) {
	if held := i.state.Load().Trust; held != nil {
		return *held, true
	}
	return Trust{}, false
}

func (i *Installation) Activate(next Enrollment) error {
	if err := next.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrRefused, err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	held := i.state.Load()
	switch current, pending := held.Enrollment, held.Request; {
	case current == nil && next.Generation != 1:
		return fmt.Errorf("%w: the first credential generation is 1, not %d", ErrRefused, next.Generation)
	case current != nil && next.AgentID != current.AgentID:
		return fmt.Errorf("%w: the installation is enrolled as %s, and enrolling it as %s takes a replacement installation",
			ErrRefused, secrets.Shown(current.AgentID), secrets.Shown(next.AgentID))
	case current != nil && next.Generation != current.Generation+1:
		return fmt.Errorf("%w: generation %d is active, so the next one is %d, not %d",
			ErrRefused, current.Generation, current.Generation+1, next.Generation)
	case pending != nil && pending.KeyID == next.KeyID && pending.AgentID != next.AgentID:
		return fmt.Errorf("%w: key %s was asked to be agent %s, not %s",
			ErrRefused, next.KeyID, secrets.Shown(pending.AgentID), secrets.Shown(next.AgentID))
	}
	updated := *held
	updated.Enrollment = &next
	if updated.Request != nil && updated.Request.KeyID == next.KeyID {
		updated.Request = nil
	}
	return i.commit(updated, ErrRefused)
}

func (i *Installation) MayAsk(agentID string) error {
	return mayAsk(i.state.Load(), agentID)
}

func (i *Installation) Ask(next Request) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	held := i.state.Load()
	if err := mayAsk(held, next.AgentID); err != nil {
		return err
	}
	updated := *held
	updated.Request = &next
	return i.commit(updated, ErrUnasked)
}

func (i *Installation) Adopt(next Trust) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	updated := *i.state.Load()
	updated.Trust = &next
	return i.commit(updated, ErrUnadopted)
}

func mayAsk(held *state, agentID string) error {
	if !agentIDPattern.MatchString(agentID) {
		return fmt.Errorf("%w: %s is not an agent the platform issues certificates for", ErrUnasked, secrets.Shown(agentID))
	}
	if current := held.Enrollment; current != nil && current.AgentID != agentID {
		return fmt.Errorf("%w: the installation is enrolled as %s, and enrolling it as %s takes a replacement installation",
			ErrUnasked, secrets.Shown(current.AgentID), secrets.Shown(agentID))
	}
	return nil
}

func (i *Installation) commit(updated state, refused error) error {
	if err := updated.validate(); err != nil {
		return fmt.Errorf("%w: %v", refused, err)
	}
	if err := i.write(updated); err != nil {
		return err
	}
	i.state.Store(&updated)
	return nil
}

// Directory holds name, a private directory of the installation, creating it
// when it is missing. What it holds belongs to the installation: a replacement
// sets it aside with the rest, and Close closes the root it returns.
func (i *Installation) Directory(name string) (*os.Root, error) {
	if !directoryPattern.MatchString(name) || name == replacedDir {
		return nil, fmt.Errorf("%q does not name a directory of the installation", name)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	path := i.path(name)
	if err := i.root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	if err := i.syncDirectory("."); err != nil {
		return nil, err
	}
	described, err := i.root.Lstat(name)
	switch {
	case err != nil:
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	case !described.IsDir():
		return nil, fmt.Errorf("%w: %s is not a directory", ErrInsecure, path)
	}
	if err := private(path, described); err != nil {
		return nil, err
	}
	opened, err := i.root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if held, err := opened.Stat("."); err != nil || !os.SameFile(held, described) {
		opened.Close()
		return nil, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, path)
	}
	i.directories = append(i.directories, opened)
	return opened, nil
}

func (i *Installation) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	closed := make([]error, 0, len(i.directories)+2)
	for _, directory := range i.directories {
		closed = append(closed, directory.Close())
	}
	return errors.Join(append(closed, i.lock.Close(), i.root.Close())...)
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
	return readState(i.root, i.path(stateFile))
}

func Recorded(directory string) (Record, bool, error) {
	described, err := os.Lstat(directory)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Record{}, false, nil
	case err != nil:
		return Record{}, false, fmt.Errorf("inspect the installation state directory: %w", err)
	case !described.IsDir():
		return Record{}, false, fmt.Errorf("%w: %s is not a directory", ErrInsecure, directory)
	}
	if err := private(directory, described); err != nil {
		return Record{}, false, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return Record{}, false, fmt.Errorf("open the installation state directory: %w", err)
	}
	defer root.Close()
	held, found, err := readState(root, filepath.Join(directory, stateFile))
	if err != nil || !found {
		return Record{}, false, err
	}
	return held.Record, true, nil
}

func Adopted(directory string) (Trust, bool, error) {
	held, found, err := Recorded(directory)
	if err != nil || !found || held.Trust == nil {
		return Trust{}, false, err
	}
	return *held.Trust, true, nil
}

func readState(root *os.Root, path string) (state, bool, error) {
	described, err := root.Lstat(stateFile)
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
	file, err := root.Open(stateFile)
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
		return state{}, false, fmt.Errorf("%w: %s: %s", kind, path, secrets.Bounded(err.Error()))
	}
	return decoded, true, nil
}

func (i *Installation) start() error {
	names, err := i.names()
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return fmt.Errorf("%w: %s holds %s but no %s", ErrDamaged, i.directory, secrets.Shown(names[0]), stateFile)
	}
	return i.create("")
}

func (i *Installation) create(replaces string) error {
	fresh := state{Format: format, Record: Record{InstallationID: newInstallationID(), CreatedAt: time.Now().UTC(), Replaces: replaces}}
	if err := i.write(fresh); err != nil {
		return err
	}
	i.state.Store(&fresh)
	i.created = true
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
		return state{}, fmt.Errorf("it is not an installation state: %s", secrets.Bounded(err.Error()))
	}
	if declared.Format > format {
		return state{}, newerFormat(declared.Format)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var decoded state
	if err := decoder.Decode(&decoded); err != nil {
		return state{}, fmt.Errorf("it is not an installation state: %s", secrets.Bounded(err.Error()))
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
		return fmt.Errorf("installation_id %s is not a random UUID", secrets.Shown(s.InstallationID))
	case s.CreatedAt.IsZero():
		return errors.New("created_at is missing")
	case s.Replaces != "" && !installationIDPattern.MatchString(s.Replaces):
		return fmt.Errorf("replaces %s is not a random UUID", secrets.Shown(s.Replaces))
	case s.Replaces == s.InstallationID:
		return errors.New("the installation replaces itself")
	}
	if s.Enrollment != nil {
		if err := s.Enrollment.validate(); err != nil {
			return err
		}
	}
	if s.Request != nil {
		if err := s.Request.validate(); err != nil {
			return err
		}
		if s.Enrollment != nil && s.Request.AgentID != s.Enrollment.AgentID {
			return fmt.Errorf("the installation is enrolled as %s and asks to be %s", secrets.Shown(s.Enrollment.AgentID), secrets.Shown(s.Request.AgentID))
		}
	}
	if s.Trust != nil {
		return s.Trust.validate()
	}
	return nil
}

func (t Trust) validate() error {
	switch {
	case !digestPattern.MatchString(t.Authorities):
		return fmt.Errorf("the trust names authorities_sha256 %s, which is not a SHA-256 digest in lower-case hexadecimal", secrets.Shown(t.Authorities))
	case !digestPattern.MatchString(t.Configured):
		return fmt.Errorf("the trust names configured_sha256 %s, which is not a SHA-256 digest in lower-case hexadecimal", secrets.Shown(t.Configured))
	case t.AdoptedAt.IsZero():
		return errors.New("the trust says nothing of when it was adopted")
	}
	return nil
}

func (r Request) validate() error {
	switch {
	case !agentIDPattern.MatchString(r.AgentID):
		return fmt.Errorf("the request asks for agent_id %s, which is not an identifier the platform issues certificates for", secrets.Shown(r.AgentID))
	case !digestPattern.MatchString(r.KeyID):
		return fmt.Errorf("the request names key_id %s, which is not a SHA-256 digest in lower-case hexadecimal", secrets.Shown(r.KeyID))
	case r.RequestedAt.IsZero():
		return errors.New("the request says nothing of when it was made")
	}
	return nil
}

func (e Enrollment) validate() error {
	switch {
	case !agentIDPattern.MatchString(e.AgentID):
		return fmt.Errorf("agent_id %s is not an identifier the platform issues certificates for", secrets.Shown(e.AgentID))
	case e.Generation == 0:
		return errors.New("generation 0 does not exist: generations count from 1")
	case !digestPattern.MatchString(e.KeyID):
		return fmt.Errorf("key_id %s is not a SHA-256 digest in lower-case hexadecimal", secrets.Shown(e.KeyID))
	case e.Certificate.Subject != e.AgentID:
		return fmt.Errorf("the certificate names %s, not agent %s", secrets.Shown(e.Certificate.Subject), secrets.Shown(e.AgentID))
	case !serialPattern.MatchString(e.Certificate.Serial):
		return fmt.Errorf("the certificate serial %s is not whole bytes of lower-case hexadecimal", secrets.Shown(e.Certificate.Serial))
	case !digestPattern.MatchString(e.Certificate.FingerprintSHA256):
		return fmt.Errorf("the certificate fingerprint %s is not a SHA-256 digest in lower-case hexadecimal", secrets.Shown(e.Certificate.FingerprintSHA256))
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
