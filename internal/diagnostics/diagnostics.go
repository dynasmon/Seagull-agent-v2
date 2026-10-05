// Package diagnostics writes down what helps troubleshoot the agent, in one
// bundle an operator reads before handing it over: what the build is, what the
// agent runs on and last said of itself, what its installation records and
// holds, the certificate it presents and whom it trusts, and what it and the
// commands run as its account wrote to the system journal lately. It writes
// what it is handed, lists files without opening them, and holds no key, no
// record the spool keeps and nothing else that authenticates the agent.
package diagnostics

import (
	"encoding/json"
	"io/fs"
	"runtime/debug"
	"time"
	"unicode/utf8"
)

const (
	Format   = 1
	MaxBytes = 8 << 20
	MaxTime  = time.Minute
	maxText  = 1 << 10
	cut      = "..."
)

// Text is what a bundle says in words: a path, a name, a reason. However long
// what it was made from, it is written as a kilobyte at most.
type Text string

func (t Text) MarshalText() ([]byte, error) { return []byte(bounded(string(t), maxText)), nil }

type Bundle struct {
	Format        int         `json:"format"`
	WrittenAt     time.Time   `json:"written_at"`
	Writer        Writer      `json:"writer"`
	Limits        Limits      `json:"limits"`
	Build         Build       `json:"build"`
	Configuration Read        `json:"configuration"`
	Status        Read        `json:"status"`
	Installation  Read        `json:"installation"`
	Credential    Credential  `json:"credential"`
	Authorities   Authorities `json:"authorities"`
	Files         Files       `json:"files"`
	Logs          Logs        `json:"logs"`
}

type Writer struct {
	User   int   `json:"user"`
	Group  int   `json:"group"`
	Groups []int `json:"groups"`
}

type Limits struct {
	Bytes        int `json:"bytes"`
	Files        int `json:"files"`
	Depth        int `json:"depth"`
	LogEntries   int `json:"log_entries"`
	LogBytes     int `json:"log_bytes"`
	MessageBytes int `json:"message_bytes"`
	TextBytes    int `json:"text_bytes"`
	Seconds      int `json:"seconds"`
}

type Build struct {
	Identity     Text           `json:"identity"`
	Versions     map[string]int `json:"versions"`
	Go           Text           `json:"go,omitempty"`
	Path         Text           `json:"path,omitempty"`
	Main         Module         `json:"main"`
	Settings     map[Text]Text  `json:"settings,omitempty"`
	Dependencies []Module       `json:"dependencies,omitempty"`
}

type Module struct {
	Path    Text `json:"path"`
	Version Text `json:"version,omitempty"`
	Sum     Text `json:"sum,omitempty"`
}

// A Read is what the agent read in one place, as it read it, or why it could
// not and what to do about that.
type Read struct {
	From     Text            `json:"from,omitempty"`
	Held     json.RawMessage `json:"held,omitempty"`
	Unread   Text            `json:"unread,omitempty"`
	Recovery Text            `json:"recovery,omitempty"`
}

type Credential struct {
	From         Text          `json:"from,omitempty"`
	Chain        []Certificate `json:"chain,omitempty"`
	Verification Text          `json:"verification,omitempty"`
	Unread       Text          `json:"unread,omitempty"`
	Recovery     Text          `json:"recovery,omitempty"`
}

type Certificate struct {
	Subject     Text      `json:"subject"`
	Issuer      Text      `json:"issuer"`
	Serial      Text      `json:"serial"`
	Fingerprint Text      `json:"fingerprint_sha256"`
	KeyID       Text      `json:"key_id"`
	Key         Text      `json:"key"`
	Signature   Text      `json:"signature"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Authority   bool      `json:"authority"`
	Usages      []Text    `json:"usages,omitempty"`
	Names       []Text    `json:"names,omitempty"`
}

type Authorities struct {
	Trusted    Text `json:"trusted,omitempty"`
	Configured Set  `json:"configured"`
	Adopted    *Set `json:"adopted,omitempty"`
}

type Set struct {
	From        Text          `json:"from,omitempty"`
	Digest      Text          `json:"digest_sha256,omitempty"`
	Authorities []Certificate `json:"authorities,omitempty"`
	Unread      Text          `json:"unread,omitempty"`
	Recovery    Text          `json:"recovery,omitempty"`
}

type Files struct {
	Directory Text   `json:"directory"`
	Entries   []File `json:"entries,omitempty"`
	Complete  bool   `json:"complete"`
	Unread    Text   `json:"unread,omitempty"`

	directories []fs.FileInfo
}

type File struct {
	Path     Text      `json:"path"`
	Mode     Text      `json:"mode"`
	Size     int64     `json:"size"`
	Owner    *int      `json:"owner,omitempty"`
	Modified time.Time `json:"modified"`
}

type Logs struct {
	Sources  []Text  `json:"sources"`
	Entries  []Entry `json:"entries"`
	Complete bool    `json:"complete"`
	Unread   []Text  `json:"unread,omitempty"`
	Recovery Text    `json:"recovery,omitempty"`
}

type Entry struct {
	At       time.Time `json:"at"`
	Priority int       `json:"priority"`
	Process  int       `json:"process,omitempty"`
	User     *int      `json:"user,omitempty"`
	Login    *int      `json:"login,omitempty"`
	Command  Text      `json:"command,omitempty"`
	Message  string    `json:"message"`

	cursor string
}

func Took(from string, held any) Read {
	encoded, err := json.Marshal(held)
	if err != nil {
		return Read{From: Text(from), Unread: Text("it cannot be written down: " + err.Error())}
	}
	return Read{From: Text(from), Held: encoded}
}

func Missed(from string, err error, recovery string) Read {
	return Read{From: Text(from), Unread: Text(err.Error()), Recovery: Text(recovery)}
}

func Built(identity string, versions map[string]int, info *debug.BuildInfo) Build {
	built := Build{Identity: Text(identity), Versions: versions}
	if info == nil {
		return built
	}
	built.Go, built.Path = Text(info.GoVersion), Text(info.Path)
	built.Main = Module{Path: Text(info.Main.Path), Version: Text(info.Main.Version), Sum: Text(info.Main.Sum)}
	built.Settings = make(map[Text]Text, len(info.Settings))
	for _, setting := range info.Settings {
		built.Settings[Text(setting.Key)] = Text(setting.Value)
	}
	for _, dependency := range info.Deps {
		if dependency.Replace != nil {
			dependency = dependency.Replace
		}
		built.Dependencies = append(built.Dependencies, Module{Path: Text(dependency.Path), Version: Text(dependency.Version), Sum: Text(dependency.Sum)})
	}
	return built
}

// Unread names each part of the bundle the agent could not read, with why.
func (b Bundle) Unread() []string {
	var unread []string
	for _, part := range []struct {
		name   string
		reason Text
	}{
		{"configuration", b.Configuration.Unread},
		{"status", b.Status.Unread},
		{"installation", b.Installation.Unread},
		{"credential", b.Credential.Unread},
		{"configured authorities", b.Authorities.Configured.Unread},
		{"files", b.Files.Unread},
	} {
		if part.reason != "" {
			unread = append(unread, part.name+": "+bounded(string(part.reason), maxText))
		}
	}
	if b.Authorities.Adopted != nil && b.Authorities.Adopted.Unread != "" {
		unread = append(unread, "adopted authorities: "+bounded(string(b.Authorities.Adopted.Unread), maxText))
	}
	for _, reason := range b.Logs.Unread {
		unread = append(unread, "logs: "+bounded(string(reason), maxText))
	}
	return unread
}

func bounded(held string, most int) string {
	if len(held) <= most {
		return held
	}
	held = held[:most]
	for range utf8.UTFMax - 1 {
		if last, width := utf8.DecodeLastRuneInString(held); last != utf8.RuneError || width > 1 {
			break
		}
		held = held[:len(held)-1]
	}
	return held + cut
}
