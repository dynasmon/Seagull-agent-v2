package authentication

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxMessage = 1 << 10
	maxUser    = 256
	maxAddress = 45
)

type extra int

const (
	without extra = iota + 1
	key
	described
)

// What the monitor of sshd writes as it decides an authentication: Accepted
// or Failed, the method, the user, the address and port the connection came
// from and, for some methods, what the key or the client said. A user that
// does not exist is the client's word, and so is a certificate's identifier.
var methods = map[string]extra{
	"password":             without,
	"keyboard-interactive": without,
	"none":                 without,
	"publickey":            key,
	"hostbased":            described,
	"gssapi-with-mic":      described,
}

var (
	submethod   = regexp.MustCompile(`^[a-z]{1,16}$`)
	fingerprint = `(?:SHA256:[A-Za-z0-9+/]{43}|MD5:(?:[0-9a-f]{2}:){15}[0-9a-f]{2}|\(null\))`
	plainKey    = regexp.MustCompile(`^[A-Z0-9]+(?:-SK)? ` + fingerprint + `(?:, signature count = [0-9]{1,10})?$`)
	certified   = regexp.MustCompile(`^[A-Z0-9]+(?:-SK)?-CERT ` + fingerprint + ` ID .* \(serial [0-9]{1,20}\) CA [A-Z0-9]+(?:-SK)? ` + fingerprint + `(?:, .*)?$`)
)

type attempt struct {
	accepted bool
	method   string
	invalid  bool
	placed   bool
	user     string
	address  netip.Addr
	port     uint32
}

type place struct {
	at      int
	address netip.Addr
	port    uint32
}

// The user and the place a connection came from are read only when one place
// fits the line: a user that does not exist, or a certificate's identifier,
// can hold what looks like one, and an attempt then says only its outcome.
func parse(message string) (attempt, bool) {
	if len(message) > maxMessage || !printable(message) {
		return attempt{}, false
	}
	var found attempt
	rest, accepted := strings.CutPrefix(message, "Accepted ")
	if !accepted {
		var failed bool
		if rest, failed = strings.CutPrefix(message, "Failed "); !failed {
			return attempt{}, false
		}
	}
	method, rest, cut := strings.Cut(rest, " for ")
	name, sub, specified := strings.Cut(method, "/")
	kind, known := methods[name]
	if !cut || !known || (specified && (name != "keyboard-interactive" || !submethod.MatchString(sub))) {
		return attempt{}, false
	}
	rest, invalid := strings.CutPrefix(rest, "invalid user ")
	if accepted && invalid {
		return attempt{}, false
	}
	found.accepted, found.method, found.invalid = accepted, method, invalid
	var places []place
	for from := 0; ; {
		at := strings.Index(rest[from:], " from ")
		if at < 0 {
			break
		}
		at += from
		if fitted, ok := fits(rest[at+len(" from "):], kind); ok {
			fitted.at = at
			places = append(places, fitted)
		}
		from = at + 1
	}
	if len(places) == 1 {
		found.placed, found.user, found.address, found.port = true, bounded(rest[:places[0].at], maxUser), places[0].address, places[0].port
	}
	return found, true
}

func fits(tail string, kind extra) (place, bool) {
	address, tail, cut := strings.Cut(tail, " port ")
	if !cut || address == "" || strings.Contains(address, " ") {
		return place{}, false
	}
	digits, said, cut := strings.Cut(tail, " ssh2")
	if !cut || len(digits) == 0 || len(digits) > 5 || strings.Trim(digits, "0123456789") != "" || (len(digits) > 1 && digits[0] == '0') {
		return place{}, false
	}
	port, err := strconv.ParseUint(digits, 10, 16)
	if err != nil {
		return place{}, false
	}
	if said != "" {
		info, cut := strings.CutPrefix(said, ": ")
		switch {
		case !cut || info == "" || kind == without:
			return place{}, false
		case kind == key && !plainKey.MatchString(info) && !certified.MatchString(info):
			return place{}, false
		}
	}
	found := place{port: uint32(port)}
	if parsed, err := netip.ParseAddr(address); err == nil && len(address) <= maxAddress {
		found.address = parsed
	}
	return found, true
}

func printable(text string) bool {
	for i := range len(text) {
		if text[i] < 0x20 || text[i] > 0x7e {
			return false
		}
	}
	return true
}

func bounded(text string, most int) string {
	text = strings.ToValidUTF8(text, "�")
	if len(text) <= most {
		return text
	}
	cut := most
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}
