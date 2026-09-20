package secrets_test

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

// What one message may carry of what the agent read, and what quoting the
// least printable of it can cost: four characters a byte, its quotes and the
// mark that says the text goes on.
const (
	maxShownBytes   = 96
	maxMessageBytes = 4*maxShownBytes + 2 + 3
)

func TestAMessageCarriesTheTextItWasGivenUntilItsBound(t *testing.T) {
	for name, held := range map[string]struct {
		given   string
		bounded string
		shown   string
	}{
		"text a message carries whole": {given: "identity.state_directory", bounded: "identity.state_directory", shown: `"identity.state_directory"`},
		"nothing at all":               {given: "", bounded: "", shown: `""`},
		"text as long as the bound":    {given: strings.Repeat("a", 96), bounded: strings.Repeat("a", 96), shown: `"` + strings.Repeat("a", 96) + `"`},
		"text longer than the bound": {
			given:   strings.Repeat("a", 97),
			bounded: strings.Repeat("a", 96) + "...",
			shown:   `"` + strings.Repeat("a", 96) + `"...`,
		},
		"text a rune wider than the bound": {
			given:   strings.Repeat("a", 95) + "é",
			bounded: strings.Repeat("a", 95) + "...",
			shown:   `"` + strings.Repeat("a", 95) + `"...`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if bounded := secrets.Bounded(held.given); bounded != held.bounded {
				t.Errorf("Bounded(%d bytes) = %q, want %q", len(held.given), bounded, held.bounded)
			}
			if shown := secrets.Shown(held.given); shown != held.shown {
				t.Errorf("Shown(%d bytes) = %q, want %q", len(held.given), shown, held.shown)
			}
		})
	}
}

func TestWhatIsNotPrintableIsEscapedRatherThanWrittenIntoALog(t *testing.T) {
	for name, given := range map[string]string{
		"a line of its own":      "refused\nagent_starting",
		"a terminal's own word":  "refused\x1b[2Kagent_starting",
		"bytes that are no text": "refused\xff\xfe",
		"a byte within a rune":   "refused\xc3",
	} {
		t.Run(name, func(t *testing.T) {
			for shown, held := range map[string]string{"Bounded": secrets.Bounded(given), "Shown": secrets.Shown(given)} {
				if strings.ContainsFunc(held, func(held rune) bool { return !unicode.IsPrint(held) }) {
					t.Errorf("%s(%q) = %q, which a log carries as it is", shown, given, held)
				}
				if !strings.Contains(held, "refused") {
					t.Errorf("%s(%q) = %q, which says nothing of what it was given", shown, given, held)
				}
			}
		})
	}
}

func TestAnAddressAMessageNamesCarriesNoCredentials(t *testing.T) {
	const password = "s3cr3t-token"
	for name, held := range map[string]struct{ given, want string }{
		"an address with nothing to hide": {
			given: "https://gateway.example:8443/v1",
			want:  `"https://gateway.example:8443/v1"`,
		},
		"an address carrying a user and a password": {
			given: "https://agent:" + password + "@gateway.example:8443/v1",
			want:  `"https://(redacted)@gateway.example:8443/v1"`,
		},
		"an address carrying a user alone": {
			given: "https://" + password + "@gateway.example:8443",
			want:  `"https://(redacted)@gateway.example:8443"`,
		},
		"an address the agent could not parse": {
			given: "ht tp://agent:" + password + "@gateway.example:8443",
			want:  `"ht tp://(redacted)@gateway.example:8443"`,
		},
		"a port that is no port": {
			given: "https://agent:" + password + "@gateway.example:99999999999999999999/v1",
			want:  `"https://(redacted)@gateway.example:99999999999999999999/v1"`,
		},
		"an at sign in the path rather than an account": {
			given: "https://gateway.example:8443/v1/@events",
			want:  `"https://gateway.example:8443/v1/@events"`,
		},
		"an at sign in a query rather than an account": {
			given: "https://gateway.example:8443/v1?from=agent@host",
			want:  `"https://gateway.example:8443/v1?from=agent@host"`,
		},
		"text that names no listener at all": {
			given: "gateway.example:8443",
			want:  `"gateway.example:8443"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			address := secrets.Address(held.given)
			if address != held.want {
				t.Errorf("Address(%q) = %s, want %s", held.given, address, held.want)
			}
			if strings.Contains(address, password) {
				t.Errorf("Address(%q) = %s, which carries the password it was given", held.given, address)
			}
		})
	}
}

func TestALongCredentialIsRemovedBeforeAMessageIsCutToItsBound(t *testing.T) {
	address := secrets.Address("https://agent:" + strings.Repeat("s3cr3t", 200) + "@gateway.example:8443/v1")
	if address != `"https://(redacted)@gateway.example:8443/v1"` {
		t.Fatalf("an address with a long password reads as %s", address)
	}
}

func FuzzNothingTheAgentReadsDecidesHowLongAMessageIs(f *testing.F) {
	f.Add("https://agent:s3cr3t@gateway.example:8443/v1")
	f.Add("modules.authentication")
	f.Add(strings.Repeat("secret", 4096))
	f.Add("//@")
	f.Add("\x00\xff\x1b[2K")
	f.Add(strings.Repeat("é", 64))
	f.Fuzz(func(t *testing.T, given string) {
		for shown, held := range map[string]string{
			"Bounded": secrets.Bounded(given),
			"Shown":   secrets.Shown(given),
			"Address": secrets.Address(given),
		} {
			if len(held) > maxMessageBytes {
				t.Errorf("%s(%d bytes) is %d bytes long, and a message carries at most %d", shown, len(given), len(held), maxMessageBytes)
			}
			if !utf8.ValidString(held) || strings.ContainsFunc(held, func(held rune) bool { return !unicode.IsPrint(held) }) {
				t.Errorf("%s(%q) = %q, which a log carries as it is", shown, given, held)
			}
		}
	})
}
