package authentication

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"
)

const (
	ed25519   = "ED25519 SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM"
	authority = "ED25519 SHA256:XKVfz0pcL1Qx9TzYd0bR3eQ3aYbTn9u2b1cJv1Q7x2E"
)

func TestTheOutcomesSshdWritesAreRead(t *testing.T) {
	for _, line := range []struct {
		message string
		want    attempt
	}{
		{
			message: "Accepted publickey for nathan from 192.0.2.7 port 65196 ssh2: " + ed25519,
			want:    attempt{accepted: true, method: "publickey", placed: true, user: "nathan", address: netip.MustParseAddr("192.0.2.7"), port: 65196},
		},
		{
			message: "Failed password for root from 203.0.113.10 port 54321 ssh2",
			want:    attempt{method: "password", placed: true, user: "root", address: netip.MustParseAddr("203.0.113.10"), port: 54321},
		},
		{
			message: "Failed password for invalid user admin from 203.0.113.10 port 54322 ssh2",
			want:    attempt{method: "password", invalid: true, placed: true, user: "admin", address: netip.MustParseAddr("203.0.113.10"), port: 54322},
		},
		{
			message: "Accepted keyboard-interactive/pam for nathan from 2001:db8::7 port 22 ssh2",
			want:    attempt{accepted: true, method: "keyboard-interactive/pam", placed: true, user: "nathan", address: netip.MustParseAddr("2001:db8::7"), port: 22},
		},
		{
			message: "Failed none for invalid user  from 203.0.113.10 port 1 ssh2",
			want:    attempt{method: "none", invalid: true, placed: true, address: netip.MustParseAddr("203.0.113.10"), port: 1},
		},
		{
			message: "Failed publickey for invalid user git from 203.0.113.10 port 4444 ssh2: RSA SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM, signature count = 3",
			want:    attempt{method: "publickey", invalid: true, placed: true, user: "git", address: netip.MustParseAddr("203.0.113.10"), port: 4444},
		},
		{
			message: "Accepted publickey for deploy from 198.51.100.4 port 40000 ssh2: ED25519-CERT SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM ID deploy@ci (serial 7) CA " + authority,
			want:    attempt{accepted: true, method: "publickey", placed: true, user: "deploy", address: netip.MustParseAddr("198.51.100.4"), port: 40000},
		},
		{
			message: `Failed hostbased for root from 198.51.100.4 port 40001 ssh2: ` + ed25519 + `, client user "root", client host "builder"`,
			want:    attempt{method: "hostbased", placed: true, user: "root", address: netip.MustParseAddr("198.51.100.4"), port: 40001},
		},
		{
			message: "Accepted gssapi-with-mic for nathan from 198.51.100.4 port 40002 ssh2: nathan@EXAMPLE.ORG",
			want:    attempt{accepted: true, method: "gssapi-with-mic", placed: true, user: "nathan", address: netip.MustParseAddr("198.51.100.4"), port: 40002},
		},
		{
			message: "Failed password for root from fe80::1%eth0 port 2222 ssh2",
			want:    attempt{method: "password", placed: true, user: "root", address: netip.MustParseAddr("fe80::1%eth0"), port: 2222},
		},
		{
			message: "Failed password for root from UNKNOWN port 65535 ssh2",
			want:    attempt{method: "password", placed: true, user: "root", port: 65535},
		},
	} {
		got, ok := parse(line.message)
		if !ok || got != line.want {
			t.Errorf("%q was read as %+v, %t, want %+v", line.message, got, ok, line.want)
		}
	}
}

// A user that does not exist is what the client sent, and so is the identifier
// of a certificate it presents: either can hold what looks like a place, and
// the place read is never one of them.
func TestAPlaceTheClientWroteIsNeverTheOneRead(t *testing.T) {
	forged := " from 10.0.0.1 port 22 ssh2"
	for _, line := range []struct {
		message string
		placed  bool
		user    string
	}{
		{message: "Failed password for invalid user x" + forged + ": " + ed25519 + " from 203.0.113.10 port 4444 ssh2", placed: true, user: "x" + forged + ": " + ed25519},
		{message: "Failed password for invalid user x" + forged + " from 203.0.113.10 port 4444 ssh2", placed: true, user: "x" + forged},
		{message: "Failed publickey for invalid user x" + forged + ": " + ed25519 + " from 203.0.113.10 port 4444 ssh2: " + ed25519, placed: true, user: "x" + forged + ": " + ed25519},
		{message: "Failed publickey for invalid user x from 203.0.113.10 port 4444 ssh2: ED25519-CERT SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM ID y" + forged + ": " + ed25519 + " (serial 1) CA " + authority, placed: true, user: "x"},
		{message: "Failed publickey for invalid user x from 203.0.113.10 port 4444 ssh2: ED25519-CERT SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM ID y" + forged + ": ED25519-CERT SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM ID z (serial 1) CA " + authority + " (serial 1) CA " + authority},
		{message: "Failed publickey for invalid user x" + forged + ": ED25519-CERT SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM ID z (serial 1) CA " + authority + " from 203.0.113.10 port 4444 ssh2: ED25519-CERT SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM ID w (serial 2) CA " + authority},
		{message: `Failed gssapi-with-mic for invalid user x` + forged + `: y from 203.0.113.10 port 4444 ssh2: z`},
		{message: "Failed keyboard-interactive/pam for invalid user " + strings.Repeat(`\001`, 100) + " from 2001:db8:1234:5678:9abc:def0:1234:5678 port 6"},
	} {
		got, ok := parse(line.message)
		if !ok || got.accepted || !got.invalid {
			t.Errorf("%q was read as %+v, %t, and it is a failure of a user that does not exist", line.message, got, ok)
			continue
		}
		if line.placed && (!got.placed || got.user != line.user || got.address != netip.MustParseAddr("203.0.113.10") || got.port != 4444) {
			t.Errorf("%q was read as %+v, and only the place sshd wrote fits it", line.message, got)
		}
		if !line.placed && (got.placed || got.user != "" || got.address.IsValid() || got.port != 0) {
			t.Errorf("%q was read as %+v, and more than one place fits it, or none", line.message, got)
		}
	}
}

func TestWhatSshdWritesBesideAnOutcomeIsNotOne(t *testing.T) {
	for _, message := range []string{
		"Invalid user admin from 203.0.113.10 port 54322",
		"Postponed publickey for nathan from 192.0.2.7 port 65196 ssh2 [preauth]",
		"Partial publickey for nathan from 192.0.2.7 port 65196 ssh2: " + ed25519,
		`Accepted certificate ID "deploy@ci" (serial 7) signed by ED25519 CA SHA256:XKVfz0pcL1Qx9TzYd0bR3eQ3aYbTn9u2b1cJv1Q7x2E via /etc/ssh/ca.pub`,
		"Accepted key ED25519 SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM found at /home/nathan/.ssh/authorized_keys:1",
		"Accepted ED25519 public key SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM from root@builder",
		"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10  user=root",
		"pam_unix(sshd:session): session opened for user nathan(uid=1000) by nathan(uid=0)",
		"error: maximum authentication attempts exceeded for root from 203.0.113.10 port 54321 ssh2 [preauth]",
		"Failed to allocate internet-domain X11 display socket.",
		"Failed magic for root from 203.0.113.10 port 54321 ssh2",
		"Failed password/pam for root from 203.0.113.10 port 54321 ssh2",
		"Failed keyboard-interactive/PAM for root from 203.0.113.10 port 54321 ssh2",
		"Accepted password for invalid user root from 203.0.113.10 port 54321 ssh2",
		"Failed password for root from 203.0.113.10 port 54321 ssh2\n",
		"Failed password for r\x00ot from 203.0.113.10 port 54321 ssh2",
		"Failed password for r\xc3\xa9ot from 203.0.113.10 port 54321 ssh2",
		"Failed password for " + strings.Repeat("a", maxMessage) + " from 203.0.113.10 port 54321 ssh2",
		"Server listening on 0.0.0.0 port 22.",
		"",
	} {
		if got, ok := parse(message); ok {
			t.Errorf("%q was read as an outcome, %+v", message, got)
		}
	}
}

func TestWhatDoesNotFitAPlaceLeavesTheOutcome(t *testing.T) {
	for _, message := range []string{
		"Failed password for root from 203.0.113.10 port 65536 ssh2",
		"Failed password for root from 203.0.113.10 port -1 ssh2",
		"Failed password for root from 203.0.113.10 port 22 ssh1",
		"Failed password for root from 203.0.113.10 port 22 ssh2: " + ed25519,
		"Failed password for root from 203.0.113.10 port 22 ssh2 [preauth]",
		"Failed password for root from  port 22 ssh2",
		"Failed publickey for root from 203.0.113.10 port 22 ssh2: RSA SHA256:short",
		"Failed publickey for root from 203.0.113.10 port 22 ssh2: ",
		"Failed password for root",
	} {
		got, ok := parse(message)
		if !ok || got.placed || got.user != "" || got.address.IsValid() || got.port != 0 || got.method == "" {
			t.Errorf("%q was read as %+v, %t, and it is a failure sshd placed nowhere this reads", message, got, ok)
		}
	}
	long := strings.Repeat("a", maxUser+40)
	got, ok := parse("Failed password for invalid user " + long + " from 203.0.113.10 port 22 ssh2")
	if !ok || !got.placed || got.user != long[:maxUser] {
		t.Errorf("a long user was read as %+v, %t", got, ok)
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"Accepted publickey for nathan from 192.0.2.7 port 65196 ssh2: " + ed25519,
		"Failed password for invalid user admin from 203.0.113.10 port 54322 ssh2",
		"Failed keyboard-interactive/pam for root from 2001:db8::7 port 22 ssh2",
		"Failed publickey for invalid user x from 203.0.113.10 port 4444 ssh2: ED25519-CERT SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM ID y (serial 1) CA " + authority,
		"Failed none for invalid user  from 203.0.113.10 port 1 ssh2",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, message string) {
		got, ok := parse(message)
		if !ok {
			if got != (attempt{}) {
				t.Fatalf("%q is not an outcome and was read as %+v", message, got)
			}
			return
		}
		if !strings.HasPrefix(message, "Accepted "+got.method+" for ") && !strings.HasPrefix(message, "Failed "+got.method+" for ") {
			t.Fatalf("%q was read as an outcome by %s", message, got.method)
		}
		if !got.placed {
			if got.user != "" || got.address.IsValid() || got.port != 0 {
				t.Fatalf("%q placed nowhere was read as %+v", message, got)
			}
			return
		}
		if len(got.user) > maxUser || !utf8.ValidString(got.user) || got.port > 65535 {
			t.Fatalf("%q was read as %+v, beyond what the contract holds", message, got)
		}
		said := fmt.Sprintf(" from %s port %d ssh2", got.address, got.port)
		if got.address.IsValid() && !strings.Contains(message, said) && !strings.Contains(message, fmt.Sprintf(" port %d ssh2", got.port)) {
			t.Fatalf("%q was placed at %s", message, said)
		}
	})
}
