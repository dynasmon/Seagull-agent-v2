package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"slices"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

var (
	ErrUntrusted       = errors.New("the platform could not be authenticated")
	ErrUnauthenticated = errors.New("the agent holds no credential it can authenticate with")
	ErrRefused         = errors.New("the platform refused the agent's credential")
	ErrUnreachable     = errors.New("the platform could not be reached")
	ErrUnanswered      = errors.New("the platform took the request and did not answer it")
	ErrReplyTooLarge   = errors.New("the platform's reply is larger than the agent reads")
)

// What the platform aborts a handshake with when it does not accept the
// certificate the agent presented, by their codes in RFC 8446: a bad,
// unsupported, revoked, expired or unknown certificate, an unknown authority,
// access denied, and no certificate at all.
var refusals = []uint8{42, 43, 44, 45, 46, 48, 49, 116}

// A caller that stopped is told so, and never that the platform failed. The
// rest says whose failure it was: the platform's certificate, the agent's, or
// the network between them, before the request reached the listener or after.
func failure(ctx context.Context, target *url.URL, connected bool, err error) error {
	if stopped := ctx.Err(); stopped != nil {
		return stopped
	}
	var unverified *tls.CertificateVerificationError
	if errors.As(err, &unverified) {
		return fmt.Errorf("%w: %s: %s", ErrUntrusted, target.Redacted(), secrets.Bounded(unverified.Err.Error()))
	}
	if code, text, ok := alert(err); ok {
		if slices.Contains(refusals, code) {
			return fmt.Errorf("%w: %s answered %s", ErrRefused, target.Redacted(), text)
		}
		return fmt.Errorf("%w: %s answered %s", ErrUntrusted, target.Redacted(), text)
	}
	if connected {
		return fmt.Errorf("%w: %s: %s", ErrUnanswered, target.Redacted(), secrets.Bounded(err.Error()))
	}
	return fmt.Errorf("%w: %s: %s", ErrUnreachable, target.Redacted(), secrets.Bounded(err.Error()))
}

func alert(err error) (uint8, string, bool) {
	var remote *net.OpError
	if !errors.As(err, &remote) || remote.Op != "remote error" || remote.Err == nil {
		return 0, "", false
	}
	value := reflect.ValueOf(remote.Err)
	if value.Kind() != reflect.Uint8 || value.Type().PkgPath() != "crypto/tls" {
		return 0, "", false
	}
	return uint8(value.Uint()), remote.Err.Error(), true
}
