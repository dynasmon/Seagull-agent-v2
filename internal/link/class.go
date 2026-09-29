package link

import (
	"errors"
	"fmt"

	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
)

type Class int

const (
	Transport Class = iota + 1
	TLS
	Authorization
	Capacity
)

func (c Class) String() string {
	switch c {
	case Transport:
		return "transport"
	case TLS:
		return "tls"
	case Authorization:
		return "authorization"
	case Capacity:
		return "capacity"
	default:
		return fmt.Sprintf("class(%d)", int(c))
	}
}

// Lasting says whether a failure of the class waits on somebody to act: an
// operator, to change what the agent trusts or presents, or the platform, to
// admit the agent again. The network and a busy platform recover on their own.
func (c Class) Lasting() bool { return c == TLS || c == Authorization }

// Of says which class of failure the transport reported: the network, before
// or after the request reached the listener; a listener the agent could not
// authenticate; or a credential the agent could not present or the platform
// refused. Anything else the transport reports is no failure of the connection.
func Of(err error) (Class, bool) {
	switch {
	case errors.Is(err, transport.ErrUnreachable), errors.Is(err, transport.ErrUnanswered):
		return Transport, true
	case errors.Is(err, transport.ErrUntrusted):
		return TLS, true
	case errors.Is(err, transport.ErrRefused), errors.Is(err, transport.ErrUnauthenticated):
		return Authorization, true
	}
	return 0, false
}
