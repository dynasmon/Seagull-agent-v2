// Package transport reaches the platform. It authenticates the listener it
// connects to against the authorities the agent trusts, presents the agent's
// credential wherever it sends anything, and bounds what a request may take in
// time, bytes and connections. It moves bytes and knows nothing of what they
// carry, whose records they are or where the credential it presents is kept.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	idle           = 30 * time.Second
	keepAlive      = 30 * time.Second
	maxHeaderBytes = 16 << 10
	longestAsked   = 24 * time.Hour
)

type Options struct {
	Authorities      []*x509.Certificate
	Credentials      Credentials
	ConnectTimeout   time.Duration
	RequestTimeout   time.Duration
	MaxResponseBytes int64
	MaxConnections   int
}

type Request struct {
	URL         string
	ContentType string
	Body        io.Reader
	Length      int64
	Unchanged   string
	Most        int64
	Into        io.Writer
	Within      time.Duration
}

type Reply struct {
	Status      int
	ContentType string
	Body        []byte
	Date        time.Time
	RetryAfter  time.Duration
	Tag         string
	Peer        []*x509.Certificate
}

type Peer struct {
	Version  uint16
	Subject  string
	Names    []string
	Issuer   string
	NotAfter time.Time
	Asks     bool
}

type Client struct {
	options   Options
	resolver  *net.Resolver
	current   atomic.Pointer[connections]
	presented atomic.Pointer[tls.Certificate]
}

type connections struct {
	roots     *x509.CertPool
	transport *http.Transport
}

func New(options Options) (*Client, error) { return compose(options, nil) }

func compose(options Options, resolver *net.Resolver) (*Client, error) {
	var problems []error
	roots, err := anchors(options.Authorities)
	if err != nil {
		problems = append(problems, err)
	}
	switch {
	case options.ConnectTimeout <= 0 || options.RequestTimeout <= 0:
		problems = append(problems, fmt.Errorf("a connect timeout of %s and a request timeout of %s are not both waits", options.ConnectTimeout, options.RequestTimeout))
	case options.RequestTimeout < options.ConnectTimeout:
		problems = append(problems, fmt.Errorf("a request timeout of %s is shorter than the connect timeout of %s it covers", options.RequestTimeout, options.ConnectTimeout))
	}
	if options.MaxResponseBytes < 1 {
		problems = append(problems, fmt.Errorf("a reply of at most %d bytes leaves nothing to read", options.MaxResponseBytes))
	}
	if options.MaxConnections < 1 {
		problems = append(problems, fmt.Errorf("%d connections leave nothing to send over", options.MaxConnections))
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the transport: %w", errors.Join(problems...))
	}
	client := &Client{options: options, resolver: resolver}
	client.current.Store(client.connect(roots))
	return client, nil
}

// Trust makes authorities the ones the platform is authenticated against, from
// the next connection on: a connection already made finishes what it carries,
// and none made before is used again.
func (c *Client) Trust(authorities []*x509.Certificate) error {
	roots, err := anchors(authorities)
	if err != nil {
		return fmt.Errorf("trust the authorities: %w", err)
	}
	c.current.Swap(c.connect(roots)).transport.CloseIdleConnections()
	return nil
}

func (c *Client) connect(roots *x509.CertPool) *connections {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &connections{roots: roots, transport: &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: c.options.ConnectTimeout, KeepAlive: keepAlive, Resolver: c.resolver}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion:           tls.VersionTLS13,
			RootCAs:              roots,
			GetClientCertificate: c.certificate,
		},
		TLSHandshakeTimeout:    c.options.ConnectTimeout,
		DisableCompression:     true,
		MaxIdleConns:           2 * c.options.MaxConnections,
		MaxIdleConnsPerHost:    c.options.MaxConnections,
		MaxConnsPerHost:        c.options.MaxConnections,
		IdleConnTimeout:        idle,
		MaxResponseHeaderBytes: maxHeaderBytes,
		Protocols:              protocols,
	}}
}

func anchors(authorities []*x509.Certificate) (*x509.CertPool, error) {
	if len(authorities) == 0 {
		return nil, errors.New("no authority to authenticate the platform with")
	}
	roots := x509.NewCertPool()
	for _, authority := range authorities {
		if authority == nil || !authority.BasicConstraintsValid || !authority.IsCA {
			return nil, errors.New("a trust anchor that is not a certificate authority")
		}
		roots.AddCert(authority)
	}
	return roots, nil
}

// Post and Get send a request as the enrolled agent, and return whatever the
// platform answered it with: a refusal is a reply like any other. Nothing is
// sent without a usable credential, and nothing is sent to a platform the
// agent did not authenticate. Neither follows a redirect. A request may name
// what the agent already holds, so the platform can answer that nothing
// changed, may bound its reply other than the transport does, may be given
// longer than the transport waits, and may have a successful reply written
// where the caller keeps it rather than held whole.
func (c *Client) Post(ctx context.Context, request Request) (Reply, error) {
	return c.send(ctx, http.MethodPost, request)
}

func (c *Client) Get(ctx context.Context, request Request) (Reply, error) {
	return c.send(ctx, http.MethodGet, request)
}

func (c *Client) send(ctx context.Context, method string, request Request) (Reply, error) {
	target, err := secured(request.URL)
	if err != nil {
		return Reply{}, err
	}
	if err := c.present(); err != nil {
		return Reply{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, max(c.options.RequestTimeout, request.Within))
	defer cancel()
	var connected atomic.Bool
	traced := httptrace.WithClientTrace(bounded, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }})
	sent, err := http.NewRequestWithContext(traced, method, target.String(), body(request.Body))
	if err != nil {
		return Reply{}, fmt.Errorf("send to %s: %w", target.Redacted(), err)
	}
	sent.ContentLength = request.Length
	if request.ContentType != "" {
		sent.Header.Set("Content-Type", request.ContentType)
	}
	if request.Unchanged != "" {
		sent.Header.Set("If-None-Match", request.Unchanged)
	}
	response, err := c.current.Load().transport.RoundTrip(sent)
	if err != nil {
		return Reply{}, failure(ctx, target, connected.Load(), err)
	}
	defer response.Body.Close()
	most := c.options.MaxResponseBytes
	if request.Most > 0 {
		most = request.Most
	}
	var content []byte
	if request.Into != nil && response.StatusCode == http.StatusOK {
		kept := &writing{into: request.Into}
		copied, err := io.Copy(kept, io.LimitReader(response.Body, most+1))
		switch {
		case kept.err != nil:
			return Reply{}, fmt.Errorf("%w: %v", ErrUnwritten, kept.err)
		case err != nil:
			return Reply{}, failure(ctx, target, true, err)
		case copied > most:
			return Reply{}, fmt.Errorf("%w: %s answered with more than %d bytes", ErrReplyTooLarge, target.Redacted(), most)
		}
	} else {
		content, err = io.ReadAll(io.LimitReader(response.Body, most+1))
		if err != nil {
			return Reply{}, failure(ctx, target, true, err)
		}
		if int64(len(content)) > most {
			return Reply{}, fmt.Errorf("%w: %s answered with more than %d bytes", ErrReplyTooLarge, target.Redacted(), most)
		}
	}
	var peer []*x509.Certificate
	if response.TLS != nil {
		peer = slices.Clone(response.TLS.PeerCertificates)
	}
	date, _ := http.ParseTime(response.Header.Get("Date"))
	return Reply{
		Status:      response.StatusCode,
		ContentType: response.Header.Get("Content-Type"),
		Body:        content,
		Date:        date,
		RetryAfter:  asked(response.Header.Get("Retry-After"), date),
		Tag:         response.Header.Get("ETag"),
		Peer:        peer,
	}, nil
}

// Check authenticates the listener at address without presenting anything,
// and sends nothing over the connection it closes at once: what the listener
// presented, and whether it asked for the certificate of an enrolled agent.
func (c *Client) Check(ctx context.Context, address string) (Peer, error) {
	target, err := secured(address)
	if err != nil {
		return Peer{}, err
	}
	var asked atomic.Bool
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: c.options.ConnectTimeout, Resolver: c.resolver},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    c.current.Load().roots,
			ServerName: target.Hostname(),
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				asked.Store(true)
				return &tls.Certificate{}, nil
			},
		},
	}
	bounded, cancel := context.WithTimeout(ctx, c.options.ConnectTimeout)
	defer cancel()
	connection, err := dialer.DialContext(bounded, "tcp", reachable(target))
	if err != nil {
		return Peer{}, failure(ctx, target, false, err)
	}
	defer connection.Close()
	state := connection.(*tls.Conn).ConnectionState()
	leaf := state.PeerCertificates[0]
	names := slices.Clone(leaf.DNSNames)
	for _, address := range leaf.IPAddresses {
		names = append(names, address.String())
	}
	return Peer{
		Version:  state.Version,
		Subject:  leaf.Subject.CommonName,
		Names:    names,
		Issuer:   leaf.Issuer.CommonName,
		NotAfter: leaf.NotAfter,
		Asks:     asked.Load(),
	}, nil
}

func (c *Client) Close() { c.current.Load().transport.CloseIdleConnections() }

func asked(header string, date time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if header != "" && strings.Trim(header, "0123456789") == "" {
		seconds, err := strconv.ParseInt(header, 10, 64)
		if err != nil || seconds > int64(longestAsked/time.Second) {
			return longestAsked
		}
		return time.Duration(seconds) * time.Second
	}
	at, err := http.ParseTime(header)
	if err != nil {
		return 0
	}
	if date.IsZero() {
		date = time.Now()
	}
	return min(max(at.Sub(date), 0), longestAsked)
}

func body(held io.Reader) io.ReadCloser {
	if held == nil {
		return http.NoBody
	}
	return io.NopCloser(held)
}

func secured(address string) (*url.URL, error) {
	target, err := url.Parse(address)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil {
		return nil, errors.New("the transport reaches the platform at an https address with a host and no credentials")
	}
	return target, nil
}

func reachable(target *url.URL) string {
	if target.Port() == "" {
		return net.JoinHostPort(target.Hostname(), "443")
	}
	return target.Host
}

type writing struct {
	into io.Writer
	err  error
}

func (w *writing) Write(written []byte) (int, error) {
	count, err := w.into.Write(written)
	if err != nil && w.err == nil {
		w.err = err
	}
	return count, err
}
