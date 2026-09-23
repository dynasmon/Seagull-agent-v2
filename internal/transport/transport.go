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
	"net/url"
	"slices"
	"sync/atomic"
	"time"
)

const (
	idle           = 30 * time.Second
	keepAlive      = 30 * time.Second
	maxHeaderBytes = 16 << 10
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
}

type Reply struct {
	Status      int
	ContentType string
	Body        []byte
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
	roots     *x509.CertPool
	transport *http.Transport
	presented atomic.Pointer[tls.Certificate]
}

func New(options Options) (*Client, error) {
	var problems []error
	if len(options.Authorities) == 0 {
		problems = append(problems, errors.New("no authority to authenticate the platform with"))
	}
	for _, authority := range options.Authorities {
		if authority == nil || !authority.BasicConstraintsValid || !authority.IsCA {
			problems = append(problems, errors.New("a trust anchor that is not a certificate authority"))
			break
		}
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
	client := &Client{options: options, roots: x509.NewCertPool()}
	for _, authority := range options.Authorities {
		client.roots.AddCert(authority)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	client.transport = &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: options.ConnectTimeout, KeepAlive: keepAlive}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion:           tls.VersionTLS13,
			RootCAs:              client.roots,
			GetClientCertificate: client.certificate,
		},
		TLSHandshakeTimeout:    options.ConnectTimeout,
		DisableCompression:     true,
		MaxIdleConns:           2 * options.MaxConnections,
		MaxIdleConnsPerHost:    options.MaxConnections,
		MaxConnsPerHost:        options.MaxConnections,
		IdleConnTimeout:        idle,
		MaxResponseHeaderBytes: maxHeaderBytes,
		Protocols:              protocols,
	}
	return client, nil
}

// Post sends a request as the enrolled agent, and returns whatever the
// platform answered it with: a refusal is a reply like any other. Nothing is
// sent without a usable credential, and nothing is sent to a platform the
// agent did not authenticate. Post never follows a redirect.
func (c *Client) Post(ctx context.Context, request Request) (Reply, error) {
	target, err := secured(request.URL)
	if err != nil {
		return Reply{}, err
	}
	if err := c.present(); err != nil {
		return Reply{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, c.options.RequestTimeout)
	defer cancel()
	sent, err := http.NewRequestWithContext(bounded, http.MethodPost, target.String(), body(request.Body))
	if err != nil {
		return Reply{}, fmt.Errorf("send to %s: %w", target.Redacted(), err)
	}
	sent.ContentLength = request.Length
	sent.Header.Set("Content-Type", request.ContentType)
	response, err := c.transport.RoundTrip(sent)
	if err != nil {
		return Reply{}, failure(ctx, target, err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, c.options.MaxResponseBytes+1))
	if err != nil {
		return Reply{}, failure(ctx, target, err)
	}
	if int64(len(content)) > c.options.MaxResponseBytes {
		return Reply{}, fmt.Errorf("%w: %s answered with more than %d bytes", ErrReplyTooLarge, target.Redacted(), c.options.MaxResponseBytes)
	}
	return Reply{Status: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: content}, nil
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
		NetDialer: &net.Dialer{Timeout: c.options.ConnectTimeout},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    c.roots,
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
		return Peer{}, failure(ctx, target, err)
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

func (c *Client) Close() { c.transport.CloseIdleConnections() }

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
