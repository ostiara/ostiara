// Package client is the CLI's HTTP client for the broker.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ostiara/ostiara/internal/api"
	"github.com/ostiara/ostiara/internal/wire"
)

// Client calls one broker as one user.
type Client struct {
	BaseURL string
	User    string
	Token   func(context.Context) (string, error) // nil: send no bearer token
	HTTP    *http.Client
	tls     *tls.Config // nil: trust the system's CAs
}

func New(baseURL, user string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		User:    user,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// TrustCA makes the client trust only the CA certificates in pemFile, for HTTP and WebSocket alike.
func (c *Client) TrustCA(pemFile string) error {
	data, err := os.ReadFile(pemFile)
	if err != nil {
		return fmt.Errorf("reading broker CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("no PEM certificates found in %s", pemFile)
	}
	c.tls = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = c.tls.Clone() // net/http adds h2 to its copy; the WebSocket dialer must not see it
	c.HTTP.Transport = transport
	return nil
}

func (c *Client) CreateSession(ctx context.Context, req api.CreateSessionRequest) (api.Session, error) {
	var sess api.Session
	err := c.do(ctx, http.MethodPost, "/v1/sessions", req, &sess)
	return sess, err
}

func (c *Client) GetSession(ctx context.Context, id string) (api.Session, error) {
	var sess api.Session
	err := c.do(ctx, http.MethodGet, "/v1/sessions/"+url.PathEscape(id), nil, &sess)
	return sess, err
}

// ListSessions lists sessions; an empty status lists all.
func (c *Client) ListSessions(ctx context.Context, status api.Status) ([]api.Session, error) {
	path := "/v1/sessions"
	if status != "" {
		path += "?status=" + url.QueryEscape(string(status))
	}
	var sessions []api.Session
	err := c.do(ctx, http.MethodGet, path, nil, &sessions)
	return sessions, err
}

// Decide approves (true) or denies (false) a session.
func (c *Client) Decide(ctx context.Context, id string, approve bool) (api.Session, error) {
	action := "deny"
	if approve {
		action = "approve"
	}
	var sess api.Session
	err := c.do(ctx, http.MethodPost, "/v1/sessions/"+url.PathEscape(id)+"/"+action, nil, &sess)
	return sess, err
}

// Attach opens the live WebSocket for an approved session.
func (c *Client) Attach(ctx context.Context, id string) (*wire.Conn, error) {
	ws, err := c.dialSession(ctx, id, "attach")
	if err != nil {
		return nil, err
	}
	return wire.New(ws), nil
}

// dialSession opens a WebSocket to /v1/sessions/{id}/{action} with the caller's credentials.
func (c *Client) dialSession(ctx context.Context, id, action string) (*websocket.Conn, error) {
	u, err := url.Parse(c.BaseURL + "/v1/sessions/" + url.PathEscape(id) + "/" + action)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}

	header, err := c.headers(ctx)
	if err != nil {
		return nil, err
	}

	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = c.tls.Clone()
	ws, resp, err := dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		if resp != nil {
			if msg := readError(resp.Body); msg != "" {
				return nil, errors.New(msg)
			}
		}
		return nil, fmt.Errorf("connecting to session: %w", err)
	}
	return ws, nil
}

// Forward opens one connection of an approved port-forward, as a byte stream.
func (c *Client) Forward(ctx context.Context, id string) (*wire.Raw, error) {
	ws, err := c.dialSession(ctx, id, "forward")
	if err != nil {
		return nil, err
	}
	return wire.NewRaw(ws), nil
}

// do sends one JSON request and decodes the JSON reply into out.
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	header, err := c.headers(ctx)
	if err != nil {
		return err
	}
	req.Header = header
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach the broker at %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		if msg := readError(resp.Body); msg != "" {
			return errors.New(msg)
		}
		return fmt.Errorf("broker returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// headers identifies the caller: the bearer token if there is one, plus the dev-only user header.
func (c *Client) headers(ctx context.Context) (http.Header, error) {
	header := http.Header{}
	header.Set(api.UserHeader, c.User)
	if c.Token == nil {
		return header, nil
	}
	token, err := c.Token(ctx)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return header, nil
	}
	if !safeForToken(c.BaseURL) {
		return nil, fmt.Errorf("refusing to send your Kubernetes token to %s over plain http; use https", c.BaseURL)
	}
	header.Set("Authorization", "Bearer "+token)
	return header, nil
}

// safeForToken allows https anywhere, and plain http only to this machine (e.g. kubectl port-forward).
func safeForToken(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		ip := net.ParseIP(u.Hostname())
		return u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	}
	return false
}

func readError(body io.Reader) string {
	var e api.ErrorResponse
	if json.NewDecoder(io.LimitReader(body, 64<<10)).Decode(&e) != nil {
		return ""
	}
	return e.Error
}
