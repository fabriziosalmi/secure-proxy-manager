package cli

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// client calls the management API with an API token, over TLS checked one of
// three ways: against a pinned certificate fingerprint, against the system's
// authorities, or not at all when the person asked for --insecure.
type client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// errPinMismatch is a server whose certificate is not the pinned one.
var errPinMismatch = errors.New("the server's certificate is not the one pinned")

func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func newClient(c Config, insecure bool) (*client, error) {
	if c.URL == "" {
		return nil, errors.New("no server: give --url, set SPM_URL, or run spm login")
	}
	base, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
		return nil, fmt.Errorf("the server address %q is not an http or https URL", c.URL)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case insecure:
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- the person asked for --insecure
	case c.Fingerprint != "":
		// The pin replaces the authority check: the certificate must be
		// exactly the one confirmed at spm login.
		want := strings.ToLower(strings.ReplaceAll(c.Fingerprint, ":", ""))
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- VerifyConnection checks the pinned fingerprint
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errPinMismatch
			}
			if got := fingerprintOf(cs.PeerCertificates[0]); got != want {
				return fmt.Errorf("%w (got %s, pinned %s): run spm login again if it changed on purpose", errPinMismatch, got, want)
			}
			return nil
		}
	}
	return &client{
		base:  base,
		token: c.Token,
		http: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: nil},
			// A redirect is not followed: on a 301, Go would send a POST or a
			// DELETE again as a GET, with the token, and its 200 would read
			// as the write done. do() reports it instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// response is one answer of the API.
type response struct {
	status     int
	body       []byte
	apiVersion string
}

// do sends one request. path is the API path with its query ("/api/logs?limit=5").
func (cl *client) do(method, path string, body []byte) (*response, error) {
	u := cl.base.String() + path
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return nil, err
	}
	if cl.token != "" {
		req.Header.Set("Authorization", "Bearer "+cl.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cl.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		target := resp.Header.Get("Location")
		if loc, err := resp.Location(); err == nil {
			target = loc.String()
		}
		return nil, fmt.Errorf("%s %s: the server redirected to %q (%d); nothing was sent there: give that server's address with --url",
			method, path, target, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	return &response{status: resp.StatusCode, body: b, apiVersion: resp.Header.Get("X-API-Version")}, nil
}
