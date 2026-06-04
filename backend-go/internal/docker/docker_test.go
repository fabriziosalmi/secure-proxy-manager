package docker

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type mockRoundTripper struct {
	roundTrip func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

func TestClient_KillContainer(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		respBody   string
		wantErr    bool
	}{
		{
			name:       "success 204",
			statusCode: http.StatusNoContent,
			wantErr:    false,
		},
		{
			name:       "success 200",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "error 404",
			statusCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "error 500",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mrt := &mockRoundTripper{
				roundTrip: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: tt.statusCode,
						Body:       io.NopCloser(strings.NewReader(tt.respBody)),
						Header:     make(http.Header),
					}, nil
				},
			}
			client := &Client{
				hc: &http.Client{Transport: mrt},
			}

			err := client.KillContainer("secure-proxy-manager-proxy", "HUP")
			if (err != nil) != tt.wantErr {
				t.Errorf("KillContainer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_KillContainer_RequestError(t *testing.T) {
	mrt := &mockRoundTripper{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("network error")
		},
	}
	client := &Client{
		hc: &http.Client{Transport: mrt},
	}

	err := client.KillContainer("test-container", "HUP")
	if err == nil {
		t.Error("Expected error from network failure, got nil")
	}
}

// failingTransport must never be reached when the allowlist rejects a call.
type failingTransport struct{ t *testing.T }

func (f *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Fatal("allowlist should have rejected the call before any HTTP request")
	return nil, nil
}

func TestClient_Allowlist(t *testing.T) {
	client := &Client{hc: &http.Client{Transport: &failingTransport{t}}}

	if err := client.KillContainer("evil-container", "HUP"); err == nil {
		t.Error("KillContainer: expected rejection of non-allowlisted container")
	}
	if err := client.KillContainer("secure-proxy-manager-dns-1", "KILL"); err == nil {
		t.Error("KillContainer: expected rejection of non-allowlisted signal")
	}
	if err := client.RestartContainer("evil-container"); err == nil {
		t.Error("RestartContainer: expected rejection of non-allowlisted container")
	}
	if _, err := client.ExecContainer("secure-proxy-manager-proxy", []string{"sh", "-c", "rm -rf /"}); err == nil {
		t.Error("ExecContainer: expected rejection of non-allowlisted command")
	}
	if _, err := client.ExecContainer("evil-container", []string{"squid", "-k", "purge"}); err == nil {
		t.Error("ExecContainer: expected rejection of non-allowlisted container")
	}
}

func TestNew(t *testing.T) {
	c := New()
	if c == nil || c.hc == nil {
		t.Fatal("New() returned nil client or http client")
	}
	if c.hc.Timeout != 10*time.Second {
		t.Errorf("Expected 10s timeout, got %v", c.hc.Timeout)
	}
}
