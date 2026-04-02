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

			err := client.KillContainer("test-container", "HUP")
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

func TestNew(t *testing.T) {
	c := New()
	if c == nil || c.hc == nil {
		t.Fatal("New() returned nil client or http client")
	}
	if c.hc.Timeout != 10*time.Second {
		t.Errorf("Expected 10s timeout, got %v", c.hc.Timeout)
	}
}
