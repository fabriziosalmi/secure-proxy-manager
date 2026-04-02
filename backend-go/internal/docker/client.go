// Package docker provides a minimal Docker Engine API client over the Unix socket.
// It replaces the previous subprocess.run(["docker","exec",...]) calls with proper
// HTTP calls to the Docker daemon — no CGO, no docker SDK dependency.
package docker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

const dockerSock = "/var/run/docker.sock"

// DockerClient defines the interface for interacting with the Docker Engine API.
type DockerClient interface {
	KillContainer(name, signal string) error
}

// Client is a minimal Docker Engine API client.
type Client struct {
	hc *http.Client
}

var _ DockerClient = (*Client)(nil)

// New returns a Client that talks to the Docker socket.
func New() *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", dockerSock)
		},
	}
	return &Client{hc: &http.Client{Transport: transport, Timeout: 10 * time.Second}}
}

// KillContainer sends signal to a container via the Docker Engine API.
// Equivalent to: docker kill --signal=<sig> <name>
func (c *Client) KillContainer(name, signal string) error {
	url := fmt.Sprintf("http://localhost/v1.41/containers/%s/kill?signal=%s", name, signal)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("docker kill %s signal=%s: %w", name, signal, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker kill returned HTTP %d", resp.StatusCode)
	}
	return nil
}
