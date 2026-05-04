// Package docker provides a minimal Docker Engine API client over the Unix socket.
// It replaces the previous subprocess.run(["docker","exec",...]) calls with proper
// HTTP calls to the Docker daemon — no CGO, no docker SDK dependency.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const dockerSock = "/var/run/docker.sock"

// DockerClient defines the interface for interacting with the Docker Engine API.
type DockerClient interface {
	KillContainer(name, signal string) error
	RestartContainer(name string) error
	ExecContainer(name string, cmd []string) (string, error)
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
	u := fmt.Sprintf("http://localhost/v1.41/containers/%s/kill?signal=%s",
		url.PathEscape(name), url.QueryEscape(signal))
	req, err := http.NewRequest(http.MethodPost, u, nil)
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

// RestartContainer restarts a container via the Docker Engine API.
// Equivalent to: docker restart <name>
func (c *Client) RestartContainer(name string) error {
	u := fmt.Sprintf("http://localhost/v1.41/containers/%s/restart", url.PathEscape(name))
	req, err := http.NewRequest(http.MethodPost, u, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("docker restart %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker restart returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// ExecContainer runs a command inside a container and returns stdout.
// Equivalent to: docker exec <name> <cmd...>
func (c *Client) ExecContainer(name string, cmd []string) (string, error) {
	// Step 1: Create exec instance
	createBody, _ := json.Marshal(map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          cmd,
	})
	createURL := fmt.Sprintf("http://localhost/v1.41/containers/%s/exec", url.PathEscape(name))
	createReq, err := http.NewRequest(http.MethodPost, createURL, bytes.NewReader(createBody))
	if err != nil {
		return "", fmt.Errorf("build exec create request: %w", err)
	}
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := c.hc.Do(createReq)
	if err != nil {
		return "", fmt.Errorf("docker exec create: %w", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("docker exec create returned HTTP %d", createResp.StatusCode)
	}
	var execResult struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&execResult); err != nil {
		return "", fmt.Errorf("decode exec ID: %w", err)
	}

	// Step 2: Start exec and capture output
	startBody, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	startURL := fmt.Sprintf("http://localhost/v1.41/exec/%s/start", execResult.ID)
	startReq, err := http.NewRequest(http.MethodPost, startURL, bytes.NewReader(startBody))
	if err != nil {
		return "", fmt.Errorf("build exec start request: %w", err)
	}
	startReq.Header.Set("Content-Type", "application/json")
	startResp, err := c.hc.Do(startReq)
	if err != nil {
		return "", fmt.Errorf("docker exec start: %w", err)
	}
	defer startResp.Body.Close()
	// Docker multiplexes stdout/stderr with 8-byte headers in non-TTY mode.
	// Read raw and strip control bytes — good enough for text output.
	out, err := io.ReadAll(io.LimitReader(startResp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("read exec output: %w", err)
	}
	return stripDockerMux(out), nil
}

// stripDockerMux removes Docker stream multiplexing headers from exec output.
// Each frame: [type(1) 0 0 0 size(4)] payload. We extract payloads.
func stripDockerMux(raw []byte) string {
	var buf bytes.Buffer
	for len(raw) >= 8 {
		size := int(raw[4])<<24 | int(raw[5])<<16 | int(raw[6])<<8 | int(raw[7])
		raw = raw[8:]
		if size > len(raw) {
			size = len(raw)
		}
		buf.Write(raw[:size])
		raw = raw[size:]
	}
	if buf.Len() == 0 {
		return string(raw) // fallback: no mux headers (TTY mode)
	}
	return buf.String()
}
