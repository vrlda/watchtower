// Package watchtower is a minimal exception-capture SDK: apps report
// exceptions to a watchtower server, which fingerprints and groups them
// into incidents.
//
// Env: WATCHTOWER_ENDPOINT (required), WATCHTOWER_TOKEN (required),
// WATCHTOWER_HOST_ID, WATCHTOWER_SERVICE, WATCHTOWER_ENVIRONMENT.
package watchtower

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

// Frame is one stack frame (innermost first).
type Frame struct {
	File     string `json:"file"`
	Line     uint32 `json:"line"`
	Function string `json:"function"`
}

// Client reports exceptions to the watchtower server.
type Client struct {
	Endpoint    string
	Token       string
	HostID      string
	Service     string
	Environment string
}

// New builds a client from env vars (HostID defaults to the OS hostname,
// Service to "app", Environment to "prod").
func New() *Client {
	host, _ := os.Hostname()
	return &Client{
		Endpoint:    strings.TrimRight(os.Getenv("WATCHTOWER_ENDPOINT"), "/"),
		Token:       os.Getenv("WATCHTOWER_TOKEN"),
		HostID:      envOr("WATCHTOWER_HOST_ID", host),
		Service:     envOr("WATCHTOWER_SERVICE", "app"),
		Environment: envOr("WATCHTOWER_ENVIRONMENT", "prod"),
	}
}

func envOr(name, dflt string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return dflt
}

type exceptionPayload struct {
	Type    string  `json:"type"`
	Message string  `json:"message"`
	Level   string  `json:"level"`
	Frames  []Frame `json:"frames"`
}

type body struct {
	HostID      string           `json:"host_id"`
	Service     string           `json:"service"`
	Environment string           `json:"environment"`
	Exception   exceptionPayload `json:"exception"`
}

// Capture reports an exception. Best-effort with one retry; never panics.
func (c *Client) Capture(level, kind, message string, frames []Frame) bool {
	if c.Endpoint == "" || c.Token == "" {
		return false
	}
	payload, err := json.Marshal(body{
		HostID:      c.HostID,
		Service:     c.Service,
		Environment: c.Environment,
		Exception: exceptionPayload{
			Type:    kind,
			Message: message,
			Level:   level,
			Frames:  frames,
		},
	})
	if err != nil {
		return false
	}
	url := c.Endpoint + "/v1/errors"
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.Token)
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return true
			}
		}
		if attempt == 0 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return false
}
