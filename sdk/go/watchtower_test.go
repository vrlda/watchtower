package watchtower

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCapturePostsExpectedPayload(t *testing.T) {
	var gotBody body
	var gotAuth string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{
		Endpoint:    srv.URL,
		Token:       "tok",
		HostID:      "h-1",
		Service:     "api",
		Environment: "prod",
	}
	ok := c.Capture("error", "ValueError", "bad input", []Frame{{File: "app.go", Line: 42, Function: "validate"}})
	if !ok {
		t.Fatal("capture returned false")
	}
	if gotPath != "/v1/errors" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotBody.HostID != "h-1" || gotBody.Service != "api" {
		t.Fatalf("body host/service = %q/%q", gotBody.HostID, gotBody.Service)
	}
	if gotBody.Exception.Type != "ValueError" || gotBody.Exception.Frames[0].Line != 42 {
		t.Fatalf("exception = %+v", gotBody.Exception)
	}
}

func TestNoConfigReturnsFalse(t *testing.T) {
	c := &Client{}
	if c.Capture("error", "T", "m", nil) {
		t.Fatal("no-config capture returned true")
	}
}
