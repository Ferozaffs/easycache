package cache

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func postJSON(t *testing.T, url string, v any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(v)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func upload(t *testing.T, url string, body []byte) response {
	t.Helper()
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload status %d: %s", resp.StatusCode, b)
	}
	var r response
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestHandlerRoundTrip uploads a file, then checks both by exact hash and by
// partial signature, and downloads it back over HTTP.
func TestHandlerRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewHandler(s).Routes())
	defer srv.Close()

	content := bytes.Repeat([]byte("cache me "), 10_000)
	up := upload(t, srv.URL+"/upload", content)
	if up.Hash == "" || up.Sig == "" || up.Path == "" || up.URL == "" {
		t.Fatalf("incomplete upload response: %+v", up)
	}

	// Exact hash check -> hit.
	resp := postJSON(t, srv.URL+"/check", map[string]string{"hash": up.Hash})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hash check returned %d", resp.StatusCode)
	}
	var got response
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got.Hash != up.Hash {
		t.Fatalf("hash check mismatch")
	}

	// Partial sig check -> hit (unambiguous single candidate).
	resp = postJSON(t, srv.URL+"/check", map[string]string{"sig": up.Sig})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sig check returned %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Unknown hash -> 404 empty body (miss).
	resp = postJSON(t, srv.URL+"/check", map[string]string{"hash": "deadbeef"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown hash returned %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Ambiguous sig -> 404 (fail safe).
	head := bytes.Repeat([]byte{0x00}, MaxSample)
	tail := bytes.Repeat([]byte{0xFF}, MaxSample)
	mk := func(b int) []byte {
		mid := bytes.Repeat([]byte{byte(b)}, 50000)
		c := make([]byte, 0, len(head)+len(mid)+len(tail))
		c = append(c, head...)
		c = append(c, mid...)
		c = append(c, tail...)
		return c
	}
	upload(t, srv.URL+"/upload", mk(0x01))
	upload(t, srv.URL+"/upload", mk(0x02))
	fp, _ := FingerprintReader(bytes.NewReader(mk(0x01)))
	resp = postJSON(t, srv.URL+"/check", map[string]string{"sig": fp.Sig})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ambiguous sig returned %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// Download the file back.
	get, err := http.Get(srv.URL + "/files/" + up.Hash)
	if err != nil {
		t.Fatal(err)
	}
	gotBytes, _ := io.ReadAll(get.Body)
	get.Body.Close()
	if !bytes.Equal(gotBytes, content) {
		t.Fatalf("downloaded bytes differ (%d vs %d)", len(gotBytes), len(content))
	}
}

func TestHandlerCheckRequiresSigOrHash(t *testing.T) {
	s, _ := Open(t.TempDir())
	srv := httptest.NewServer(NewHandler(s).Routes())
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/check", map[string]string{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty check returned %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}
