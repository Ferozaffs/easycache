package client

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"easycache/internal/cache"
	"easycache/internal/discovery"
)

// newTestServer wraps an httptest server URL into a client.Server.
func newTestServer(t *testing.T, rawURL string) *Server {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	return &Server{
		Server: discovery.Server{Host: net.ParseIP(host), Port: port},
		client: http.DefaultClient,
	}
}

func TestRedactURL(t *testing.T) {
	sas := "https://acct.blob.core.windows.net/c/f.zip?sig=a1b2c3&sv=2020-08-04&se=2099-01-01"
	if got := redactURL(sas); got != "https://acct.blob.core.windows.net/c/f.zip" {
		t.Fatalf("redactURL leaked query: %s", got)
	}
	if got := redactURL("https://host/f.bin"); got != "https://host/f.bin" {
		t.Fatalf("redactURL altered plain url: %s", got)
	}
}

func TestClientCheckAndUpload(t *testing.T) {
	store, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(cache.NewHandler(store).Routes())
	defer srv.Close()
	s := newTestServer(t, srv.URL)

	dir := t.TempDir()
	fp := filepath.Join(dir, "payload.bin")
	content := bytes.Repeat([]byte("file body "), 8888)
	if err := os.WriteFile(fp, content, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Not cached yet -> nil, nil.
	full, err := FullSignature(fp)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Check(ctx, full.Sig, full.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatalf("expected miss, got %+v", res)
	}

	// Upload.
	up, err := s.Upload(ctx, fp, filepath.Base(fp))
	if err != nil {
		t.Fatal(err)
	}
	if up.Hash != full.Hash {
		t.Fatalf("upload hash %s != full %s", up.Hash, full.Hash)
	}

	// Now check by exact hash -> hit.
	res, err = s.Check(ctx, full.Sig, full.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("expected hit after upload")
	}

	// Quick partial signature also resolves (unambiguous).
	size, sig, err := QuickSignature(fp)
	if err != nil {
		t.Fatal(err)
	}
	if size != full.Size {
		t.Fatalf("quick size %d != full %d", size, full.Size)
	}
	res, err = s.Check(ctx, sig, "")
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("expected hit via partial sig")
	}
}

// TestRemoteSignature proves that sampling a remote file via HEAD + ranged GETs
// yields exactly the same partial signature as reading the whole file locally —
// the mechanism for checking a cache hit before downloading any file that lacks
// a published checksum.
func TestRemoteSignature(t *testing.T) {
	dir := t.TempDir()
	content := make([]byte, 200*1024)
	for i := range content {
		content[i] = byte(i * 31)
	}
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	fs := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer fs.Close()
	url := fs.URL + "/blob.bin"

	size, sig, err := RemoteSignature(url)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := cache.FingerprintReader(bytes.NewReader(content))
	if size != int64(len(content)) {
		t.Fatalf("size %d != %d", size, len(content))
	}
	if sig != want.Sig {
		t.Fatalf("remote sig %s != local sig %s", sig, want.Sig)
	}
}

// TestRemoteCheckAndFetch drives the whole workflow: an origin file behind a
// plain file server, a cache that stores it, then a "remote only" pass that
// samples the origin, finds a cache hit and copies from the cache.
func TestRemoteCheckAndFetch(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte("streaming payload "), 9000)
	originName := "data.bin"
	if err := os.WriteFile(filepath.Join(dir, originName), content, 0o644); err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer origin.Close()
	originURL := origin.URL + "/" + originName

	store, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cacheSrv := httptest.NewServer(cache.NewHandler(store).Routes())
	defer cacheSrv.Close()
	c := newTestServer(t, cacheSrv.URL)

	ctx := context.Background()

	// Sample the origin, upload it to the cache.
	size, sig, err := RemoteSignature(originURL)
	if err != nil {
		t.Fatal(err)
	}
	up, err := c.Upload(ctx, filepath.Join(dir, originName), originName)
	if err != nil {
		t.Fatal(err)
	}

	// Now a fresh "remote" pass: sample origin → cache says hit → fetch back.
	size2, sig2, err := RemoteSignature(originURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = size2
	res, err := c.Check(ctx, sig2, "")
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("expected cache hit from remote sampling")
	}
	if res.Hash != up.Hash {
		t.Fatalf("hit hash %s != upload hash %s", res.Hash, up.Hash)
	}
	out := filepath.Join(t.TempDir(), "fetched.bin")
	if err := c.Fetch(ctx, res.Hash, out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("fetched-from-cache bytes do not match origin")
	}

	// Sanity: the whole workflow is driven by a cheap partial signature.
	_ = sig
	_ = sig2
	if size <= 0 {
		t.Fatal("invalid size from remote")
	}
}
