package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"easycache/internal/cache"
	"easycache/internal/discovery"
)

// Server is a discovered cache instance with a friendly client API.
type Server struct {
	discovery.Server
	client *http.Client
}

// Result mirrors the server's cache entry response.
type Result struct {
	Sig  string `json:"sig"`
	Hash string `json:"hash"`
	Size int64  `json:"size"`
	Name string `json:"name,omitempty"`
	Path string `json:"path"`
	URL  string `json:"url"`
}

// Discover finds cache servers on the local network within timeout.
func Discover(ctx context.Context, timeout time.Duration) ([]Server, error) {
	found, err := discovery.Lookup(ctx, timeout)
	if err != nil {
		return nil, err
	}
	out := make([]Server, 0, len(found))
	for _, s := range found {
		out = append(out, Server{Server: s, client: &http.Client{Timeout: 30 * time.Second}})
	}
	return out, nil
}

// NewServer builds a client for an explicitly addressed cache server, bypassing
// zero-config discovery. Useful when mDNS is unavailable or outside the LAN.
func NewServer(host string, port int) Server {
	return Server{
		Server: discovery.Server{
			Instance: net.JoinHostPort(host, strconv.Itoa(port)),
			Host:     net.ParseIP(host),
			Port:     port,
		},
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// QuickSignature computes just the cheap partial signature for a local file by
// reading only the head and tail sample, never the whole file. This is the fast
// path for deciding whether to bother uploading.
func QuickSignature(path string) (size int64, sig string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	size = info.Size()

	first := make([]byte, cache.MaxSample)
	last := make([]byte, cache.MaxSample)
	_, _ = io.ReadFull(f, first)

	tailOff := size - cache.MaxSample
	if tailOff > 0 {
		if _, err := f.ReadAt(last, tailOff); err != nil && err != io.EOF {
			return 0, "", err
		}
		last = last[:cache.MaxSample]
	} else {
		// Whole file fits in one sample: tail == head.
		last = first[:size]
		first = first[:size]
	}
	return size, cache.Signature(size, first, last), nil
}

// FullSignature computes the exact full-content SHA-256 and the partial
// signature by reading the whole file once. Use this for authoritative checks
// and uploads.
func FullSignature(path string) (cache.Fingerprint, error) {
	f, err := os.Open(path)
	if err != nil {
		return cache.Fingerprint{}, err
	}
	defer f.Close()
	return cache.FingerprintReader(f)
}

// Check asks the server whether an entry matching the signature (pre-filter) or
// the exact hash (authoritative) is cached. It returns (nil, nil) when the
// entry is not cached, and (nil, err) on transport or protocol failure.
func (s Server) Check(ctx context.Context, sig, hash string) (*Result, error) {
	body, _ := json.Marshal(map[string]string{"sig": sig, "hash": hash})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL()+"/check", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, nil // not cached
	case http.StatusOK:
		var r Result
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			return nil, err
		}
		return &r, nil
	default:
		return nil, fmt.Errorf("check: unexpected status %d", resp.StatusCode)
	}
}

// Upload streams a file to the cache and returns the resulting entry.
func (s Server) Upload(ctx context.Context, path, name string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL()+"/upload", f)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Filename", name)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("upload: status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	var r Result
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Fetch copies a cached blob to a local file. It returns an error if the hash
// is not cached. Use it to grab a file from the cache instead of re-downloading.
func (s Server) Fetch(ctx context.Context, hash, out string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL()+"/files/"+hash, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("not cached: %s", hash)
	case http.StatusOK:
		// continue
	default:
		return fmt.Errorf("fetch: status %d", resp.StatusCode)
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

// RemoteSignature computes the cache's partial signature for a remote file by
// reading only a HEAD (for the size) and two small ranged GETs (the head and
// tail 64KB). It never downloads the whole body, so it works for any file that
// has no published checksum but is served behind HTTP range support (most CDNs
// and static file servers). The signature is the same one the cache uses, so a
// hit here is a hit in the cache.
func RemoteSignature(rawURL string) (size int64, sig string, err error) {
	c := &http.Client{Timeout: 30 * time.Second}

	head, err := c.Head(rawURL)
	if err != nil {
		return 0, "", err
	}
	head.Body.Close()
	if head.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("HEAD %s: status %d", redactURL(rawURL), head.StatusCode)
	}
	if head.ContentLength < 0 {
		return 0, "", fmt.Errorf("no Content-Length for %s", redactURL(rawURL))
	}
	size = head.ContentLength

	if size == 0 {
		return 0, cache.Signature(0, nil, nil), nil
	}
	if size <= int64(cache.MaxSample) {
		whole, err := getRange(c, rawURL, 0, size-1)
		if err != nil {
			return 0, "", err
		}
		return size, cache.Signature(size, whole, whole), nil
	}

	first, err := getRange(c, rawURL, 0, int64(cache.MaxSample)-1)
	if err != nil {
		return 0, "", err
	}
	last, err := getRange(c, rawURL, size-int64(cache.MaxSample), size-1)
	if err != nil {
		return 0, "", err
	}
	return size, cache.Signature(size, first, last), nil
}

// Download streams a remote URL straight to a local file. This is the origin
// fetch used when a cache miss has to be retrieved from the source.
func Download(ctx context.Context, rawURL, out string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: status %d", redactURL(rawURL), resp.StatusCode)
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

// getRange issues a single ranged GET. It returns 416 status details on an
// unsatisfiable range and an error if the server refuses ranges (a 200 would
// imply a full-body download, which we explicitly do not want).
func getRange(c *http.Client, rawURL string, lo, hi int64) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", lo, hi))
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusPartialContent:
		return io.ReadAll(resp.Body)
	case http.StatusRequestedRangeNotSatisfiable:
		return nil, fmt.Errorf("range %d-%d unsatisfiable", lo, hi)
	default:
		return nil, fmt.Errorf("range not supported (status %d) for %s", resp.StatusCode, redactURL(rawURL))
	}
}

// redactURL drops the query string so signed URLs (e.g. Azure SAS tokens) never
// leak credentials into error messages or logs.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	return u.String()
}
