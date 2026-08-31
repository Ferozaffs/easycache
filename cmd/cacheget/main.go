package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"easycache/internal/client"
)

var (
	timeoutFlag = flag.Duration("timeout", 3*time.Second, "zero-config look-up time")
	serverFlag  = flag.String("server", os.Getenv("CACHE_ADDR"), "comma-separated cache server host:port (skips zero-config look-up)")
)

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}

	ctx := context.Background()
	switch flag.Arg(0) {
	case "list":
		cmdList(ctx)
	case "check":
		cmdCheck(ctx, flag.Arg(1))
	case "put":
		cmdPut(ctx, flag.Arg(1))
	case "hash":
		cmdHash(flag.Arg(1))
	case "get":
		cmdGet(ctx, flag.Arg(1), flag.Arg(2))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `easycache client

  easycache list      discover cache servers
  easycache check <f> fast check a local file by partial signature (<=128KB read)
  easycache put  <f>  exact check then upload a local file if not cached
  easycache hash <f>  print size + partial signature + full SHA-256 of a local file
  easycache get  <url|sha256> [out]
                        URL: sample the remote (~130KB), copy from cache on hit,
                             or download once + seed the cache on miss.
                        sha256: check the cache by an exact content hash, and copy
                             it out if cached (no hash source = no download possible).

  -timeout 3s  zero-config look-up time
  -server  h:p  use a specific cache server, comma-separated. Also CACHE_ADDR.
                 Set it to skip mDNS (e.g. outside the LAN).
`)
}

func cmdList(ctx context.Context) {
	servers, err := client.Discover(ctx, *timeoutFlag)
	if err != nil {
		fatal(err)
	}
	if len(servers) == 0 {
		fmt.Println("no caches found")
		return
	}
	for _, s := range servers {
		fmt.Printf("%s  %s\n", s.Instance, s.URL())
	}
}

func cmdCheck(ctx context.Context, file string) {
	if file == "" {
		fatal("usage: easycache check <file>")
	}
	servers := mustDiscover(ctx)
	size, sig, err := client.QuickSignature(file)
	if err != nil {
		fatal(err)
	}
	for _, s := range servers {
		res, err := s.Check(ctx, sig, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", s.Instance, err)
			continue
		}
		if res == nil {
			fmt.Printf("%s: not cached\n", s.Instance)
			continue
		}
		fmt.Printf("%s: cached (%d bytes)\n  path %s\n  url  %s\n", s.Instance, size, res.Path, res.URL)
	}
}

func cmdPut(ctx context.Context, file string) {
	if file == "" {
		fatal("usage: easycache put <file>")
	}
	servers := mustDiscover(ctx)

	// Authoritative fingerprint: full SHA-256, no false positives.
	fp, err := client.FullSignature(file)
	if err != nil {
		fatal(err)
	}
	name := filepath.Base(file)

	for _, s := range servers {
		res, err := s.Check(ctx, fp.Sig, fp.Hash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", s.Instance, err)
			continue
		}
		if res != nil {
			fmt.Printf("%s: already cached\n  path %s\n  url  %s\n", s.Instance, res.Path, res.URL)
			continue
		}
		up, err := s.Upload(ctx, file, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", s.Instance, err)
			continue
		}
		fmt.Printf("%s: uploaded %d bytes\n  path %s\n  url  %s\n", s.Instance, up.Size, up.Path, up.URL)
	}
}

func cmdHash(file string) {
	if file == "" {
		fatal("usage: easycache hash <file>")
	}
	fp, err := client.FullSignature(file)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("size %d\nsig  %s\nhash %s\n", fp.Size, fp.Sig, fp.Hash)
}

// cmdGet is the single combined action. It takes either a URL or a SHA-256:
//
//   - URL: sample the remote file (~130 KB, head/tail), copy it from the cache if
//     that signature is already stored, otherwise download it once from the origin
//     and seed the cache so the next call is a hit.
//   - sha256: check the cache by an exact content hash and copy it out if present.
//     There is no download source for a bare hash, so a miss just reports it.
func cmdGet(ctx context.Context, arg, out string) {
	if arg == "" {
		fatal("usage: easycache get <url|sha256> [outfile]")
	}
	if isURL(arg) {
		getFromURL(ctx, arg, out)
		return
	}
	getByHash(ctx, arg, out)
}

func getFromURL(ctx context.Context, url, out string) {
	if out == "" {
		out = filepath.Base(url)
		if out == "" {
			out = "download.bin"
		}
	}

	servers := mustDiscover(ctx)

	// Cheap probe: HEAD + two small ranged GETs. If the remote does not offer
	// Content-Length / range support we cannot sample it, so we skip the pre-check
	// and just download+seed (still correct, just no cache-hit shortcut).
	size, sig, err := client.RemoteSignature(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot sample remote (%v) — downloading directly\n", err)
		seedFromOrigin(ctx, servers, url, out)
		return
	}

	// Pass 1 — is it already cached?
	for _, s := range servers {
		res, err := s.Check(ctx, sig, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", s.Instance, err)
			continue
		}
		if res == nil {
			continue
		}
		if err := s.Fetch(ctx, res.Hash, out); err != nil {
			fmt.Fprintf(os.Stderr, "%s: fetch: %v\n", s.Instance, err)
			continue
		}
		fmt.Printf("%s: cache HIT — copied %d bytes to %s (no download)\n", s.Instance, size, out)
		return
	}

	// Pass 2 — miss: fetch from the origin, then seed every reachable cache.
	fmt.Printf("not cached — downloading %d bytes from origin\n", size)
	seedFromOrigin(ctx, servers, url, out)
}

// seedFromOrigin downloads the file from the origin into out and uploads it to
// every reachable cache server.
func seedFromOrigin(ctx context.Context, servers []client.Server, url, out string) {
	if err := client.Download(ctx, url, out); err != nil {
		fatal(err)
	}
	seeded := false
	for _, s := range servers {
		up, err := s.Upload(ctx, out, filepath.Base(out))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: seed: %v\n", s.Instance, err)
			continue
		}
		seeded = true
		fmt.Printf("%s: seeded %d bytes (next time is a hit)\n", s.Instance, up.Size)
	}
	if !seeded {
		fmt.Printf("downloaded to %s, but no cache server accepted it\n", out)
	}
}

// getByHash looks a blob up by its full content hash and copies it to out. With
// no third party download source for a bare hash, a miss simply reports itself.
func getByHash(ctx context.Context, id, out string) {
	id = normalizeHash(id)
	if len(id) != 64 {
		fatal(fmt.Sprintf("expected a http(s) URL or a 64-character sha256, got %q", id))
	}
	servers := mustDiscover(ctx)
	for _, s := range servers {
		res, err := s.Check(ctx, "", id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", s.Instance, err)
			continue
		}
		if res == nil {
			fmt.Printf("%s: not cached\n", s.Instance)
			continue
		}
		if out == "" {
			fmt.Printf("%s: cached (%d bytes)\n  path %s\n  url  %s\n", s.Instance, res.Size, res.Path, res.URL)
			return
		}
		if err := s.Fetch(ctx, res.Hash, out); err != nil {
			fmt.Fprintf(os.Stderr, "%s: fetch: %v\n", s.Instance, err)
			continue
		}
		fmt.Printf("%s: cached — copied %d bytes to %s\n", s.Instance, res.Size, out)
		return
	}
	fatal("hash not found in any reachable cache server")
}

// isURL reports whether arg looks like an http(s) URL rather than a content hash.
func isURL(arg string) bool {
	lower := strings.ToLower(strings.TrimSpace(arg))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// normalizeHash lowercases a hash and strips an optional "sha256:" prefix.
func normalizeHash(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	id = strings.TrimPrefix(id, "sha256:")
	return id
}

func mustDiscover(ctx context.Context) []client.Server {
	if *serverFlag != "" {
		servers, err := fromAddrs(*serverFlag)
		if err != nil {
			fatal(err)
		}
		return servers
	}
	servers, err := client.Discover(ctx, *timeoutFlag)
	if err != nil {
		fatal(err)
	}
	if len(servers) == 0 {
		fatal("no caches found")
	}
	return servers
}

func fromAddrs(s string) ([]client.Server, error) {
	var out []client.Server
	for _, a := range strings.Split(s, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(a)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		out = append(out, client.NewServer(host, port))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no server addresses in %q", s)
	}
	return out, nil
}

func fatal(a ...any) {
	fmt.Fprint(os.Stderr, "error: ")
	fmt.Fprintln(os.Stderr, a...)
	os.Exit(1)
}
