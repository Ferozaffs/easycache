package cache

import (
	"bytes"
	"os"
	"testing"
)

func TestStorePutDedupeAndCandidate(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Upload a first file.
	content1 := []byte("some cacheable content")
	tmp, err := s.NewTempFile()
	if err != nil {
		t.Fatal(err)
	}
	fp1, err := FingerprintAndCopy(tmp, bytes.NewReader(content1))
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	e1, err := s.Commit(tmp.Name(), fp1, "first.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e1.Path); err != nil {
		t.Fatalf("stored file missing: %v", err)
	}

	// Same content again must dedupe to the same entry, not a second file.
	tmp2, err := s.NewTempFile()
	if err != nil {
		t.Fatal(err)
	}
	fp2, _ := FingerprintAndCopy(tmp2, bytes.NewReader(content1))
	tmp2.Close()
	e2, err := s.Commit(tmp2.Name(), fp2, "second.bin")
	if err != nil {
		t.Fatal(err)
	}
	if e2.Hash != e1.Hash {
		t.Fatalf("dedupe returned different hash: %s vs %s", e2.Hash, e1.Hash)
	}

	if got, ok := s.ByHash(fp1.Hash); !ok || got.Path != e1.Path {
		t.Fatalf("ByHash lookup failed")
	}
	if got, ok := s.Candidate(fp1.Sig); !ok || got.Hash != fp1.Hash {
		t.Fatalf("Candidate lookup failed for unambiguous sig")
	}
}

func TestStoreAmbiguousSigFailsSafe(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	head := bytes.Repeat([]byte{0x00}, MaxSample)
	tail := bytes.Repeat([]byte{0xFF}, MaxSample)
	mk := func(marker byte) []byte {
		mid := bytes.Repeat([]byte{marker}, 4096)
		b := make([]byte, 0, len(head)+len(mid)+len(tail))
		b = append(b, head...)
		b = append(b, mid...)
		b = append(b, tail...)
		return b
	}

	upload := func(content []byte, name string) *Entry {
		tmp, _ := s.NewTempFile()
		fp, _ := FingerprintAndCopy(tmp, bytes.NewReader(content))
		tmp.Close()
		e, err := s.Commit(tmp.Name(), fp, name)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}

	e1 := upload(mk(0x01), "a.bin")
	e2 := upload(mk(0x02), "b.bin")
	if e1.Sig != e2.Sig {
		t.Fatalf("expected sig collision, got %s vs %s", e1.Sig, e2.Sig)
	}
	if _, ok := s.Candidate(e1.Sig); ok {
		t.Fatal("ambiguous sig must NOT resolve to a single candidate")
	}
	// Exact hash lookups are unaffected.
	if _, ok := s.ByHash(e1.Hash); !ok {
		t.Fatal("exact hash lookup should still work")
	}
	if _, ok := s.ByHash(e2.Hash); !ok {
		t.Fatal("exact hash lookup should still work")
	}
}
