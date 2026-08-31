package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

const knownHelloHash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

func TestFingerprintReaderSmall(t *testing.T) {
	fp, err := FingerprintReader(bytes.NewReader([]byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	if fp.Size != 5 {
		t.Fatalf("size = %d, want 5", fp.Size)
	}
	if fp.Hash != knownHelloHash {
		t.Fatalf("hash = %s, want %s", fp.Hash, knownHelloHash)
	}
	// For a small file, head == tail == whole content.
	want := Signature(5, []byte("hello"), []byte("hello"))
	if fp.Sig != want {
		t.Fatalf("sig = %s, want %s", fp.Sig, want)
	}
}

func TestFingerprintReaderMatchesParts(t *testing.T) {
	head := bytes.Repeat([]byte{0xAA}, MaxSample)
	mid := bytes.Repeat([]byte{0x11}, 50000)
	tail := bytes.Repeat([]byte{0xBB}, MaxSample)
	body := append(append(append([]byte{}, head...), mid...), tail...)

	fp, err := FingerprintReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if fp.Size != int64(len(body)) {
		t.Fatalf("size = %d, want %d", fp.Size, len(body))
	}
	if fp.Sig != Signature(fp.Size, head, tail) {
		t.Fatalf("sig mismatch")
	}
}

func TestFingerprintReaderMatchesCopy(t *testing.T) {
	content := bytes.Repeat([]byte("datapayload"), 20_000)
	var buf bytes.Buffer
	fpRead, err := FingerprintReader(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	fpCopy, err := FingerprintAndCopy(&buf, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if fpRead.Hash != fpCopy.Hash || fpRead.Sig != fpCopy.Sig || fpRead.Size != fpCopy.Size {
		t.Fatalf("reader/copy mismatch: %+v vs %+v", fpRead, fpCopy)
	}
	if !bytes.Equal(buf.Bytes(), content) {
		t.Fatalf("copy did not reproduce content")
	}
}

func TestFingerprintDistinguishesContent(t *testing.T) {
	a := bytes.Repeat([]byte{0x01}, 100_000)
	b := bytes.Repeat([]byte{0x02}, 100_000)
	fa, _ := FingerprintReader(bytes.NewReader(a))
	fb, _ := FingerprintReader(bytes.NewReader(b))
	if fa.Hash == fb.Hash {
		t.Fatal("different content produced same hash")
	}
	if fa.Sig == fb.Sig {
		t.Fatal("different content produced same sig")
	}
}

// TestFingerprintCollisionProvesSigIsOnlyAFilter builds two files that share
// the same size and the same head/tail sample (thus the same Sig) but differ in
// the middle. It confirms that the Sig cannot be trusted as an identity and
// that the full hash is the only decisive identifier.
func TestFingerprintCollisionProvesSigIsOnlyAFilter(t *testing.T) {
	head := bytes.Repeat([]byte{0x00}, MaxSample)
	tail := bytes.Repeat([]byte{0xFF}, MaxSample)

	makeBody := func(marker byte) []byte {
		mid := bytes.Repeat([]byte{marker}, 4096)
		b := make([]byte, 0, len(head)+len(mid)+len(tail))
		b = append(b, head...)
		b = append(b, mid...)
		b = append(b, tail...)
		return b
	}
	_ = makeBody

	file1 := append(append(append([]byte{}, head...), bytes.Repeat([]byte{0x01}, 4096)...), tail...)
	file2 := append(append(append([]byte{}, head...), bytes.Repeat([]byte{0x02}, 4096)...), tail...)

	fp1, _ := FingerprintReader(bytes.NewReader(file1))
	fp2, _ := FingerprintReader(bytes.NewReader(file2))

	if fp1.Size != fp2.Size {
		t.Fatalf("sizes differ: %d vs %d", fp1.Size, fp2.Size)
	}
	if fp1.Sig != fp2.Sig {
		t.Fatalf("expected a Sig collision, got %s vs %s", fp1.Sig, fp2.Sig)
	}
	if fp1.Hash == fp2.Hash {
		t.Fatal("hash collision: this test setup is wrong")
	}

	// Sanity: the full SHA-256 really is the identity.
	if got := hex.EncodeToString(sha256sum(file1)); got != fp1.Hash {
		t.Fatalf("hash inconsistent")
	}
}

func sha256sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
