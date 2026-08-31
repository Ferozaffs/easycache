package cache

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
)

// MaxSample is how many bytes are read from the head and tail of a file to
// build a cheap partial signature. It is deliberately small so fingerprinting a
// huge file costs at most 2*MaxSample bytes of reads.
const MaxSample = 64 * 1024

// Fingerprint is the pair of identifiers a client can compute for a file.
type Fingerprint struct {
	// Hash is the full SHA-256 of the entire content. Unambiguous identity.
	Hash string
	// Sig is a cheap partial signature derived from size + first/last sample.
	// It is a pre-filter, not an identity: collisions are possible in theory.
	Sig string
	// Size is the total number of bytes.
	Size int64
}

// Signature computes the cheap partial signature from a total size and the
// head/tail samples. Two files only share a Sig if they have the same length
// and the same first/last MaxSample bytes.
func Signature(size int64, first, last []byte) string {
	h := sha256.New()
	var sz [8]byte
	binary.BigEndian.PutUint64(sz[:], uint64(size))
	h.Write(sz[:])
	f := sha256.Sum256(first)
	h.Write(f[:])
	l := sha256.Sum256(last)
	h.Write(l[:])
	return hex.EncodeToString(h.Sum(nil))
}

// FingerprintReader reads the whole stream once, returning the full SHA-256
// and the partial signature without buffering more than ~2*MaxSample bytes.
func FingerprintReader(r io.Reader) (Fingerprint, error) {
	full := sha256.New()
	first := make([]byte, 0, MaxSample)
	last := newRingBuf(MaxSample)
	buf := make([]byte, 32*1024)
	var size int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			size += int64(n)
			full.Write(buf[:n])
			if len(first) < MaxSample {
				if need := MaxSample - len(first); n > need {
					first = append(first, buf[:need]...)
				} else {
					first = append(first, buf[:n]...)
				}
			}
			last.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return Fingerprint{}, err
		}
	}
	return Fingerprint{
		Hash: hex.EncodeToString(full.Sum(nil)),
		Sig:  Signature(size, first, last.Bytes()),
		Size: size,
	}, nil
}

// FingerprintAndCopy is FingerprintReader for an upload: it fingerprints the
// stream while tee-ing it into dst (the on-disk temp file) so the body is only
// read once.
func FingerprintAndCopy(dst io.Writer, r io.Reader) (Fingerprint, error) {
	full := sha256.New()
	mw := io.MultiWriter(dst, full)
	first := make([]byte, 0, MaxSample)
	last := newRingBuf(MaxSample)
	buf := make([]byte, 32*1024)
	var size int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			size += int64(n)
			if _, werr := mw.Write(buf[:n]); werr != nil {
				return Fingerprint{}, werr
			}
			if len(first) < MaxSample {
				if need := MaxSample - len(first); n > need {
					first = append(first, buf[:need]...)
				} else {
					first = append(first, buf[:n]...)
				}
			}
			last.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return Fingerprint{}, err
		}
	}
	return Fingerprint{
		Hash: hex.EncodeToString(full.Sum(nil)),
		Sig:  Signature(size, first, last.Bytes()),
		Size: size,
	}, nil
}

// ringBuf keeps the last n bytes written to it, in order.
type ringBuf struct {
	buf []byte
	n   int
}

func newRingBuf(n int) *ringBuf { return &ringBuf{n: n} }

func (r *ringBuf) Write(p []byte) {
	if len(p) >= r.n {
		r.buf = append(r.buf[:0], p[len(p)-r.n:]...)
		return
	}
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.n {
		r.buf = r.buf[len(r.buf)-r.n:]
	}
}

func (r *ringBuf) Bytes() []byte { return r.buf }
