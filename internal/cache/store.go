package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Entry is one cached file and where it lives on the server.
type Entry struct {
	Sig  string `json:"sig"`
	Hash string `json:"hash"`
	Size int64  `json:"size"`
	Name string `json:"name,omitempty"`
	Path string `json:"path"`
}

// Store is a content-addressed cache on disk. Files are stored under
// <dir>/<hash> and each has a sidecar <dir>/<hash>.json holding the cheap
// signature so the in-memory index can be rebuilt at startup without re-reading
// every file body.
type Store struct {
	mu     sync.RWMutex
	dir    string
	byHash map[string]*Entry
	bySig  map[string][]string // sig -> set of file hashes sharing it
}

// Open creates (or loads) a Store rooted at dir. Data and metadata subfolders
// are created on first use. If the directory already holds files, the index is
// rebuilt from the sidecar metadata.
func Open(dir string) (*Store, error) {
	s := &Store{
		dir:    dir,
		byHash: map[string]*Entry{},
		bySig:  map[string][]string{},
	}
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o755); err != nil {
		return nil, fmt.Errorf("create tmp: %w", err)
	}
	if err := s.rebuild(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) rebuild() error {
	metas, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	if err != nil {
		return err
	}
	for _, mp := range metas {
		data, err := os.ReadFile(mp)
		if err != nil {
			continue
		}
		var e Entry
		if err := json.Unmarshal(data, &e); err != nil {
			continue
		}
		hash := filepath.Base(mp)
		hash = hash[:len(hash)-len(".json")]
		e.Hash = hash
		dataPath := filepath.Join(s.dir, hash)
		if _, err := os.Stat(dataPath); err != nil {
			continue
		}
		e.Path = dataPath
		s.add(&e)
	}
	return nil
}

// add inserts an entry into the in-memory index. Caller holds the write lock.
func (s *Store) add(e *Entry) {
	e.Path = filepath.Join(s.dir, e.Hash)
	s.byHash[e.Hash] = e
	if !contains(s.bySig[e.Sig], e.Hash) {
		s.bySig[e.Sig] = append(s.bySig[e.Sig], e.Hash)
	}
}

// ByHash returns the entry for an exact full-content hash.
func (s *Store) ByHash(hash string) (*Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byHash[hash]
	return e, ok
}

// Candidate returns the entry a partial signature resolves to, but only when it
// is unambiguous. If the signature maps to zero or to more than one distinct
// cached file, ok is false so the caller fails safe rather than guessing.
func (s *Store) Candidate(sig string) (*Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hashes := s.bySig[sig]
	if len(hashes) != 1 {
		return nil, false
	}
	return s.byHash[hashes[0]], true
}

// DataPath returns the on-disk path for a known hash.
func (s *Store) DataPath(hash string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byHash[hash]
	if !ok {
		return "", false
	}
	return e.Path, true
}

// NewTempFile returns a file in the tmp subdir for a streaming upload.
func (s *Store) NewTempFile() (*os.File, error) {
	return os.CreateTemp(filepath.Join(s.dir, "tmp"), "upload-*")
}

// Commit atomically finalises an upload. If the content hash is already known
// the temp file is discarded and the existing entry returned (dedupe).
func (s *Store) Commit(tmpPath string, fp Fingerprint, name string) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.byHash[fp.Hash]; ok {
		_ = os.Remove(tmpPath)
		return e, nil
	}

	final := filepath.Join(s.dir, fp.Hash)
	if err := os.Rename(tmpPath, final); err != nil {
		return nil, fmt.Errorf("finalise upload: %w", err)
	}
	e := &Entry{
		Sig:  fp.Sig,
		Hash: fp.Hash,
		Size: fp.Size,
		Name: name,
		Path: final,
	}
	meta, err := json.MarshalIndent(&Entry{Sig: fp.Sig, Size: fp.Size, Name: name}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(final+".json", meta, 0o644); err != nil {
		return nil, fmt.Errorf("write metadata: %w", err)
	}
	s.add(e)
	return e, nil
}

// Del removes a cached file and its metadata.
func (s *Store) Del(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byHash[hash]
	if !ok {
		return nil
	}
	delete(s.byHash, hash)
	if list, ok := s.bySig[e.Sig]; ok {
		s.bySig[e.Sig] = removeStr(list, hash)
		if len(s.bySig[e.Sig]) == 0 {
			delete(s.bySig, e.Sig)
		}
	}
	_ = os.Remove(e.Path)
	_ = os.Remove(e.Path + ".json")
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func removeStr(list []string, v string) []string {
	out := list[:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
