package cache

import (
	"encoding/json"
	"net/http"
	"os"
)

// Handler serves the two cache endpoints over HTTP.
type Handler struct {
	store *Store
}

// NewHandler builds the HTTP handler bound to an open Store.
func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

type checkRequest struct {
	Sig  string `json:"sig"`
	Hash string `json:"hash"`
}

// response is returned for /check hits and /upload completions.
type response struct {
	Sig  string `json:"sig"`
	Hash string `json:"hash"`
	Size int64  `json:"size"`
	Name string `json:"name,omitempty"`
	Path string `json:"path"`
	URL  string `json:"url"`
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /check", h.check)
	mux.HandleFunc("POST /upload", h.upload)
	mux.HandleFunc("GET /files/{hash}", h.file)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// check matches a request against the cache. A full hash is authoritative; a
// partial signature is only trusted when it resolves to exactly one candidate.
// Any ambiguity is reported as a miss (404, empty body) so the caller never
// gets pointed at the wrong file.
func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	var req checkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var e *Entry
	var ok bool
	switch {
	case req.Hash != "":
		e, ok = h.store.ByHash(req.Hash)
	case req.Sig != "":
		e, ok = h.store.Candidate(req.Sig)
	default:
		http.Error(w, "sig or hash required", http.StatusBadRequest)
		return
	}

	if !ok {
		// Miss: 404 with an empty body, per the chosen semantics.
		w.WriteHeader(http.StatusNotFound)
		return
	}
	h.writeEntry(w, r, e)
}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request) {
	tmp, err := h.store.NewTempFile()
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	fp, err := FingerprintAndCopy(tmp, r.Body)
	if err != nil {
		tmp.Close()
		http.Error(w, "upload failed", http.StatusBadRequest)
		return
	}
	if err := tmp.Close(); err != nil {
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}

	e, err := h.store.Commit(tmpName, fp, r.Header.Get("X-Filename"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.writeEntry(w, r, e)
}

func (h *Handler) writeEntry(w http.ResponseWriter, r *http.Request, e *Entry) {
	_ = json.NewEncoder(w).Encode(response{
		Sig:  e.Sig,
		Hash: e.Hash,
		Size: e.Size,
		Name: e.Name,
		Path: e.Path,
		URL:  baseURL(r) + "/files/" + e.Hash,
	})
}

func (h *Handler) file(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	path, ok := h.store.DataPath(hash)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", itoa(info.Size()))
	http.ServeFile(w, r, path)
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for nx := n; nx > 0; nx /= 10 {
		i--
		b[i] = byte('0' + nx%10)
	}
	return string(b[i:])
}
