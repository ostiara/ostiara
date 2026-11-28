// Package recording saves shell sessions as asciicast v2 files, playable with
// `asciinema play` or `ostiara replay`, and fingerprints each one for the audit log.
package recording

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// DefaultLimit caps one recording, so a runaway session can't fill the disk.
const DefaultLimit = 64 << 20

var validID = regexp.MustCompile(`^[a-f0-9]{8,64}$`)

// Header is the first line of an asciicast v2 file.
type Header struct {
	Version   int    `json:"version"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Timestamp int64  `json:"timestamp"`
	Title     string `json:"title,omitempty"`
}

// Result describes a finished recording, for the audit log.
type Result struct {
	File      string `json:"file"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Store keeps recordings as <Dir>/<session id>.cast.
type Store struct {
	Dir   string
	Limit int64 // 0 means DefaultLimit
}

// Path is where a session's recording lives; the id is checked so it can't escape Dir.
func (s Store) Path(id string) (string, error) {
	if !validID.MatchString(id) {
		return "", fmt.Errorf("bad session id %q", id)
	}
	return filepath.Join(s.Dir, id+".cast"), nil
}

// Create starts a new recording. It never overwrites one that exists.
func (s Store) Create(id, title string, now time.Time) (*Recorder, error) {
	path, err := s.Path(id)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create recording: %w", err)
	}
	limit := s.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	r := &Recorder{f: f, h: sha256.New(), start: now, now: time.Now, limit: limit, file: filepath.Base(path)}
	r.w = io.MultiWriter(f, r.h)
	if err := r.line(Header{Version: 2, Width: 80, Height: 24, Timestamp: now.Unix(), Title: title}); err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

// Open reads a recording back.
func (s Store) Open(id string) (*os.File, error) {
	path, err := s.Path(id)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

// Recorder appends events to one recording. Safe for concurrent use.
type Recorder struct {
	mu        sync.Mutex
	f         *os.File
	h         hash.Hash
	w         io.Writer
	start     time.Time
	now       func() time.Time
	written   int64
	limit     int64
	truncated bool
	err       error
	file      string
}

// Output records what the session printed.
func (r *Recorder) Output(p []byte) { r.event("o", string(p)) }

// Input records what was typed.
func (r *Recorder) Input(p []byte) { r.event("i", string(p)) }

// Resize records a new terminal size.
func (r *Recorder) Resize(width, height uint16) {
	if width == 0 || height == 0 {
		return // no real terminal size: nothing to replay
	}
	r.event("r", strconv.Itoa(int(width))+"x"+strconv.Itoa(int(height)))
}

func (r *Recorder) event(kind, data string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.truncated || r.err != nil {
		return
	}
	elapsed := r.now().Sub(r.start).Seconds()
	r.err = r.lineLocked([]any{json.Number(strconv.FormatFloat(elapsed, 'f', 6, 64)), kind, data})
}

func (r *Recorder) line(v any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lineLocked(v)
}

func (r *Recorder) lineLocked(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if r.written+int64(len(b)) > r.limit {
		r.truncated = true
		return nil
	}
	n, err := r.w.Write(b)
	r.written += int64(n)
	return err
}

// Close finishes the recording and returns its size and fingerprint.
func (r *Recorder) Close() (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	err := errors.Join(r.err, r.f.Sync(), r.f.Close())
	return Result{File: r.file, Bytes: r.written, SHA256: hex.EncodeToString(r.h.Sum(nil)), Truncated: r.truncated}, err
}

// Tee returns a writer that records p, then passes it on to w.
func Tee(w io.Writer, record func([]byte)) io.Writer {
	return teeWriter{w: w, record: record}
}

type teeWriter struct {
	w      io.Writer
	record func([]byte)
}

func (t teeWriter) Write(p []byte) (int, error) {
	t.record(p)
	return t.w.Write(p)
}
