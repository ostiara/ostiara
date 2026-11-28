package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)

func newRecorder(t *testing.T, limit int64) (*Recorder, Store) {
	t.Helper()
	st := Store{Dir: t.TempDir(), Limit: limit}
	r, err := st.Create("2cd09933", "ostiara 2cd09933: alice on demo/p", t0)
	if err != nil {
		t.Fatal(err)
	}
	clock := t0
	r.now = func() time.Time { clock = clock.Add(500 * time.Millisecond); return clock }
	return r, st
}

func TestRecordsAsciicast(t *testing.T) {
	r, st := newRecorder(t, 0)
	r.Resize(0, 0) // ignored
	r.Resize(120, 40)
	var screen bytes.Buffer
	out := Tee(&screen, r.Output)
	out.Write([]byte("$ ls\r\n"))
	r.Input([]byte("ls\r"))
	res, err := r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if screen.String() != "$ ls\r\n" {
		t.Fatalf("Tee didn't pass output through: %q", screen.String())
	}

	data, _ := os.ReadFile(filepath.Join(st.Dir, res.File))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 {
		t.Fatalf("want header + 3 events, got %d lines:\n%s", len(lines), data)
	}
	var h Header
	json.Unmarshal([]byte(lines[0]), &h)
	if h.Version != 2 || h.Timestamp != t0.Unix() || !strings.Contains(h.Title, "alice") {
		t.Fatalf("header = %+v", h)
	}
	if lines[1] != `[0.500000,"r","120x40"]` || lines[2] != `[1.000000,"o","$ ls\r\n"]` || lines[3] != `[1.500000,"i","ls\r"]` {
		t.Fatalf("events:\n%s", strings.Join(lines[1:], "\n"))
	}
	sum := sha256.Sum256(data)
	if res.SHA256 != hex.EncodeToString(sum[:]) || res.Bytes != int64(len(data)) || res.Truncated {
		t.Fatalf("result %+v doesn't describe the file (%d bytes)", res, len(data))
	}
}

func TestLimitTruncates(t *testing.T) {
	r, st := newRecorder(t, 200)
	for range 20 {
		r.Output([]byte("0123456789"))
	}
	res, _ := r.Close()
	info, _ := os.Stat(filepath.Join(st.Dir, res.File))
	if !res.Truncated || info.Size() > 200 || res.Bytes != info.Size() {
		t.Fatalf("result %+v, file %d bytes: want truncated at 200", res, info.Size())
	}
}

func TestStoreRules(t *testing.T) {
	st := Store{Dir: t.TempDir()}
	for _, bad := range []string{"../etc/passwd", "ABC12345", "", "2cd0"} {
		if _, err := st.Create(bad, "", t0); err == nil {
			t.Errorf("Create(%q): want refused", bad)
		}
	}
	r, err := st.Create("deadbeef", "", t0)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, err := st.Create("deadbeef", "", t0); err == nil {
		t.Fatal("second Create for the same session: want refused, never overwrite")
	}
	if info, _ := os.Stat(filepath.Join(st.Dir, "deadbeef.cast")); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}
