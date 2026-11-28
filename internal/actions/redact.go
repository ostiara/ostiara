package actions

import (
	"bytes"
	"io"
	"regexp"
	"sync"
)

// secretKey matches variable names that usually hold secrets.
var secretKey = regexp.MustCompile(`(?i)(pass|secret|token|key|credential|auth|private|cert|cookie|session|dsn|conn)`)

// urlCredentials matches the password in scheme://user:password@host.
var urlCredentials = regexp.MustCompile(`(://[^:/@\s]*:)[^@/\s]+@`)

// RedactEnvLine hides a KEY=VALUE line's value when the key looks secret, and any password
// inside a URL whatever the key is called (e.g. DATABASE_URL=postgres://app:hunter2@db).
func RedactEnvLine(line []byte) []byte {
	key, value, ok := bytes.Cut(line, []byte("="))
	if !ok {
		return line
	}
	if secretKey.Match(key) && len(bytes.TrimSpace(value)) > 0 {
		out := append([]byte(nil), key...)
		return append(out, "=•••••• (hidden by ostiara)"...)
	}
	return urlCredentials.ReplaceAll(line, []byte("${1}••••••@"))
}

// EnvRedactor returns a writer that redacts each complete line before passing it on.
// Call Flush at the end for a last line with no newline.
func EnvRedactor(w io.Writer) *LineRedactor {
	return &LineRedactor{w: w, redact: RedactEnvLine}
}

// LineRedactor buffers output into lines so nothing is passed on half-redacted.
type LineRedactor struct {
	mu     sync.Mutex
	w      io.Writer
	buf    []byte
	redact func([]byte) []byte
}

func (l *LineRedactor) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		line := l.redact(append([]byte(nil), l.buf[:i]...))
		if _, err := l.w.Write(append(line, '\n')); err != nil {
			return 0, err
		}
		l.buf = l.buf[i+1:]
	}
	return len(p), nil
}

// Flush passes on a final unterminated line.
func (l *LineRedactor) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buf) == 0 {
		return nil
	}
	_, err := l.w.Write(l.redact(l.buf))
	l.buf = nil
	return err
}
