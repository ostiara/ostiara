package broker

import (
	"os"
	"sync"
	"time"
)

// reloader keeps a config file loaded and re-reads it when it changes, as a mounted ConfigMap
// does. A bad edit is logged and the last good version stays in use.
type reloader[T any] struct {
	path    string
	load    func(string) (T, error)
	log     func(msg string, args ...any)
	mu      sync.Mutex
	current T
	mtime   time.Time
}

func newReloader[T any](path string, load func(string) (T, error), log func(string, ...any)) (*reloader[T], error) {
	v, err := load(path)
	if err != nil {
		return nil, err
	}
	r := &reloader[T]{path: path, load: load, log: log, current: v}
	if info, err := os.Stat(path); err == nil {
		r.mtime = info.ModTime()
	}
	return r, nil
}

func (r *reloader[T]) get() T {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.path == "" {
		return r.current
	}
	info, err := os.Stat(r.path)
	if err != nil || info.ModTime().Equal(r.mtime) {
		return r.current
	}
	v, err := r.load(r.path)
	if err != nil {
		r.log("config not reloaded; keeping the last good version", "file", r.path, "err", err)
		return r.current
	}
	r.current, r.mtime = v, info.ModTime()
	return r.current
}
