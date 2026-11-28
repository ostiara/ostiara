package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// runReplay plays a recorded session in the terminal, from the broker or a local .cast file.
func runReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	speed := fs.Float64("speed", 1, "playback speed")
	idle := fs.Duration("idle-limit", 2*time.Second, "shorten pauses longer than this")
	save := fs.String("o", "", "save the recording to this file instead of playing it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ostiara replay [-speed 1] [-o file] SESSION_ID|FILE.cast")
	}
	src, err := openRecording(fs.Arg(0))
	if err != nil {
		return err
	}
	defer src.Close()

	if *save != "" {
		out, err := os.OpenFile(*save, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, src)
		return err
	}
	if *speed <= 0 {
		return errors.New("-speed must be above 0")
	}
	return play(os.Stdout, src, *speed, *idle, time.Sleep)
}

func openRecording(arg string) (io.ReadCloser, error) {
	if strings.HasSuffix(arg, ".cast") || strings.ContainsRune(arg, os.PathSeparator) {
		return os.Open(arg)
	}
	c, err := newClient()
	if err != nil {
		return nil, err
	}
	return c.Recording(context.Background(), arg)
}

// play writes a recording's output events with their original timing.
func play(w io.Writer, r io.Reader, speed float64, idle time.Duration, sleep func(time.Duration)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	if !sc.Scan() {
		return errors.New("empty recording")
	}
	var header struct {
		Version int    `json:"version"`
		Title   string `json:"title"`
	}
	if err := json.Unmarshal(sc.Bytes(), &header); err != nil || header.Version != 2 {
		return errors.New("not an asciicast v2 recording")
	}
	if header.Title != "" {
		fmt.Fprintf(os.Stderr, "▶ %s\n", header.Title)
	}
	var last float64
	for sc.Scan() {
		var ev []json.RawMessage
		if json.Unmarshal(sc.Bytes(), &ev) != nil || len(ev) != 3 {
			continue
		}
		var at float64
		var kind, data string
		if json.Unmarshal(ev[0], &at) != nil || json.Unmarshal(ev[1], &kind) != nil || json.Unmarshal(ev[2], &data) != nil {
			continue
		}
		if kind != "o" {
			continue
		}
		gap := time.Duration((at - last) / speed * float64(time.Second))
		if gap > idle {
			gap = idle
		}
		if gap > 0 {
			sleep(gap)
		}
		last = at
		io.WriteString(w, data)
	}
	return sc.Err()
}
