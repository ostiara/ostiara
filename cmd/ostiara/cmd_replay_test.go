package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPlay(t *testing.T) {
	cast := `{"version":2,"width":80,"height":24,"timestamp":1}
[0.5,"o","hello "]
[0.6,"i","secret"]
[30.0,"o","world"]
[30.0,"r","100x30"]
`
	var out bytes.Buffer
	var slept []time.Duration
	if err := play(&out, strings.NewReader(cast), 2, 2*time.Second, func(d time.Duration) { slept = append(slept, d) }); err != nil {
		t.Fatal(err)
	}
	if out.String() != "hello world" {
		t.Fatalf("output = %q (input and resize events must not be printed)", out.String())
	}
	if len(slept) != 2 || slept[0] != 250*time.Millisecond || slept[1] != 2*time.Second {
		t.Fatalf("pauses = %v, want 250ms at 2x speed, then the 2s idle cap", slept)
	}
	if err := play(&out, strings.NewReader(`{"version":1}`), 1, time.Second, func(time.Duration) {}); err == nil {
		t.Fatal("asciicast v1: want an error")
	}
}
