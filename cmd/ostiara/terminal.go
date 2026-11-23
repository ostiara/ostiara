package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/ostiara/ostiara/internal/wire"
)

// runTerminal wires this terminal to a live session and returns the exit code.
func runTerminal(ctx context.Context, conn *wire.Conn, tty bool) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if tty {
		fd := int(os.Stdin.Fd())
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			return 1, fmt.Errorf("setting terminal to raw mode: %w", err)
		}
		defer term.Restore(fd, oldState)
		go forwardResizes(ctx, conn, fd)
	}
	go forwardStdin(conn)

	for {
		channel, data, err := conn.Receive()
		if err != nil {
			return 1, fmt.Errorf("lost connection to the broker: %w", err)
		}
		switch channel {
		case wire.ChanStdout:
			os.Stdout.Write(data)
		case wire.ChanStderr:
			os.Stderr.Write(data)
		case wire.ChanExit:
			var exit wire.Exit
			if err := json.Unmarshal(data, &exit); err != nil {
				return 1, fmt.Errorf("bad exit message: %w", err)
			}
			if exit.Error != "" {
				return 1, errors.New(exit.Error)
			}
			return exit.Code, nil
		}
	}
}

func forwardStdin(conn *wire.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			if conn.Send(wire.ChanStdin, buf[:n]) != nil {
				return
			}
		}
		if err != nil {
			_ = conn.Send(wire.ChanStdinClose, nil) // lets `sh` / `cat` see end of input
			return
		}
	}
}

// forwardResizes sends the window size now and on every SIGWINCH (macOS/Linux only).
func forwardResizes(ctx context.Context, conn *wire.Conn, fd int) {
	resized := make(chan os.Signal, 1)
	signal.Notify(resized, syscall.SIGWINCH)
	defer signal.Stop(resized)

	for {
		if width, height, err := term.GetSize(fd); err == nil {
			_ = conn.SendJSON(wire.ChanResize, wire.Resize{Width: uint16(width), Height: uint16(height)})
		}
		select {
		case <-resized:
		case <-ctx.Done():
			return
		}
	}
}
