// Package wire frames a live session over a WebSocket: [channel byte][payload].
package wire

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/gorilla/websocket"
)

const (
	ChanStdin      byte = 0 // CLI → broker
	ChanStdout     byte = 1 // broker → CLI
	ChanStderr     byte = 2 // broker → CLI (non-TTY only)
	ChanResize     byte = 3 // CLI → broker, JSON Resize
	ChanExit       byte = 4 // broker → CLI, JSON Exit, always last
	ChanStdinClose byte = 5 // CLI → broker, end of input
)

// Resize is a new terminal size.
type Resize struct {
	Width  uint16 `json:"width"`
	Height uint16 `json:"height"`
}

// Exit reports how the remote command finished.
type Exit struct {
	Code  int    `json:"code"`
	Error string `json:"error,omitempty"`
}

// Conn is a WebSocket with channel framing. Safe for concurrent writers.
type Conn struct {
	ws      *websocket.Conn
	writeMu sync.Mutex
}

func New(ws *websocket.Conn) *Conn {
	return &Conn{ws: ws}
}

// Send writes one framed message.
func (c *Conn) Send(channel byte, data []byte) error {
	msg := make([]byte, 1+len(data))
	msg[0] = channel
	copy(msg[1:], data)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.WriteMessage(websocket.BinaryMessage, msg)
}

func (c *Conn) SendJSON(channel byte, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Send(channel, data)
}

// Receive blocks until the next framed message arrives.
func (c *Conn) Receive() (channel byte, data []byte, err error) {
	for {
		msgType, msg, err := c.ws.ReadMessage()
		if err != nil {
			return 0, nil, err
		}
		if msgType != websocket.BinaryMessage || len(msg) == 0 {
			continue
		}
		return msg[0], msg[1:], nil
	}
}

// Writer returns an io.Writer that sends everything on one channel.
func (c *Conn) Writer(channel byte) io.Writer {
	return channelWriter{conn: c, channel: channel}
}

func (c *Conn) Close() error {
	return c.ws.Close()
}

type channelWriter struct {
	conn    *Conn
	channel byte
}

func (w channelWriter) Write(p []byte) (int, error) {
	if err := w.conn.Send(w.channel, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
