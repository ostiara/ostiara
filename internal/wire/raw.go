package wire

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Raw carries a plain byte stream over a WebSocket, as binary messages. Used for port-forward.
type Raw struct {
	ws      *websocket.Conn
	r       io.Reader // current message being read
	writeMu sync.Mutex
}

func NewRaw(ws *websocket.Conn) *Raw {
	return &Raw{ws: ws}
}

// Read returns io.EOF when the other side closes normally.
func (c *Raw) Read(p []byte) (int, error) {
	for {
		if c.r == nil {
			typ, r, err := c.ws.NextReader()
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return 0, io.EOF
			}
			if err != nil {
				return 0, err
			}
			if typ != websocket.BinaryMessage {
				continue
			}
			c.r = r
		}
		n, err := c.r.Read(p)
		if errors.Is(err, io.EOF) {
			c.r = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *Raw) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWith tells the other side why the stream ended, then closes it.
func (c *Raw) CloseWith(code int, reason string) error {
	if len(reason) > 120 { // close reasons are limited to 123 bytes
		reason = reason[:120]
	}
	c.writeMu.Lock()
	_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
	c.writeMu.Unlock()
	return c.ws.Close()
}

func (c *Raw) Close() error {
	return c.CloseWith(websocket.CloseNormalClosure, "")
}
