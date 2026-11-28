// Package notify tells a team's chat about access requests and decisions. It only announces:
// approving still happens with `ostiara approve`, checked against Kubernetes identity.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/ostiara/ostiara/internal/api"
)

// Event kinds worth telling people about.
const (
	Requested = "requested"
	Approved  = "approved"
	Denied    = "denied"
)

// Event is one session change.
type Event struct {
	Kind    string
	Session api.Session
}

// Sender delivers one event to one chat service.
type Sender interface {
	Name() string // for logs; never the webhook URL, which is a secret
	Send(ctx context.Context, e Event) error
}

// Dispatcher sends events in the background, so a slow or broken chat service never
// delays or fails an access request.
type Dispatcher struct {
	senders []Sender
	queue   chan Event
	log     *slog.Logger
	timeout time.Duration
	done    chan struct{}
}

func NewDispatcher(log *slog.Logger, senders ...Sender) *Dispatcher {
	d := &Dispatcher{
		senders: senders,
		queue:   make(chan Event, 100),
		log:     log,
		timeout: 10 * time.Second,
		done:    make(chan struct{}),
	}
	go d.run()
	return d
}

// Notify queues e and returns at once. When the queue is full the event is dropped and logged.
func (d *Dispatcher) Notify(e Event) {
	select {
	case d.queue <- e:
	default:
		d.log.Warn("notification dropped: queue full", "event", e.Kind, "session", e.Session.ID)
	}
}

// Close sends what's queued, then stops.
func (d *Dispatcher) Close() {
	close(d.queue)
	<-d.done
}

func (d *Dispatcher) run() {
	defer close(d.done)
	for e := range d.queue {
		for _, s := range d.senders {
			ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
			if err := s.Send(ctx, e); err != nil {
				d.log.Warn("notification failed", "to", s.Name(), "event", e.Kind, "session", e.Session.ID, "err", err)
			}
			cancel()
		}
	}
}

// post sends a JSON payload, retrying once if the service is busy or erroring.
func post(ctx context.Context, client *http.Client, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := range 2 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return lastErr
			case <-time.After(time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = errorWithoutURL(err)
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		switch {
		case resp.StatusCode < 300:
			return nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("webhook returned %s", resp.Status)
		default:
			return fmt.Errorf("webhook returned %s", resp.Status)
		}
	}
	return lastErr
}

// errorWithoutURL keeps the webhook URL, which works as a password, out of logs.
func errorWithoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("webhook %s failed: %w", ue.Op, ue.Err)
	}
	return errors.New("webhook request failed")
}

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}
