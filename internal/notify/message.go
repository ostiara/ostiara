package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/ostiara/ostiara/internal/api"
)

// summary is a chat-neutral description of an event; each sender formats and escapes it.
type summary struct {
	Title  string
	Facts  [][2]string // label, value
	Footer string      // the command to run, if any
}

func summarize(e Event) summary {
	s := e.Session
	target := s.Namespace + "/" + s.Pod
	access := "exec: " + strings.Join(s.Command, " ")
	if s.Kind == api.KindPortForward {
		target = fmt.Sprintf("%s:%d", target, s.Port)
		access = "port-forward for " + (time.Duration(s.WindowSeconds) * time.Second).String()
	}
	reason := s.Reason
	if reason == "" {
		reason = "(none given)"
	}
	facts := [][2]string{{"Requester", s.Requester}, {"Pod", target}, {"Access", access}}

	switch e.Kind {
	case Requested:
		return summary{
			Title:  fmt.Sprintf("🗝️ %s is asking for access to %s", s.Requester, target),
			Facts:  append(facts, [2]string{"Reason", reason}, [2]string{"Session", s.ID}),
			Footer: fmt.Sprintf("ostiara approve %s   (or: ostiara deny %s)", s.ID, s.ID),
		}
	case Approved:
		until := "within 5 minutes, once"
		if s.Kind == api.KindPortForward {
			until = "until " + s.ExpiresAt.UTC().Format("15:04 UTC")
		}
		return summary{
			Title: fmt.Sprintf("✅ %s approved %s's access to %s (%s)", s.Approver, s.Requester, target, until),
			Facts: append(facts, [2]string{"Session", s.ID}),
		}
	default:
		return summary{
			Title: fmt.Sprintf("⛔ %s denied %s's access to %s", s.Approver, s.Requester, target),
			Facts: append(facts, [2]string{"Session", s.ID}),
		}
	}
}
