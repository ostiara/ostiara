package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"time"
)

// Finding kinds.
const (
	UnapprovedBrokerExec = "unapproved-broker-exec" // the broker's identity opened a shell or port-forward ostiara never approved
	DirectAccess         = "direct-access"          // someone other than the broker exec'd, attached or port-forwarded
)

// Finding is one pod access in the Kubernetes audit log that needs a human to look at it.
type Finding struct {
	Kind        string
	Time        time.Time
	User        string
	Namespace   string
	Pod         string
	Subresource string
	AuditID     string
}

// CheckOptions tunes Check.
type CheckOptions struct {
	BrokerUser string        // the broker's Kubernetes username
	Window     time.Duration // how far apart an approved attach and its exec may be
}

// k8sEvent is the part of an audit.k8s.io/v1 Event that Check reads.
type k8sEvent struct {
	AuditID   string
	User      struct{ Username string }
	ObjectRef *struct {
		Resource, Subresource, Namespace, Name string
	}
	ResponseStatus           *struct{ Code int }
	RequestReceivedTimestamp time.Time
}

// Check reads the Kubernetes API audit log and ostiara's audit log, and reports every
// shell, attach or port-forward into a pod that no ostiara approval accounts for.
func Check(k8sLog, ostiaraLog io.Reader, opts CheckOptions) ([]Finding, error) {
	// "exec ns/pod" or "portforward ns/pod" -> times ostiara opened an approved connection.
	approved := map[string][]time.Time{}
	err := eachLine(ostiaraLog, func(line []byte) {
		var e Event
		if json.Unmarshal(line, &e) != nil || e.Stream != Stream {
			return
		}
		switch e.Kind {
		case Attached:
			approved["exec "+e.Namespace+"/"+e.Pod] = append(approved["exec "+e.Namespace+"/"+e.Pod], e.Time)
		case ForwardOpened:
			approved["portforward "+e.Namespace+"/"+e.Pod] = append(approved["portforward "+e.Namespace+"/"+e.Pod], e.Time)
		}
	})
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var accesses []k8sEvent
	err = eachLine(k8sLog, func(line []byte) {
		var e k8sEvent
		if json.Unmarshal(line, &e) != nil || e.ObjectRef == nil || e.ObjectRef.Resource != "pods" {
			return
		}
		if !slices.Contains([]string{"exec", "attach", "portforward"}, e.ObjectRef.Subresource) {
			return
		}
		if e.ResponseStatus != nil && e.ResponseStatus.Code >= 400 {
			return // refused by the API server: nothing was opened
		}
		if seen[e.AuditID] {
			return // the same request logged at another stage
		}
		seen[e.AuditID] = true
		accesses = append(accesses, e)
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(accesses, func(a, b k8sEvent) int { return a.RequestReceivedTimestamp.Compare(b.RequestReceivedTimestamp) })

	var findings []Finding
	for _, a := range accesses {
		f := Finding{
			Time:        a.RequestReceivedTimestamp,
			User:        a.User.Username,
			Namespace:   a.ObjectRef.Namespace,
			Pod:         a.ObjectRef.Name,
			Subresource: a.ObjectRef.Subresource,
			AuditID:     a.AuditID,
		}
		if a.User.Username != opts.BrokerUser {
			f.Kind = DirectAccess
			findings = append(findings, f)
			continue
		}
		if claim(approved, f.Subresource+" "+f.Namespace+"/"+f.Pod, f.Time, opts.Window) {
			continue
		}
		f.Kind = UnapprovedBrokerExec
		findings = append(findings, f)
	}
	return findings, nil
}

// claim uses up the approved attach closest to t, if one is within window.
func claim(attaches map[string][]time.Time, key string, t time.Time, window time.Duration) bool {
	best, bestGap := -1, window+1
	for i, at := range attaches[key] {
		gap := t.Sub(at)
		if gap < 0 {
			gap = -gap
		}
		if gap <= window && gap < bestGap {
			best, bestGap = i, gap
		}
	}
	if best < 0 {
		return false
	}
	attaches[key] = slices.Delete(attaches[key], best, best+1)
	return true
}

// eachLine calls fn for every non-empty line, allowing the long lines Kubernetes audit logs have.
func eachLine(r io.Reader, fn func([]byte)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		if line := sc.Bytes(); len(bytes.TrimSpace(line)) > 0 {
			fn(line)
		}
	}
	return sc.Err()
}
