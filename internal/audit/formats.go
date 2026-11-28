package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"
)

// eachK8sEvent reads a Kubernetes audit log in whichever form it was exported:
//   - audit.k8s.io/v1 events, one per line (kube-apiserver, kind, AKS Log Analytics exports)
//   - Google Cloud Audit Logs entries, as JSON lines or the array `gcloud logging read --format=json` prints (GKE)
//   - CloudWatch Logs exports, where each event's "message" holds the audit event as a string (EKS)
func eachK8sEvent(r io.Reader, fn func(k8sEvent)) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	for _, raw := range splitJSON(data) {
		if e, ok := decodeK8sEvent(raw); ok {
			fn(e)
		}
	}
	return nil
}

// splitJSON returns the JSON objects in data: a top-level array, a CloudWatch {"events": [...]},
// or one object per line.
func splitJSON(data []byte) []json.RawMessage {
	trimmed := bytes.TrimSpace(data)
	var list []json.RawMessage
	if bytes.HasPrefix(trimmed, []byte("[")) && json.Unmarshal(trimmed, &list) == nil {
		return list
	}
	var cw struct {
		Events []json.RawMessage `json:"events"`
	}
	if bytes.HasPrefix(trimmed, []byte("{")) && json.Unmarshal(trimmed, &cw) == nil && len(cw.Events) > 0 {
		return cw.Events
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if line = bytes.TrimSpace(line); len(line) > 0 {
			list = append(list, json.RawMessage(line))
		}
	}
	return list
}

func decodeK8sEvent(raw json.RawMessage) (k8sEvent, bool) {
	var probe struct {
		ProtoPayload json.RawMessage `json:"protoPayload"`
		Message      *string         `json:"message"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return k8sEvent{}, false
	}
	switch {
	case probe.ProtoPayload != nil:
		return fromGCP(raw)
	case probe.Message != nil:
		return decodeK8sEvent(json.RawMessage(*probe.Message))
	}
	var e k8sEvent
	if json.Unmarshal(raw, &e) != nil {
		return k8sEvent{}, false
	}
	return e, true
}

// gkeMethod matches e.g. io.k8s.core.v1.pods.exec.create; gkeResource core/v1/namespaces/demo/pods/web/exec.
var (
	gkeMethod   = regexp.MustCompile(`^io\.k8s\.core\.v1\.pods\.(exec|attach|portforward)\.`)
	gkeResource = regexp.MustCompile(`namespaces/([^/]+)/pods/([^/]+)/`)
)

func fromGCP(raw json.RawMessage) (k8sEvent, bool) {
	var entry struct {
		InsertID     string    `json:"insertId"`
		Timestamp    time.Time `json:"timestamp"`
		ProtoPayload struct {
			MethodName         string `json:"methodName"`
			ResourceName       string `json:"resourceName"`
			AuthenticationInfo struct {
				PrincipalEmail string `json:"principalEmail"`
			} `json:"authenticationInfo"`
			Status *struct {
				Code int `json:"code"`
			} `json:"status"`
		} `json:"protoPayload"`
	}
	if json.Unmarshal(raw, &entry) != nil {
		return k8sEvent{}, false
	}
	p := entry.ProtoPayload
	m := gkeMethod.FindStringSubmatch(p.MethodName)
	r := gkeResource.FindStringSubmatch(p.ResourceName + "/")
	if m == nil || r == nil {
		return k8sEvent{}, false
	}
	e := k8sEvent{AuditID: entry.InsertID, RequestReceivedTimestamp: entry.Timestamp}
	e.User.Username = strings.TrimSpace(p.AuthenticationInfo.PrincipalEmail)
	e.ObjectRef = &struct{ Resource, Subresource, Namespace, Name string }{"pods", m[1], r[1], r[2]}
	if p.Status != nil && p.Status.Code != 0 {
		e.ResponseStatus = &struct{ Code int }{403} // a gRPC error code: the API server refused it
	}
	return e, true
}
