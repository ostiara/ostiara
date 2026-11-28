// Package doctor checks a cluster for ways around ostiara: RBAC that grants direct pod access or
// its equivalents, and whether the admission policy that blocks direct access is in place.
package doctor

import (
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

// Capability is a kind of access that can get around ostiara or reach what it protects.
type Capability string

const (
	PodAccess  Capability = "pod-access" // exec, attach, port-forward, debug
	Secrets    Capability = "secrets"    // read Secrets directly
	Workloads  Capability = "workloads"  // create or change pods and controllers, which can mount Secrets
	Escalation Capability = "escalation" // grant yourself more: bind, escalate, impersonate, nodes/proxy
)

// check is one (apiGroup, resource, verbs) a capability is made of.
type check struct {
	group    string
	resource string
	verbs    []string
	label    string
}

var checks = map[Capability][]check{
	PodAccess: {
		{"", "pods/exec", []string{"create", "get"}, "exec"},
		{"", "pods/attach", []string{"create", "get"}, "attach"},
		{"", "pods/portforward", []string{"create", "get"}, "port-forward"},
		{"", "pods/ephemeralcontainers", []string{"update", "patch"}, "debug"},
	},
	Secrets: {
		{"", "secrets", []string{"get", "list", "watch"}, "read secrets"},
	},
	Workloads: {
		{"", "pods", []string{"create", "update", "patch"}, "pods"},
		{"apps", "deployments", []string{"create", "update", "patch"}, "deployments"},
		{"apps", "statefulsets", []string{"create", "update", "patch"}, "statefulsets"},
		{"apps", "daemonsets", []string{"create", "update", "patch"}, "daemonsets"},
		{"apps", "replicasets", []string{"create", "update", "patch"}, "replicasets"},
		{"batch", "jobs", []string{"create", "update", "patch"}, "jobs"},
		{"batch", "cronjobs", []string{"create", "update", "patch"}, "cronjobs"},
	},
	Escalation: {
		{"rbac.authorization.k8s.io", "roles", []string{"bind", "escalate"}, "bind/escalate roles"},
		{"rbac.authorization.k8s.io", "clusterroles", []string{"bind", "escalate"}, "bind/escalate clusterroles"},
		{"rbac.authorization.k8s.io", "rolebindings", []string{"create", "update", "patch"}, "change rolebindings"},
		{"rbac.authorization.k8s.io", "clusterrolebindings", []string{"create", "update", "patch"}, "change clusterrolebindings"},
		{"", "users", []string{"impersonate"}, "impersonate users"},
		{"", "groups", []string{"impersonate"}, "impersonate groups"},
		{"", "serviceaccounts", []string{"impersonate"}, "impersonate serviceaccounts"},
		{"", "nodes/proxy", []string{"get", "create"}, "nodes/proxy"},
	},
}

// grants reports what a set of rules allows for one capability, e.g. ["exec", "port-forward"].
// limited is true when every matching rule names specific resources only.
func grants(rules []rbacv1.PolicyRule, c Capability) (what []string, limited bool) {
	limited = true
	for _, ch := range checks[c] {
		for _, r := range rules {
			if matches(r.APIGroups, ch.group) && resourceMatches(r.Resources, ch.resource) && verbMatches(r.Verbs, ch.verbs) {
				if !slices.Contains(what, ch.label) {
					what = append(what, ch.label)
				}
				if len(r.ResourceNames) == 0 {
					limited = false
				}
			}
		}
	}
	if len(what) == len(checks[c]) && len(what) > 1 {
		what = []string{"all of it"}
	}
	return what, len(what) > 0 && limited
}

func matches(list []string, want string) bool {
	return slices.Contains(list, "*") || slices.Contains(list, want)
}

// resourceMatches follows RBAC: "*" is everything, "*/sub" is that subresource of anything.
func resourceMatches(list []string, want string) bool {
	if slices.Contains(list, "*") || slices.Contains(list, want) {
		return true
	}
	if _, sub, ok := strings.Cut(want, "/"); ok {
		return slices.Contains(list, "*/"+sub)
	}
	return false
}

func verbMatches(list []string, wants []string) bool {
	if slices.Contains(list, "*") {
		return true
	}
	for _, w := range wants {
		if slices.Contains(list, w) {
			return true
		}
	}
	return false
}
