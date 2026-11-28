package doctor

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// Names ostiara's manifests use.
const (
	PolicyName     = "ostiara-block-direct-access"
	ExemptionsName = "ostiara-admission"
	BrokerExecRole = "ostiara-broker-exec"
)

// Snapshot is what doctor reads from the cluster.
type Snapshot struct {
	ClusterRoles        []rbacv1.ClusterRole
	Roles               []rbacv1.Role
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	RoleBindings        []rbacv1.RoleBinding
	Namespaces          []corev1.Namespace
	Policy              *admissionv1.ValidatingAdmissionPolicy // nil: not installed
	PolicyBindings      []admissionv1.ValidatingAdmissionPolicyBinding
	Exemptions          *corev1.ConfigMap // nil: missing
	ProviderIDs         []string          // from nodes, to tell which platform this is
	BrokerUser          string
}

// Grant is one subject that holds a capability through one binding.
type Grant struct {
	Capability Capability
	Subject    string
	System     bool // a Kubernetes or platform component, not a person or app
	What       []string
	Limited    bool   // only for named resources
	Scope      string // "cluster-wide" or "namespace <ns>"
	Via        string
	Blocked    string // pod access stopped by the admission policy: "", "yes" or "in protected namespaces"
}

// Check is one enforcement finding.
type Check struct {
	OK   bool
	Text string
}

// Report is doctor's result.
type Report struct {
	Enforcement []Check
	Grants      []Grant
	Notes       []string
}

// Warnings counts what needs attention: failed checks and non-system grants not fully blocked.
func (r Report) Warnings() int {
	n := 0
	for _, c := range r.Enforcement {
		if !c.OK {
			n++
		}
	}
	for _, g := range r.Grants {
		if !g.System && g.Blocked != "yes" {
			n++
		}
	}
	return n
}

// Analyze works out the report from a snapshot.
func Analyze(s Snapshot) Report {
	var r Report
	enforcing, protected := enforcement(s, &r)

	clusterRoles := map[string][]rbacv1.PolicyRule{}
	for _, cr := range s.ClusterRoles {
		clusterRoles[cr.Name] = cr.Rules
	}
	roles := map[string][]rbacv1.PolicyRule{}
	for _, ro := range s.Roles {
		roles[ro.Namespace+"/"+ro.Name] = ro.Rules
	}

	add := func(subjects []rbacv1.Subject, rules []rbacv1.PolicyRule, scope, ns, via string) {
		for _, c := range []Capability{PodAccess, Secrets, Workloads, Escalation} {
			what, limited := grants(rules, c)
			if len(what) == 0 {
				continue
			}
			for _, sub := range subjects {
				name, system := describe(sub)
				if name == "ServiceAccount "+serviceAccountRef(s.BrokerUser) {
					continue // the broker is meant to hold these
				}
				g := Grant{Capability: c, Subject: name, System: system, What: what, Limited: limited, Scope: scope, Via: via}
				if c == PodAccess && enforcing {
					switch {
					case ns == "":
						g.Blocked = "in protected namespaces"
					case protected[ns]:
						g.Blocked = "yes"
					}
				}
				r.Grants = append(r.Grants, g)
			}
		}
	}
	for _, b := range s.ClusterRoleBindings {
		add(b.Subjects, clusterRoles[b.RoleRef.Name], "cluster-wide", "",
			fmt.Sprintf("ClusterRoleBinding %s → ClusterRole %s", b.Name, b.RoleRef.Name))
	}
	for _, b := range s.RoleBindings {
		rules := roles[b.Namespace+"/"+b.RoleRef.Name]
		if b.RoleRef.Kind == "ClusterRole" {
			rules = clusterRoles[b.RoleRef.Name]
		}
		add(b.Subjects, rules, "namespace "+b.Namespace, b.Namespace,
			fmt.Sprintf("RoleBinding %s/%s → %s %s", b.Namespace, b.Name, b.RoleRef.Kind, b.RoleRef.Name))
	}

	order := map[Capability]int{PodAccess: 0, Secrets: 1, Workloads: 2, Escalation: 3}
	slices.SortStableFunc(r.Grants, func(a, b Grant) int {
		return cmp.Or(cmp.Compare(order[a.Capability], order[b.Capability]),
			boolCompare(a.System, b.System), cmp.Compare(a.Subject, b.Subject), cmp.Compare(a.Scope, b.Scope))
	})

	r.Notes = append(r.Notes,
		"Members of system:masters bypass RBAC and aren't listed here. The admission policy still blocks their direct pod access in protected namespaces.")
	r.Notes = append(r.Notes, platformNotes(s.ProviderIDs)...)
	return r
}

// enforcement checks the admission policy setup and returns whether it blocks, and where.
func enforcement(s Snapshot, r *Report) (bool, map[string]bool) {
	protected := map[string]bool{}
	brokerNS := map[string]bool{}
	for _, b := range s.RoleBindings {
		if b.RoleRef.Kind == "ClusterRole" && b.RoleRef.Name == BrokerExecRole {
			brokerNS[b.Namespace] = true
		}
	}

	if s.Policy == nil {
		r.Enforcement = append(r.Enforcement, Check{false, "Admission policy " + PolicyName + " isn't installed: RBAC alone decides who can get into pods (deploy/admission-policy.yaml)"})
		return false, protected
	}
	var binding *admissionv1.ValidatingAdmissionPolicyBinding
	for i := range s.PolicyBindings {
		if s.PolicyBindings[i].Spec.PolicyName == PolicyName {
			binding = &s.PolicyBindings[i]
		}
	}
	if binding == nil {
		r.Enforcement = append(r.Enforcement, Check{false, "Admission policy is installed but not bound, so it blocks nothing"})
		return false, protected
	}
	if !slices.Contains(binding.Spec.ValidationActions, admissionv1.Deny) {
		r.Enforcement = append(r.Enforcement, Check{false, fmt.Sprintf("Admission policy is in %v mode: it reports direct access but doesn't block it", binding.Spec.ValidationActions)})
		return false, protected
	}
	r.Enforcement = append(r.Enforcement, Check{true, "Admission policy is installed and blocking"})

	sel := binding.Spec.MatchResources
	switch {
	case sel == nil || sel.NamespaceSelector == nil:
		for _, ns := range s.Namespaces {
			protected[ns.Name] = true
		}
	case len(sel.NamespaceSelector.MatchExpressions) > 0:
		r.Enforcement = append(r.Enforcement, Check{false, "The policy binding uses matchExpressions; doctor only understands matchLabels, so protected namespaces may be wrong"})
		fallthrough
	default:
		for _, ns := range s.Namespaces {
			if labelsMatch(ns.Labels, sel.NamespaceSelector.MatchLabels) {
				protected[ns.Name] = true
			}
		}
	}
	names := keys(protected)
	if len(names) == 0 {
		r.Enforcement = append(r.Enforcement, Check{false, "No namespace is protected yet: label them with ostiara.io/enforce=true"})
	} else {
		r.Enforcement = append(r.Enforcement, Check{true, "Protected namespaces: " + strings.Join(names, ", ")})
	}
	var gaps []string
	for _, ns := range keys(brokerNS) {
		if !protected[ns] {
			gaps = append(gaps, ns)
		}
	}
	if len(gaps) > 0 {
		r.Enforcement = append(r.Enforcement, Check{false, "ostiara serves these namespaces but doesn't protect them, so direct access still works there: " + strings.Join(gaps, ", ")})
	}

	switch {
	case s.Exemptions == nil:
		r.Enforcement = append(r.Enforcement, Check{false, "ConfigMap ostiara-system/" + ExemptionsName + " is missing: everyone, the broker included, is blocked"})
	default:
		users, groups := strings.TrimSpace(s.Exemptions.Data["exemptUsers"]), strings.TrimSpace(s.Exemptions.Data["exemptGroups"])
		if users != "" || groups != "" {
			r.Enforcement = append(r.Enforcement, Check{false, fmt.Sprintf("Break-glass is open: exempt users [%s], groups [%s]. Clear them when the incident is over", users, groups)})
		} else {
			r.Enforcement = append(r.Enforcement, Check{true, "No break-glass exemptions"})
		}
	}
	return true, protected
}

// Namespaces and users that belong to Kubernetes or the platform, not to people or apps.
var (
	systemNamespacePrefixes = []string{"kube-", "local-path-storage", "gke-", "gmp-", "amazon-", "aws-", "calico-", "tigera-", "cilium"}
	systemUsers             = []string{"kube-apiserver-kubelet-client", "kube-apiserver"}
)

func describe(s rbacv1.Subject) (name string, system bool) {
	switch s.Kind {
	case rbacv1.ServiceAccountKind:
		for _, p := range systemNamespacePrefixes {
			if strings.HasPrefix(s.Namespace, p) {
				system = true
			}
		}
		return "ServiceAccount " + s.Namespace + "/" + s.Name, system
	default:
		return s.Kind + " " + s.Name, strings.HasPrefix(s.Name, "system:") || slices.Contains(systemUsers, s.Name)
	}
}

// serviceAccountRef turns system:serviceaccount:ns:name into ns/name.
func serviceAccountRef(user string) string {
	parts := strings.Split(user, ":")
	if len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
		return parts[2] + "/" + parts[3]
	}
	return user
}

func platformNotes(providerIDs []string) []string {
	seen := map[string]bool{}
	var notes []string
	for _, id := range providerIDs {
		scheme, _, _ := strings.Cut(id, "://")
		if seen[scheme] {
			continue
		}
		seen[scheme] = true
		switch scheme {
		case "gce":
			notes = append(notes, "GKE: Google IAM roles grant Kubernetes access too and aren't visible here. roles/container.developer and roles/container.admin include exec; give developers roles/container.viewer or a custom role.")
		case "aws":
			notes = append(notes, "EKS: access entries, access policies (e.g. AmazonEKSClusterAdminPolicy) and the aws-auth ConfigMap grant access outside these RBAC objects. Review them with `aws eks list-access-entries`.")
		case "azure":
			notes = append(notes, "AKS: Azure RBAC role assignments and local accounts grant access outside these RBAC objects. Disable local accounts and give developers an Azure role without exec.")
		}
	}
	return notes
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func boolCompare(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	default:
		return 1
	}
}
