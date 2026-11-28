package doctor

import (
	"context"
	"slices"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const broker = "system:serviceaccount:ostiara-system:ostiara-broker"

var (
	editRole = rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "edit"}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods/exec", "pods/portforward", "secrets", "pods"}, Verbs: []string{"create", "get", "update"}},
	}}
	adminRole = rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
	}}
	brokerRole = rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: BrokerExecRole}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods/exec", "pods/portforward"}, Verbs: []string{"create", "get"}},
	}}
	viewRole = rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "view"}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "pods/log"}, Verbs: []string{"get", "list"}},
	}}
)

func rb(ns, name, role string, sub rbacv1.Subject) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: role}, Subjects: []rbacv1.Subject{sub}}
}

func user(name string) rbacv1.Subject { return rbacv1.Subject{Kind: rbacv1.UserKind, Name: name} }

func ns(name string, labels map[string]string) corev1.Namespace {
	return corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// cluster is a small cluster: prod is protected and served by the broker, staging is only served.
func cluster(actions ...admissionv1.ValidationAction) Snapshot {
	if len(actions) == 0 {
		actions = []admissionv1.ValidationAction{admissionv1.Deny}
	}
	return Snapshot{
		BrokerUser:   broker,
		ClusterRoles: []rbacv1.ClusterRole{editRole, adminRole, brokerRole, viewRole},
		Namespaces: []corev1.Namespace{
			ns("prod", map[string]string{"ostiara.io/enforce": "true"}), ns("staging", nil), ns("kube-system", nil),
		},
		RoleBindings: []rbacv1.RoleBinding{
			rb("prod", "broker", BrokerExecRole, rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Namespace: "ostiara-system", Name: "ostiara-broker"}),
			rb("staging", "broker", BrokerExecRole, rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Namespace: "ostiara-system", Name: "ostiara-broker"}),
			rb("prod", "alice-edit", "edit", user("alice")),
			rb("staging", "bob-edit", "edit", user("bob")),
			rb("prod", "carol-view", "view", user("carol")),
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "admins"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "admins"}, {Kind: rbacv1.GroupKind, Name: "system:masters"}},
		}},
		Policy: &admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Name: PolicyName}},
		PolicyBindings: []admissionv1.ValidatingAdmissionPolicyBinding{{Spec: admissionv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: PolicyName, ValidationActions: actions,
			MatchResources: &admissionv1.MatchResources{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"ostiara.io/enforce": "true"}}},
		}}},
		Exemptions: &corev1.ConfigMap{Data: map[string]string{"exemptUsers": "", "exemptGroups": ""}},
	}
}

func find(r Report, c Capability, subject string) (Grant, bool) {
	for _, g := range r.Grants {
		if g.Capability == c && g.Subject == subject {
			return g, true
		}
	}
	return Grant{}, false
}

func checkText(r Report) string {
	var b strings.Builder
	for _, c := range r.Enforcement {
		b.WriteString(c.Text + "\n")
	}
	return b.String()
}

func TestBlockedOnlyWhereProtected(t *testing.T) {
	r := Analyze(cluster())
	if g, _ := find(r, PodAccess, "User alice"); g.Blocked != "yes" {
		t.Errorf("alice's exec in protected prod: blocked=%q, want yes", g.Blocked)
	}
	if g, ok := find(r, PodAccess, "User bob"); !ok || g.Blocked != "" {
		t.Errorf("bob's exec in unprotected staging: %+v, want a grant that isn't blocked", g)
	}
	if g, _ := find(r, PodAccess, "Group admins"); g.Blocked != "in protected namespaces" || !slices.Equal(g.What, []string{"all of it"}) {
		t.Errorf("cluster-admin: %+v", g)
	}
	if _, ok := find(r, Secrets, "User alice"); !ok {
		t.Error("alice's edit role also reads Secrets: want a Secrets finding, which the policy can't block")
	}
	if _, ok := find(r, PodAccess, "User carol"); ok {
		t.Error("carol only has view: want no pod-access finding")
	}
	for _, g := range r.Grants {
		if strings.Contains(g.Subject, "ostiara-broker") {
			t.Errorf("the broker is meant to have access, don't report it: %+v", g)
		}
	}
	if g, _ := find(r, PodAccess, "Group system:masters"); !g.System {
		t.Error("system:masters should be marked as a system subject")
	}
	if !strings.Contains(checkText(r), "doesn't protect them") || !strings.Contains(checkText(r), "staging") {
		t.Errorf("want the served-but-unprotected staging gap reported:\n%s", checkText(r))
	}
}

func TestNotEnforcing(t *testing.T) {
	cases := map[string]Snapshot{
		"no policy":  func() Snapshot { s := cluster(); s.Policy = nil; return s }(),
		"no binding": func() Snapshot { s := cluster(); s.PolicyBindings = nil; return s }(),
		"audit mode": cluster(admissionv1.Warn, admissionv1.Audit),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			r := Analyze(s)
			if g, _ := find(r, PodAccess, "User alice"); g.Blocked != "" {
				t.Errorf("alice blocked=%q, want not blocked when the policy isn't enforcing", g.Blocked)
			}
			if r.Enforcement[0].OK {
				t.Errorf("first check should fail: %+v", r.Enforcement[0])
			}
		})
	}
}

func TestExemptions(t *testing.T) {
	s := cluster()
	s.Exemptions = nil
	if !strings.Contains(checkText(Analyze(s)), "is missing") {
		t.Error("missing ConfigMap: want it reported")
	}
	s = cluster()
	s.Exemptions.Data["exemptUsers"] = "dave"
	if !strings.Contains(checkText(Analyze(s)), "Break-glass is open") {
		t.Error("exempt user: want break-glass reported")
	}
}

func TestRuleMatching(t *testing.T) {
	cases := []struct {
		name  string
		rule  rbacv1.PolicyRule
		c     Capability
		want  []string
		limit bool
	}{
		{"wildcard subresource", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"*/exec"}, Verbs: []string{"create"}}, PodAccess, []string{"exec"}, false},
		{"named pods only", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}, ResourceNames: []string{"db-0"}}, PodAccess, []string{"exec"}, true},
		{"wrong verb", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"list"}}, PodAccess, nil, false},
		{"wrong group", rbacv1.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"secrets"}, Verbs: []string{"get"}}, Secrets, nil, false},
		{"debug via patch", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/ephemeralcontainers"}, Verbs: []string{"patch"}}, PodAccess, []string{"debug"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			what, limited := grants([]rbacv1.PolicyRule{tc.rule}, tc.c)
			if !slices.Equal(what, tc.want) || limited != tc.limit {
				t.Fatalf("got (%v, %v), want (%v, %v)", what, limited, tc.want, tc.limit)
			}
		})
	}
}

func TestPlatformNotes(t *testing.T) {
	s := cluster()
	s.ProviderIDs = []string{"gce://p/z/n1", "gce://p/z/n2", "aws:///us-east-1a/i-1"}
	notes := strings.Join(Analyze(s).Notes, "\n")
	if strings.Count(notes, "GKE:") != 1 || !strings.Contains(notes, "EKS:") || strings.Contains(notes, "AKS:") {
		t.Fatalf("notes:\n%s", notes)
	}
}

func TestLoad(t *testing.T) {
	cs := fake.NewClientset(&editRole, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}, Spec: corev1.NodeSpec{ProviderID: "kind://docker/kind/n1"}})
	s, err := Load(context.Background(), cs, broker)
	if err != nil {
		t.Fatal(err)
	}
	if s.Policy != nil || s.Exemptions != nil {
		t.Fatalf("nothing installed: want nil policy and exemptions, got %+v %+v", s.Policy, s.Exemptions)
	}
	if len(s.ClusterRoles) != 1 || len(s.Namespaces) != 1 || len(s.ProviderIDs) != 1 {
		t.Fatalf("snapshot = %+v", s)
	}
	if r := Analyze(s); !strings.Contains(checkText(r), "isn't installed") {
		t.Fatalf("want 'not installed' reported:\n%s", checkText(r))
	}
}
