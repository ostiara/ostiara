package doctor

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Load reads what Analyze needs. It takes cluster-wide read access to RBAC, namespaces,
// nodes and admission policies, so run it as an admin.
func Load(ctx context.Context, cs kubernetes.Interface, brokerUser string) (Snapshot, error) {
	s := Snapshot{BrokerUser: brokerUser}
	list := metav1.ListOptions{}
	wrap := func(what string, err error) error {
		if apierrors.IsForbidden(err) {
			return fmt.Errorf("reading %s: forbidden (doctor needs cluster-wide read access; run it as an admin)", what)
		}
		return fmt.Errorf("reading %s: %w", what, err)
	}

	crs, err := cs.RbacV1().ClusterRoles().List(ctx, list)
	if err != nil {
		return s, wrap("clusterroles", err)
	}
	s.ClusterRoles = crs.Items
	rs, err := cs.RbacV1().Roles("").List(ctx, list)
	if err != nil {
		return s, wrap("roles", err)
	}
	s.Roles = rs.Items
	crbs, err := cs.RbacV1().ClusterRoleBindings().List(ctx, list)
	if err != nil {
		return s, wrap("clusterrolebindings", err)
	}
	s.ClusterRoleBindings = crbs.Items
	rbs, err := cs.RbacV1().RoleBindings("").List(ctx, list)
	if err != nil {
		return s, wrap("rolebindings", err)
	}
	s.RoleBindings = rbs.Items
	nss, err := cs.CoreV1().Namespaces().List(ctx, list)
	if err != nil {
		return s, wrap("namespaces", err)
	}
	s.Namespaces = nss.Items

	nodes, err := cs.CoreV1().Nodes().List(ctx, list)
	if err != nil {
		return s, wrap("nodes", err)
	}
	for _, n := range nodes.Items {
		s.ProviderIDs = append(s.ProviderIDs, n.Spec.ProviderID)
	}

	policy, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, PolicyName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		return s, wrap("validatingadmissionpolicies", err)
	default:
		s.Policy = policy
	}
	bindings, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(ctx, list)
	if err != nil {
		return s, wrap("validatingadmissionpolicybindings", err)
	}
	s.PolicyBindings = bindings.Items

	cm, err := cs.CoreV1().ConfigMaps("ostiara-system").Get(ctx, ExemptionsName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		return s, wrap("configmap ostiara-system/"+ExemptionsName, err)
	default:
		s.Exemptions = cm
	}
	return s, nil
}
