package github

import "github.com/Legit-Labs/legitify/internal/common/permissions"

type enterpriseContext struct {
	roles []permissions.Role
}

func (ec *enterpriseContext) Premium() bool {
	return true
}

// Ultimate is not a meaningful distinction on GitHub; mirror Premium() so the
// "ultimate" prerequisite (used only by GitLab policies) is a no-op here.
func (ec *enterpriseContext) Ultimate() bool {
	return true
}

func (ec *enterpriseContext) Roles() []permissions.Role {
	return ec.roles
}
func newEnterpriseContext(roles []permissions.Role) *enterpriseContext {
	return &enterpriseContext{
		roles: roles,
	}
}
