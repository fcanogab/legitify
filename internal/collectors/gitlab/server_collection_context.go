package gitlab

import (
	"github.com/Legit-Labs/legitify/internal/common/permissions"
)

type serverCollectionContext struct {
}

func newServerCollectionContext() serverCollectionContext {
	return serverCollectionContext{}
}

func (c serverCollectionContext) Premium() bool {
	return true
}

// Ultimate is conservatively assumed true: there is currently no license-tier detection
// for self-managed instance-wide settings (see Premium() above), so instance-level checks
// that require Ultimate are not skipped here either.
func (c serverCollectionContext) Ultimate() bool {
	return true
}

func (c serverCollectionContext) Roles() []permissions.Role {
	return []permissions.Role{permissions.OrgRoleOwner}
}
