package gitlab

import (
	"github.com/Legit-Labs/legitify/internal/common/permissions"
	"github.com/xanzy/go-gitlab"
)

type collectionContext struct {
	group      *gitlab.Group
	roles      []permissions.Role
	isPremium  bool
	isUltimate bool
}

func newCollectionContext(group *gitlab.Group, roles []permissions.Role, isPremium bool, isUltimate bool) collectionContext {
	return collectionContext{
		group:      group,
		roles:      roles,
		isPremium:  isPremium,
		isUltimate: isUltimate,
	}
}

func (c collectionContext) Premium() bool {
	return c.isPremium
}

func (c collectionContext) Ultimate() bool {
	return c.isUltimate
}

func (c collectionContext) Roles() []permissions.Role {
	return c.roles
}
