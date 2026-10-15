package collectors

import (
	"github.com/Legit-Labs/legitify/cmd/progressbar"
	"github.com/Legit-Labs/legitify/internal/collected"
	"github.com/Legit-Labs/legitify/internal/common/namespace"
	"github.com/Legit-Labs/legitify/internal/common/permissions"
)

type CollectedDataContext interface {
	Premium() bool
	// Ultimate reports whether the entity's plan grants access to GitLab Ultimate-only
	// features (e.g. audit event streaming). It has no meaning on GitHub, where
	// implementers simply mirror Premium().
	Ultimate() bool
	Roles() []permissions.Role
}

type CollectedDataRepositoryContext interface {
	CollectedDataContext
	HasBranchProtectionPermission() bool
	HasGithubAdvancedSecurity() bool
}

type CollectedData struct {
	Context       CollectedDataContext
	Entity        collected.Entity
	Namespace     namespace.Namespace
	CanonicalLink string
}

type SubCollectorChannels struct {
	Collected         <-chan CollectedData
	Progress          <-chan progressbar.ChannelType
	MissingPermission <-chan MissingPermission
}

type Collector interface {
	Collect() SubCollectorChannels
	Namespace() namespace.Namespace
	CollectTotalEntities() int
}
