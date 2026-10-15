package gitlab_collected

import (
	"github.com/Legit-Labs/legitify/internal/common/namespace"
	gitlab2 "github.com/xanzy/go-gitlab"
)

type Repository struct {
	*gitlab2.Project
	Members                     []*gitlab2.ProjectMember       `json:"members,omitempty"`
	ProtectedBranches           []*gitlab2.ProtectedBranch     `json:"protected_branches"`
	Webhooks                    []*gitlab2.ProjectHook         `json:"webhooks"`
	PushRules                   *gitlab2.ProjectPushRules      `json:"push_rules"`
	ApprovalConfiguration       *gitlab2.ProjectApprovals      `json:"approval_configuration"`
	ApprovalRules               []*gitlab2.ProjectApprovalRule `json:"approval_rules"`
	MinimumRequiredApprovals    int                            `json:"minimum_required_approvals"`
	RenovateConfigPath          string                         `json:"renovate_config_path,omitempty"`
	RenovateBranches            []string                       `json:"renovate_branches,omitempty"`
	SecretPushProtectionEnabled *bool                          `json:"secret_push_protection_enabled,omitempty"`
	UnpinnedCIIncludes          []UnpinnedCIInclude            `json:"unpinned_ci_includes"`
}

// UnpinnedCIInclude represents a single external `include:` entry in a project's CI/CD
// configuration (or one of its local includes) that isn't pinned to an immutable
// reference - either a GitLab CI/CD component or project template referenced by a
// floating branch/tag rather than a full-length commit SHA, or a `remote:` include,
// which can never be pinned to a commit since it isn't backed by a Git ref at all.
type UnpinnedCIInclude struct {
	SourceFile string `json:"source_file"`
	Type       string `json:"type"` // "project", "remote", or "component"
	Reference  string `json:"reference"`
}

func (r Repository) ViolationEntityType() string {
	return namespace.Repository
}

func (r Repository) CanonicalLink() string {
	return r.Project.WebURL
}

func (r Repository) Name() string {
	return r.Project.Name
}

func (r Repository) ID() int64 {
	return int64(r.Project.ID)
}
