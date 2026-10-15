package gitlab_collected

import (
	"fmt"
	"strings"

	gitlab2 "github.com/xanzy/go-gitlab"
)

// Runner represents a GitLab CI/CD runner - either an instance-wide ("shared") runner, or
// one scoped to a specific group or project - together with enough context to build a
// canonical link back to where it's managed.
//
// Unlike GitHub, which groups self-hosted runners into "runner groups" with an explicit
// "allow public repositories" toggle, GitLab exposes the equivalent risk controls directly
// on the runner itself: Locked (restrict the runner to specific projects) and AccessLevel
// (restrict the runner to protected branches/tags only). See RunnerDetails in
// github.com/xanzy/go-gitlab for the full set of available fields.
type Runner struct {
	*gitlab2.RunnerDetails
	// OwnerWebURL is the web URL of the group or project under which this runner was
	// discovered (empty for instance-wide runners discovered via the admin API, in which
	// case InstanceURL is used instead to build a fallback admin link).
	OwnerWebURL string `json:"-"`
	// InstanceURL is the base URL of the GitLab instance (empty for GitLab.com).
	InstanceURL string `json:"-"`
}

func (r Runner) ViolationEntityType() string {
	return "runner"
}

func (r Runner) CanonicalLink() string {
	if r.OwnerWebURL != "" {
		return fmt.Sprintf("%s/-/settings/ci_cd#js-runners-settings", strings.TrimRight(r.OwnerWebURL, "/"))
	}

	base := r.InstanceURL
	if base == "" {
		base = "https://gitlab.com"
	}
	return fmt.Sprintf("%s/admin/runners/%d", strings.TrimRight(base, "/"), r.RunnerDetails.ID)
}

func (r Runner) Name() string {
	if r.RunnerDetails.Description != "" {
		return r.RunnerDetails.Description
	}
	return fmt.Sprintf("runner-%d", r.RunnerDetails.ID)
}

func (r Runner) ID() int64 {
	return int64(r.RunnerDetails.ID)
}
