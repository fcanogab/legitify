package test

import (
	"github.com/Legit-Labs/legitify/internal/common/scm_type"
	"testing"

	githubcollected "github.com/Legit-Labs/legitify/internal/collected/github"
	gitlabcollected "github.com/Legit-Labs/legitify/internal/collected/gitlab_collected"
	"github.com/Legit-Labs/legitify/internal/common/namespace"
	"github.com/google/go-github/v53/github"
	gitlab2 "github.com/xanzy/go-gitlab"
)

type runnerGroupMockConfiguration struct {
	allowedByPublic bool
}

func newRunnerGroupMock(config runnerGroupMockConfiguration) githubcollected.RunnerGroup {
	return githubcollected.RunnerGroup{
		Organization: defaultOrg,
		RunnerGroup: &github.RunnerGroup{
			AllowsPublicRepositories: &config.allowedByPublic,
		},
	}
}

func TestRunnerGroup(t *testing.T) {
	tests := []struct {
		name             string
		policyName       string
		scmType          scm_type.ScmType
		shouldBeViolated bool
		args             runnerGroupMockConfiguration
	}{
		{
			name:             "runner group is allowed to run by public repositories",
			policyName:       "runner_group_can_be_used_by_public_repositories",
			scmType:          scm_type.GitHub,
			shouldBeViolated: true,
			args: runnerGroupMockConfiguration{
				allowedByPublic: true,
			},
		},
		{
			name:             "runner group is not allowed to run by public repositoreis",
			policyName:       "runner_group_can_be_used_by_public_repositories",
			scmType:          scm_type.GitHub,
			shouldBeViolated: false,
			args: runnerGroupMockConfiguration{
				allowedByPublic: false,
			},
		},
	}

	for _, test := range tests {
		PolicyTestTemplate(t, test.name, newRunnerGroupMock(test.args),
			namespace.RunnerGroup, test.policyName, test.shouldBeViolated, test.scmType)
	}
}

func newGitlabRunnerMock(accessLevel string, locked bool, runnerType string) gitlabcollected.Runner {
	return gitlabcollected.Runner{
		RunnerDetails: &gitlab2.RunnerDetails{
			AccessLevel: accessLevel,
			Locked:      locked,
			RunnerType:  runnerType,
		},
	}
}

func TestGitlabRunnerAllowsRunningJobsFromUnprotectedBranches(t *testing.T) {
	testedPolicyName := "runner_allows_running_jobs_from_unprotected_branches"

	tests := []struct {
		name             string
		accessLevel      string
		shouldBeViolated bool
	}{
		{
			name:             "runner is restricted to protected branches",
			accessLevel:      "ref_protected",
			shouldBeViolated: false,
		},
		{
			name:             "runner is not restricted to protected branches",
			accessLevel:      "not_protected",
			shouldBeViolated: true,
		},
	}

	for _, test := range tests {
		PolicyTestTemplate(t, test.name, newGitlabRunnerMock(test.accessLevel, false, "project_type"),
			namespace.RunnerGroup, testedPolicyName, test.shouldBeViolated, scm_type.GitLab)
	}
}

func TestGitlabRunnerNotLimitedToSpecificProjects(t *testing.T) {
	testedPolicyName := "runner_not_limited_to_specific_projects"

	tests := []struct {
		name             string
		locked           bool
		runnerType       string
		shouldBeViolated bool
	}{
		{
			name:             "project runner locked to specific projects",
			locked:           true,
			runnerType:       "project_type",
			shouldBeViolated: false,
		},
		{
			name:             "project runner not locked to specific projects",
			locked:           false,
			runnerType:       "project_type",
			shouldBeViolated: true,
		},
		{
			name:             "group runner not locked to specific projects",
			locked:           false,
			runnerType:       "group_type",
			shouldBeViolated: true,
		},
		{
			name:             "instance-wide shared runner is exempt regardless of locked",
			locked:           false,
			runnerType:       "instance_type",
			shouldBeViolated: false,
		},
	}

	for _, test := range tests {
		PolicyTestTemplate(t, test.name, newGitlabRunnerMock("ref_protected", test.locked, test.runnerType),
			namespace.RunnerGroup, testedPolicyName, test.shouldBeViolated, scm_type.GitLab)
	}
}
