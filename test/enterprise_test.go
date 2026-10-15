package test

import (
	githubcollected "github.com/Legit-Labs/legitify/internal/collected/github"
	gitlabcollected "github.com/Legit-Labs/legitify/internal/collected/gitlab_collected"
	"github.com/Legit-Labs/legitify/internal/common/namespace"
	"github.com/Legit-Labs/legitify/internal/common/scm_type"
	"testing"

	gitlab2 "github.com/xanzy/go-gitlab"
)

func makeEnterpriseForPolicy(policy string) githubcollected.Enterprise {
	return githubcollected.Enterprise{
		MembersCanChangeRepositoryVisibilitySetting:   policy,
		NotificationDeliveryRestrictionEnabledSetting: policy,
		EnterpriseName: "name",
		Url:            "url",
	}
}

func TestEnterpriseVisibilityChangePolicy(t *testing.T) {
	name := "Enterprise should prevent repositories visibility changes"
	testedPolicyName := "enterprise_not_using_visibility_change_disable_policy"

	policies := map[string]bool{
		"ENABLED":   true,
		"NO_POLICY": true,
		"DISABLED":  false,
	}

	for i := range policies {
		enterpriseTestTemplate(t, name, makeEnterpriseForPolicy(i), testedPolicyName, policies[i], scm_type.GitHub)
	}
}

func TestEnterpriseNotificationRestrictionPolicy(t *testing.T) {
	name := "Enterprise Should Send Email Notifications Only To Verified Domains"
	testedPolicyName := "enable_email_notification_to_verified_domains"

	policies := map[string]bool{
		"ENABLED":   false,
		"NO_POLICY": true,
		"DISABLED":  true,
	}

	for i := range policies {
		enterpriseTestTemplate(t, name, makeEnterpriseForPolicy(i), testedPolicyName, policies[i], scm_type.GitHub)
	}
}

func enterpriseTestTemplate(t *testing.T, name string, mockData githubcollected.Enterprise, testedPolicyName string, expectFailure bool, scmType scm_type.ScmType) {
	ns := namespace.Enterprise
	PolicyTestTemplate(t, name, mockData, ns, testedPolicyName, expectFailure, scmType)
}

func TestGitLabServerPersonalAccessTokenExpirationPolicy(t *testing.T) {
	testedPolicyName := "personal_access_token_expiration_not_enforced"
	ns := namespace.Enterprise

	tests := []struct {
		name             string
		shouldBeViolated bool
		enforced         bool
	}{
		{
			name:             "PAT expiration is enforced",
			shouldBeViolated: false,
			enforced:         true,
		},
		{
			name:             "PAT expiration is not enforced",
			shouldBeViolated: true,
			enforced:         false,
		},
	}

	for _, test := range tests {
		mockData := gitlabcollected.NewServer("https://gitlab.example.com", &gitlab2.Settings{
			EnforcePATExpiration: test.enforced,
		})
		PolicyTestTemplate(t, test.name, mockData, ns, testedPolicyName, test.shouldBeViolated, scm_type.GitLab)
	}
}
