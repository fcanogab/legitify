package repository

# METADATA
# scope: rule
# title: Project Should Be Updated At Least Quarterly
# description: A project which is not actively maintained may not be patched against security issues within its code and dependencies, and is therefore at higher risk of including known vulnerabilities.
# custom:
#   remediationSteps:
#     - 1. Make sure you have admin permissions
#     - 2. Either Delete or Archive the project
#   severity: HIGH
#   threat: As new vulnerabilities are found over time, unmaintained repositories are more likely to point to dependencies that have known vulnerabilities, exposing these repositories to 1-day attacks.
default project_not_maintained := true

project_not_maintained := false {
	input.archived == false
	ns := time.parse_rfc3339_ns(input.last_activity_at)
	now := time.now_ns()
	diff := time.diff(now, ns)
	monthsIndex := 1
	inactivityMonthsThreshold := 3
	diff[monthsIndex] < inactivityMonthsThreshold
	yearIndex := 0
	diff[yearIndex] == 0
}

# METADATA
# scope: rule
# title: Project Should Have A Low Owner Count
# description: Projects owners are highly privileged and could create great damage if they are compromised. It is recommended to limit the number of Project Owners to the minimum required, and no more than 5% of the userbase (Up to 3 owners are always allowed).
# custom:
#   severity: LOW
#   remediationSteps:
#     - 1. Make sure you have owner permissions
#     - 2. Go to the Project Information -> Members page
#     - 3. Select the unwanted owner users and remove the selected owners
#   threat:
#     - A compromised user with owner permissions can initiate a supply chain attack in a plethora of ways.
#     - Having many admin users increases the overall risk of user compromise, and makes it more likely to lose track of unused admin permissions given to users in the past.
default project_has_too_many_admins := true

project_has_too_many_admins := false {
	admins := [admin | admin := input.members[_]; admin.access_level == 50]
	adminNum := count(admins)
	userNum := count(input.members)
	maxAdmins := max([3, ceil(userNum * 0.05)])
	adminNum <= maxAdmins
}

# METADATA
# scope: rule
# title: Forking Should Not Be Allowed for Private/Internal Projects
# description: Forking a project (repository) can lead to loss of control and potential exposure of source code. If you do not need forking, it is recommended to turn it off in the project or group configuration. The option to fork should be enabled only by owners deliberately when opting to create a fork.
# custom:
#   remediationSteps:
#     - 1. Make sure you have owner permissions
#     - 2. Go to the project's settings page
#     - 3. Enter 'General' tab
#     - 4. Under 'Visibility, project features, permissions', Toggle off 'Forks'
#   severity: LOW
#   threat: Forked repositories may leak important code assets or sensitive secrets embedded in the code to anyone outside your organization, as the code becomes publicly accessible.
default forking_allowed_for_repository := true

forking_allowed_for_repository := false {
	input.public
}

forking_allowed_for_repository := false {
	not input.public
	input.forking_access_level != "enabled"
}

# METADATA
# scope: rule
# title: Default Branch Should Be Protected
# description: Branch protection is not enabled for this repository’s default branch. Protecting branches ensures new code changes must go through a controlled merge process and allows enforcement of code review as well as other security tests. This issue is raised if the default branch protection is turned off.
# custom:
#   remediationSteps:
#     - 1. Make sure you have owner permissions
#     - 2. Go to the project's settings -> Repository page
#     - 3. Enter 'Protected branches' tab
#     - 4. Select the default branch
#     - 5. Set the allowed to merge to 'maintainers' and the allowed to push to 'No one'
#   severity: MEDIUM
#   prerequisites: [premium]
#   threat: Any contributor with write access may push potentially dangerous code to this repository, making it easier to compromise and difficult to audit.
default missing_default_branch_protection := true

missing_default_branch_protection := false {
	default_protected_branches := [protected_branch | protected_branch := input.protected_branches[_]; protected_branch.name == input.default_branch]
	count(default_protected_branches) > 0
}

# METADATA
# scope: rule
# title: Default Branch Should Not Allow Force Pushes
# description: The history of the default branch is not protected against changes for this repository. Protecting branch history ensures every change that was made to code can be retained and later examined. This issue is raised if the default branch history can be modified using force push.
# custom:
#   remediationSteps:
#     - 1. Make sure you have owner permissions
#     - 2. Go to the project's settings -> Repository page
#     - 3. Enter 'Protected branches' tab
#     - 4. Select the default branch
#     - 5. Set the allowed to merge to 'maintainers' and the allowed to push to 'No one'
#   severity: MEDIUM
#   prerequisites: [premium]
#   threat: Rewriting project history can make it difficult to trace back when bugs or security issues were introduced, making them more difficult to remediate.
default missing_default_branch_protection_force_push := true

missing_default_branch_protection_force_push := false {

    default_protected_branches := [protected_branch | protected_branch := input.protected_branches[_]; protected_branch.name == input.default_branch]
	count(default_protected_branches) > 0
	rules_allow_force_push := [rule_allow_force_push | rule_allow_force_push := default_protected_branches[_]; rule_allow_force_push.allow_force_push == true]
	count(rules_allow_force_push) == 0
}

# METADATA
# scope: rule
# title: Default Branch Should Limit Code Review to Code-Owners
# description: It is recommended to require code review only from designated individuals specified in CODEOWNERS file. Turning this option on enforces that only the allowed owners can approve a code change. This option is found in the branch protection setting of the project.
# custom:
#   remediationSteps:
#     - 1. Make sure you have owner permissions
#     - 2. Go to the project's settings -> Repository page
#     - 3. Enter 'Protected branches' tab
#     - 4. Select the default branch
#     - 5. Check the 'Code owner approval'
#   severity: LOW
#   prerequisites: [premium]
#   threat: A pull request may be approved by any contributor with write access. Specifying specific code owners can ensure review is only done by individuals with the correct expertise required for the review of the changed files, potentially preventing bugs and security risks.
default repository_require_code_owner_reviews_policy := true

repository_require_code_owner_reviews_policy := false {
	default_protected_branches := [protected_branch | protected_branch := input.protected_branches[_]; protected_branch.name == input.default_branch]
	rules_allow_force_push := [ rule_require_code_owner_review | rule_require_code_owner_review := default_protected_branches[_]; rule_require_code_owner_review.code_owner_approval_required ]
	count(rules_allow_force_push) > 0
}

# METADATA
# scope: rule
# title: Webhook Configured Without SSL Verification
# description: Webhooks that are not configured with SSL verification enabled could expose your software to man-in-the-middle attacks (MITM).
# custom:
#   severity: LOW
#   remediationSteps:
#     - 1. Make sure you can manage webhooks for the project
#     - 2. Go to the project's settings page
#     - 3. Select 'Webhooks'
#     - 4. Press on the 'Enable SSL verification'
#     - 5. Click 'Save changes'
#   threat:
#     - If SSL verification is disabled, any party with access to the target DNS domain can masquerade as your designated payload URL, allowing it to freely read and affect the response of any webhook request.
#     - In the case of GitLab Self-Managed, it may be sufficient only to control the DNS configuration of the network where the instance is deployed, as an attacker can redirect traffic to the target domain in your internal network directly to them, and this is often much easier than compromising an internet-facing domain.
default project_webhook_doesnt_require_ssl := true

project_webhook_doesnt_require_ssl := false{
	webhooks_without_ssl_verification := [webhook_without_verification | webhook_without_verification := input.webhooks[_]; webhook_without_verification.enable_ssl_verification == false]
	count(webhooks_without_ssl_verification) == 0
}

# METADATA
# scope: rule
# title: Project Should Require All Pipelines to Succeed
# description: Checks that validate the quality and security of the code are not required to pass before submitting new changes. It is advised to turn this flag on to ensure any existing or future check will be required to pass.
# custom:
#   severity: MEDIUM
#   remediationSteps:
#     - 1. Make sure you can manage project merge requests permissions
#     - 2. Go to the project's settings page
#     - 3. Select 'Merge Requests'
#     - 4. Press on the 'Pipelines must succeed'
#     - 5. Click 'Save changes'
#   threat: Not defining a set of required status checks can make it easy for contributors to introduce buggy or insecure code as manual review, whether mandated or optional, is the only line of defense.
default requires_status_checks := true

requires_status_checks := false {
	input.only_allow_merge_if_pipeline_succeeds
}

# METADATA
# scope: rule
# title: Project Should Require All Conversations To Be Resolved Before Merge
# description: Require all merge request conversations to be resolved before merging. Check this to avoid bypassing/missing a Pull Request comment.
# custom:
#   severity: LOW
#   remediationSteps:
#     - 1. Make sure you can manage project merge requests permissions
#     - 2. Go to the project's settings page
#     - 3. Select 'Merge Requests'
#     - 4. Press on the 'All threads must be resolved'
#     - 5. Click 'Save changes'
#   threat: Allowing the merging of code without resolving all conversations can promote poor and vulnerable code, as important comments may be forgotten or deliberately ignored when the code is merged.
default no_conversation_resolution := true

no_conversation_resolution := false {
	input.only_allow_merge_if_all_discussions_are_resolved
}

# METADATA
# scope: rule
# title: Default Branch Should Require All Commits To Be Signed
# description: Require all commits to be signed and verified
# custom:
#   remediationSteps:
#     - 1. Make sure you have owner permissions
#     - 2. Go to the project's settings -> Repository page
#     - 3. Enter 'Push Rules' tab
#     - 4. Set the 'Reject unsigned commits' checkbox
#   severity: LOW
#   prerequisites: [premium]
#   threat: A commit containing malicious code may be crafted by a malicious actor that has acquired write access to the repository to initiate a supply chain attack. Commit signing provides another layer of defense that can prevent this type of compromise.
default no_signed_commits := true

no_signed_commits := false {
	input.push_rules.reject_unsigned_commits
}


# METADATA
# scope: rule
# title: Default Branch Should Require Code Review
# description: In order to comply with separation of duties principle and enforce secure code practices, a code review should be mandatory using the source-code-management built-in enforcement.
# custom:
#   remediationSteps:
#     - 1. Make sure you have admin permissions
#     - 2. Go to the repo's settings page
#     - 3. Enter 'Merge Requests' tab
#     - 4. Under 'Merge request approvals', Click 'Add approval rule' on the default branch rule
#     - 5. Select 'Approvals required' and enter at least 1 approvers
#     - 6. Select 'Add approvers' and select the desired members
#     - 7. Click 'Add approval rule'
#   severity: HIGH
#   prerequisites: [premium]
#   threat:
#     - Users can merge code without being reviewed which can lead to insecure code reaching the main branch and production.
default code_review_not_required := true

code_review_not_required := false {
	input.minimum_required_approvals >= 1
}

# METADATA
# scope: rule
# title: Default Branch Should Require Code Review By At Least Two Reviewers
# description: In order to comply with separation of duties principle and enforce secure code practices, a code review should be mandatory using the source-code-management built-in enforcement.
# custom:
#   remediationSteps:
#     - 1. Make sure you have admin permissions
#     - 2. Go to the repo's settings page
#     - 3. Enter 'Merge Requests' tab
#     - 4. Under 'Merge request approvals', Click 'Add approval rule' on the default branch rule
#     - 5. Select 'Approvals required' and enter at least 2 approvers
#     - 6. Select 'Add approvers' and select the desired members
#     - 7. Click 'Add approval rule'
#   severity: MEDIUM
#   prerequisites: [premium]
#   threat:
#     - Users can merge code without being reviewed which can lead to insecure code reaching the main branch and production.
default code_review_by_two_members_not_required := true

code_review_by_two_members_not_required := false {
	input.minimum_required_approvals >= 2
}

# METADATA
# scope: rule
# title: Repository Should Not Allow Review Requester To Approve Their Own Request
# description: To comply with separation of duties and enforce secure code practices, the repository should prohibit pull request owners from approving their own changes.
# custom:
#   remediationSteps:
#     - 1. Make sure you have admin permissions
#     - 2. Go to the repo's settings page
#     - 3. Enter 'Merge Requests' tab
#     - 4. Under 'Approval settings', Check 'Prevent approval by author'
#     - 5. Click 'Save Changes'
#   severity: MEDIUM
#   threat:
#     - Users can merge code without being reviewed which can lead to insecure code reaching the main branch and production.
default repository_allows_review_requester_to_approve_their_own_request := true

repository_allows_review_requester_to_approve_their_own_request := false {
	not input.approval_configuration.merge_requests_author_approval
}

# METADATA
# scope: rule
# title: Merge Request Authors Should Not Be Able To Override the Approvers List
# description: A repository should not allow merge request authors to freely edit the list of required approvers. To enforce code review only by authorized personnel, the option to override the list of valid approvers for the merge request must be toggled off.
# custom:
#   remediationSteps:
#     - 1. Make sure you have admin permissions
#     - 2. Go to the repo's settings page
#     - 3. Enter 'Merge Requests' tab
#     - 4. Under 'Approval settings', Check 'Prevent editing approval rules in merge requests'
#     - 5. Click 'Save Changes'
#   severity: MEDIUM
#   prerequisites: [premium]
#   threat:
#     - Users can merge code without being reviewed which can lead to insecure code reaching the main branch and production.
default repository_allows_overriding_approvers := true

repository_allows_overriding_approvers := false {
	input.approval_configuration.disable_overriding_approvers_per_merge_request
}

# METADATA
# scope: rule
# title: Repository Should Not Allow Committer Approvals
# description: The repository allows merge request contributors (that aren't the merge request author), to approve the merge request. To ensure merge request review is done objectively, it is recommended to toggle this option off.
# custom:
#   remediationSteps:
#     - 1. Make sure you have admin permissions
#     - 2. Go to the repo's settings page
#     - 3. Enter 'Merge Requests' tab
#     - 4. Under 'Approval settings', Check 'Prevent approvals by users who add commits'
#     - 5. Click 'Save Changes'
#   severity: LOW
#   prerequisites: [premium]
#   threat:
#     - Users can merge code without being reviewed which can lead to insecure code reaching the main branch and production.
default repository_allows_committer_approvals_policy := true

repository_allows_committer_approvals_policy := false {
	input.approval_configuration.merge_requests_disable_committers_approval
}

# METADATA
# scope: rule
# title: Default Branch Should Require New Code Changes After Approval To Be Re-Approved
# description: This security control prevents merging code that was approved but later on changed. Turning it on ensures new changes are required to be reviewed again. This setting is part of the Merge request approval settings, and hardens the code-review process. If turned off - a developer can change the code after approval, and push code that is different from the one that was previously allowed.
# custom:
#   remediationSteps:
#     - 1. Make sure you have admin permissions
#     - 2. Go to the repo's settings page
#     - 3. Enter 'Merge Requests' tab
#     - 4. Under 'Approval settings', Check 'Remove all approvals'
#     - 5. Click 'Save Changes'
#   severity: LOW
#   prerequisites: [premium]
#   threat: Buggy or insecure code may be committed after approval and will reach the main branch without review. Alternatively, an attacker can attempt a just-in-time attack to introduce dangerous code just before merge.
default repository_dismiss_stale_reviews := true

repository_dismiss_stale_reviews := false {
	input.approval_configuration.reset_approvals_on_push
}

# METADATA
# scope: rule
# title: Overriding predefined CI/CD variables should be restricted.
# description: It’s recommended to restrict users with low privileges from overriding predefined variables, as doing so could compromise the security and integrity of the CI/CD pipeline.
# custom:
#   remediationSteps:
#     - 1. Make sure you have owner or maintainer permissions
#     - 2. The remediation is available through the project's API (e.g., 'https://gitlab.com/api/v4/projects/<your-project-ID>')
#     - 3. Set the 'restrict_user_defined_variables' attribute to TRUE (this attribute is FALSE by default)
#     - 4. When 'restrict_user_defined_variables' is enabled, you can specify which role can override variables. This is done by setting the 'ci_pipeline_variables_minimum_override_role' attribute to one of: owner, maintainer, developer or no_one_allowed.
#     - 5. For more information, you can check out gitlab's API documentation: https://docs.gitlab.com/ee/api/projects.html
#   severity: LOW
#   threat: Allowing overrides of predefined variables can result in unintentional misconfigurations of the CI/CD pipeline or deliberate tampering.
default overriding_defined_variables_isnt_restricted := true

overriding_defined_variables_isnt_restricted := false {
	input.restrict_user_defined_variables
}

# METADATA
# scope: rule
# title: Project Should Have Automated Dependency Updates Enabled
# description: Enable an automated dependency-update tool (such as Renovate) to regularly scan for and patch outdated or vulnerable dependencies. This check looks for a Renovate configuration file in the repository, or for branches created by Renovate (e.g. a centrally/self-hosted configured instance with no local config file).
# custom:
#   remediationSteps:
#     - 1. Add a renovate.json (or .gitlab/renovate.json) configuration file to the repository, following https://docs.renovatebot.com/configuration-options/
#     - 2. Alternatively, onboard the repository to a self-hosted or centrally configured Renovate instance
#   severity: MEDIUM
#   threat: Outdated dependencies may contain known vulnerabilities that remain unpatched without an automated update process, exposing the repository to 1-day attacks.
default renovate_not_enabled := true

renovate_not_enabled := false {
	input.renovate_config_path != ""
}

renovate_not_enabled := false {
	count(input.renovate_branches) > 0
}

# METADATA
# scope: rule
# title: Secret Push Protection Should Be Enabled
# description: >
#     Secret push protection is not enabled for this project. When enabled, GitLab scans the content of each push for high-confidence secrets (such as API keys and tokens) and blocks the push if any are detected, reducing the risk of secrets being leaked into the repository's history. On GitLab Self-Managed/Dedicated, secret push protection must additionally be allowed on the instance before it can be enabled per-project, and for private projects it currently requires a GitLab Ultimate license (it is enabled by default for public projects on all tiers).
# custom:
#   remediationSteps:
#     - 1. Enter your project's landing page
#     - 2. Go to the left sidebar and select 'Secure' -> 'Security configuration'
#     - 3. Turn on 'Secret push protection'
#   severity: MEDIUM
#   threat: Exposed secrets increase the risk of sensitive information such as API keys, passwords, and tokens being disclosed, leading to unauthorized access to systems and services, and data breaches.
default secret_push_protection_not_enabled := true

secret_push_protection_not_enabled := false {
	input.secret_push_protection_enabled
}

# METADATA
# scope: rule
# title: CI/CD Includes Should Be Pinned To A Full Length Commit SHA
# description: >
#     This project's CI/CD configuration (or one of its local includes) references an external project, CI/CD component, or remote file without pinning it to a full-length commit SHA. A floating branch/tag can be repointed by its maintainer - or by an attacker who compromises their account - to different, potentially malicious, content without any corresponding change in this project, silently altering what runs in your pipeline. Remote (`include: remote:`) includes are flagged unconditionally, since they aren't backed by a Git ref and can never be pinned to a commit.
# custom:
#   remediationSteps:
#     - 1. Open the flagged CI/CD configuration file
#     - 2. For 'project' includes, replace the 'ref' with the full-length commit SHA it currently points to
#     - 3. For 'component' includes, replace the version suffix (after the last '@') with the full-length commit SHA it currently points to
#     - 4. For 'remote' includes, consider vendoring the file locally (so it's versioned with your own commits) instead of fetching it from an external URL
#   severity: MEDIUM
#   threat: A compromised or malicious maintainer of an included project, component, or remote file can repoint a mutable reference to arbitrary pipeline configuration, which would then run with the permissions of the pipeline (including access to CI/CD variables and secrets) on every subsequent run, without this project's owners reviewing a code change.
default ci_includes_not_pinned_to_full_length_commit_sha := true

ci_includes_not_pinned_to_full_length_commit_sha := false {
	is_array(input.unpinned_ci_includes)
	count(input.unpinned_ci_includes) == 0
}

# METADATA
# scope: rule
# title: Public Projects Should Not Use Shared Runners
# description: |
#       Shared runners (instance-wide or group-wide) are enabled for this public project.
#       Anyone can open a merge request against a public project - including unauthenticated users via a fork -
#       and its pipeline will run on the same runners used by the rest of the group/instance.
#       GitLab's own security guidance recommends against using shared runners for public projects for this reason:
#       https://docs.gitlab.com/runner/security/
# custom:
#   severity: HIGH
#   remediationSteps:
#     - 1. Go to the project's Settings page
#     - 2. Enter the 'CI/CD' tab
#     - 3. Expand the 'Runners' section
#     - 4. Toggle off 'Enable shared runners for this project'
#   threat:
#     - Shared runners are often part of the organization's private network and can be easily misconfigured or persistent (not fully ephemeral/isolated per job).
#     - Any user - including anonymous users forking a public project - can open a merge request whose pipeline executes on these shared runners.
#     - If the runner isn't properly isolated, this can be used to steal CI/CD secrets or pivot into the organization's internal network.
default project_allows_public_fork_to_use_shared_runners := true

project_allows_public_fork_to_use_shared_runners := false {
	not input.public
}

project_allows_public_fork_to_use_shared_runners := false {
	not input.shared_runners_enabled
}

# METADATA
# scope: rule
# title: Fork Merge Request Pipelines Should Not Run In The Parent Project
# description: >
#     This project allows pipelines for merge requests from forked projects to be run in the context of this (parent) project, instead of the fork's own context. GitLab enables this setting by default. When enabled, a maintainer of this project can choose to run a fork's merge request pipeline "in the parent project", which grants that pipeline access to this project's protected CI/CD variables and runners - the same privileged context a push to this project would get - even though the pipeline's code (the '.gitlab-ci.yml' and the branch it runs on) comes entirely from the external fork. This is the GitLab equivalent of GitHub's "Pwn Request" pattern: untrusted, fork-originated pipeline code running with privileged, secret-bearing access.
# custom:
#   remediationSteps:
#     - 1. Make sure you have at least Maintainer access to the project
#     - 2. Using the GitLab API, send a 'PUT' request to '/projects/:id' with 'ci_allow_fork_pipelines_to_run_in_parent_project=false' (there is currently no dedicated UI toggle for this setting)
#     - 3. Verify the change by sending a 'GET' request to '/projects/:id' and confirming 'ci_allow_fork_pipelines_to_run_in_parent_project' is 'false'
#   severity: HIGH
#   requiredScopes: [api]
#   threat:
#     - This misconfiguration could lead to the following attack:
#     - 1. Attacker forks the project and opens a merge request with a malicious change to the pipeline configuration or to code executed by it (e.g. a build script)
#     - 2. A maintainer (or, in some configurations, any user) chooses to run the merge request's pipeline in the parent project's context
#     - 3. The pipeline runs with access to the parent project's protected CI/CD variables/secrets and its runners
#     - 4. The attacker's payload exfiltrates those secrets, or uses the runner's access to pivot further into the organization's infrastructure
default fork_merge_request_pipelines_can_run_in_parent_project := true

fork_merge_request_pipelines_can_run_in_parent_project := false {
	not input.ci_allow_fork_pipelines_to_run_in_parent_project
}
