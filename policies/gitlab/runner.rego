package runner_group

# METADATA
# scope: rule
# title: Runner Should Be Restricted To Protected Branches
# description: |
#       This runner is not restricted to protected branches/tags ("Protected" is unchecked).
#       A runner that isn't restricted this way will execute pipelines triggered from *any* branch or merge request,
#       including ones opened from forks of public projects.
#       GitLab's own security guidance recommends restricting runners to protected branches/tags to reduce
#       the risk of a malicious merge request running arbitrary code on shared runner infrastructure:
#       https://docs.gitlab.com/runner/security/
# custom:
#   severity: HIGH
#   remediationSteps:
#     - 1. Go to the group or project's Settings page
#     - 2. Enter the 'CI/CD' tab and expand the 'Runners' section
#     - 3. Edit the runner
#     - 4. Under 'Configuration', check 'Protected' so the runner only runs jobs on protected branches and tags
#   threat:
#     - Runners are often part of the organization's private network and can be easily misconfigured or persistent (not fully ephemeral/isolated per job).
#     - A merge request from a fork of a public project (or any unprotected branch) can trigger a pipeline that runs on this runner.
#     - If the runner isn't restricted to protected branches, the content of that untrusted pipeline controls what code executes on it.
default runner_allows_running_jobs_from_unprotected_branches := true

runner_allows_running_jobs_from_unprotected_branches := false {
	input.access_level == "ref_protected"
}

# METADATA
# scope: rule
# title: Runner Should Be Limited To Specific Projects
# description: |
#       This group/project runner is not locked to specific projects.
#       A runner that isn't locked can be enabled by any Maintainer/Owner of any project it's made available to,
#       including public projects, effectively extending the runner's trust boundary beyond what was intended.
# custom:
#   severity: MEDIUM
#   remediationSteps:
#     - 1. Go to the group or project's Settings page
#     - 2. Enter the 'CI/CD' tab and expand the 'Runners' section
#     - 3. Edit the runner
#     - 4. Under 'Configuration', check 'Lock to current projects'
#   threat:
#     - Runners are often part of the organization's private network and can be easily misconfigured.
#     - A runner that can be freely attached to any project increases the chance it will end up serving an untrusted (e.g. public) project.
default runner_not_limited_to_specific_projects := true

runner_not_limited_to_specific_projects := false {
	input.locked
}

# an instance-wide (shared) runner is deliberately available to every project; "locking"
# doesn't apply to it the way it does to group/project runners, so it's exempted here to
# avoid noise - instance-wide exposure is covered separately by the project-level shared
# runners check.
runner_not_limited_to_specific_projects := false {
	input.runner_type == "instance_type"
}
