package github

import (
	"log"
	"regexp"

	ghcollected "github.com/Legit-Labs/legitify/internal/collected/github"
	"github.com/rhysd/actionlint"
)

// dangerousTriggerEvents lists the GitHub Actions event triggers that run with
// elevated privileges (read/write repo token, access to secrets) even when the
// workflow run was initiated from a fork - unlike the (safe-by-default) plain
// "pull_request" trigger, which always runs with read-only, secret-less permissions
// for fork-originated events.
var dangerousTriggerEvents = map[string]bool{
	"pull_request_target": true,
	"workflow_run":        true,
}

// untrustedForkRefRegex matches expression contexts that resolve to attacker-controlled
// data from a fork: the triggering pull request's head ref/sha/repo (available on
// "pull_request_target"), or the triggering workflow run's head sha/branch/repository
// (available on "workflow_run"). A workflow that feeds one of these into a checkout
// step's "ref"/"repository" input - while triggered by one of the events above - will
// build and potentially execute the fork's code with the privileged token/secrets,
// which is the classic "Pwn Request" pattern.
var untrustedForkRefRegex = regexp.MustCompile(
	`github\.event\.pull_request\.head\.(ref|sha|repo)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch|repository)`,
)

// checkoutActionRegex matches a "uses:" value referencing any version/ref of the
// official actions/checkout action.
var checkoutActionRegex = regexp.MustCompile(`(^|/)actions/checkout@`)

// withDangerousWorkflowTriggers scans the repository's GitHub Actions workflow files
// and records every workflow that combines a privileged trigger (pull_request_target
// or workflow_run) with a checkout step that explicitly checks out the triggering
// fork's untrusted ref/repository - the "Pwn Request" pattern, where code from a fork
// is checked out and (typically in a later step) built/executed with access to the
// privileged workflow token and any configured secrets.
func (rc *repositoryCollector) withDangerousWorkflowTriggers(repo ghcollected.Repository, org string) ghcollected.Repository {
	repo.DangerousWorkflowTriggers = []ghcollected.DangerousWorkflowTrigger{}

	for _, f := range rc.listWorkflowFiles(repo.Name(), org) {
		repo.DangerousWorkflowTriggers = append(repo.DangerousWorkflowTriggers, dangerousTriggersInWorkflow(f.path, f.content)...)
	}

	return repo
}

// dangerousTriggersInWorkflow parses a single workflow file and returns every
// privileged-trigger-plus-untrusted-checkout combination found in it.
func dangerousTriggersInWorkflow(path string, content []byte) []ghcollected.DangerousWorkflowTrigger {
	workflow, errs := actionlint.Parse(content)
	if workflow == nil {
		if len(errs) > 0 {
			log.Printf("failed to parse workflow file %s: %v", path, errs[0])
		}
		return nil
	}

	trigger := dangerousTriggerName(workflow.On)
	if trigger == "" {
		return nil // workflow isn't triggered by pull_request_target/workflow_run at all
	}

	var found []ghcollected.DangerousWorkflowTrigger
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			ref, line, ok := untrustedCheckoutRef(step)
			if !ok {
				continue
			}
			found = append(found, ghcollected.DangerousWorkflowTrigger{
				Path:    path,
				Trigger: trigger,
				Ref:     ref,
				Line:    line,
			})
		}
	}

	return found
}

// dangerousTriggerName returns the name of the first privileged trigger
// (pull_request_target or workflow_run) found among the workflow's "on:" events,
// or an empty string if none of them are present.
func dangerousTriggerName(events []actionlint.Event) string {
	for _, event := range events {
		if dangerousTriggerEvents[event.EventName()] {
			return event.EventName()
		}
	}
	return ""
}

// untrustedCheckoutRef reports whether a step is an actions/checkout step configured
// to check out attacker-controlled data from a fork (via its "ref" or "repository"
// input), returning the offending expression and the line it's on.
func untrustedCheckoutRef(step *actionlint.Step) (ref string, line int, found bool) {
	if step.Exec == nil || step.Exec.Kind() != actionlint.ExecKindAction {
		return "", 0, false
	}
	execAction, ok := step.Exec.(*actionlint.ExecAction)
	if !ok || execAction.Uses == nil || !checkoutActionRegex.MatchString(execAction.Uses.Value) {
		return "", 0, false
	}

	for _, key := range [...]string{"ref", "repository"} {
		input, ok := execAction.Inputs[key]
		if !ok || input.Value == nil || !untrustedForkRefRegex.MatchString(input.Value.Value) {
			continue
		}
		line := 0
		if input.Value.Pos != nil {
			line = input.Value.Pos.Line
		}
		return input.Value.Value, line, true
	}

	return "", 0, false
}
