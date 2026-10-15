package github

import (
	"log"
	"net/http"
	"regexp"
	"strings"

	ghcollected "github.com/Legit-Labs/legitify/internal/collected/github"
	"github.com/rhysd/actionlint"
)

// pinnedActionRegex matches a "uses:" reference pinned to a full-length commit SHA,
// either a plain 40+ character hex SHA (e.g. "actions/checkout@8f4b7f84...") or a
// Docker digest reference (e.g. "docker://alpine@sha256:<64 hex chars>").
var pinnedActionRegex = regexp.MustCompile(`@([a-fA-F0-9]{40,}|sha256:[a-fA-F0-9]{64})$`)

// isActionPinned reports whether a workflow "uses:" value is pinned to an immutable
// reference. Actions defined in the same repository ("./path/to/action") are always
// considered pinned, since they resolve to the same commit as the workflow itself.
func isActionPinned(uses string) bool {
	if strings.HasPrefix(uses, "./") {
		return true
	}
	return pinnedActionRegex.MatchString(uses)
}

// withUnpinnedActions scans the repository's GitHub Actions workflow files
// (.github/workflows/*) and records every action/reusable-workflow reference that
// isn't pinned to a full-length commit SHA.
func (rc *repositoryCollector) withUnpinnedActions(repo ghcollected.Repository, org string) ghcollected.Repository {
	repo.UnpinnedActions = []ghcollected.UnpinnedAction{}

	const workflowsDir = ".github/workflows"
	_, dirContents, resp, err := rc.Client.Client().Repositories.GetContents(rc.Context, org, repo.Name(), workflowsDir, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return repo // no workflows directory - nothing to check
		}
		log.Printf("failed to list workflows directory for %s: %s", repo.Name(), err)
		return repo
	}

	for _, entry := range dirContents {
		if entry.GetType() != "file" {
			continue
		}
		name := entry.GetName()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		fileContent, _, _, err := rc.Client.Client().Repositories.GetContents(rc.Context, org, repo.Name(), entry.GetPath(), nil)
		if err != nil || fileContent == nil {
			log.Printf("failed to fetch workflow file %s for %s: %v", entry.GetPath(), repo.Name(), err)
			continue
		}

		content, err := fileContent.GetContent()
		if err != nil {
			log.Printf("failed to decode workflow file %s for %s: %v", entry.GetPath(), repo.Name(), err)
			continue
		}

		repo.UnpinnedActions = append(repo.UnpinnedActions, unpinnedActionsInWorkflow(entry.GetPath(), []byte(content))...)
	}

	return repo
}

// unpinnedActionsInWorkflow parses a single workflow file and returns every
// action/reusable-workflow reference that isn't pinned to a full-length commit SHA.
func unpinnedActionsInWorkflow(path string, content []byte) []ghcollected.UnpinnedAction {
	workflow, errs := actionlint.Parse(content)
	if workflow == nil {
		if len(errs) > 0 {
			log.Printf("failed to parse workflow file %s: %v", path, errs[0])
		}
		return nil
	}

	var found []ghcollected.UnpinnedAction
	record := func(uses *actionlint.String) {
		if uses == nil || uses.Value == "" || isActionPinned(uses.Value) {
			return
		}
		line := 0
		if uses.Pos != nil {
			line = uses.Pos.Line
		}
		found = append(found, ghcollected.UnpinnedAction{
			Path: path,
			Uses: uses.Value,
			Line: line,
		})
	}

	for _, job := range workflow.Jobs {
		if job.WorkflowCall != nil {
			record(job.WorkflowCall.Uses)
		}

		for _, step := range job.Steps {
			if step.Exec == nil || step.Exec.Kind() != actionlint.ExecKindAction {
				continue
			}
			execAction, ok := step.Exec.(*actionlint.ExecAction)
			if !ok || execAction.Uses == nil {
				continue
			}
			record(execAction.Uses)
		}
	}

	return found
}
