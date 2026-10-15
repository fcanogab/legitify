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

// workflowFile is a single fetched GitHub Actions workflow file, ready to be parsed.
type workflowFile struct {
	path    string
	content []byte
}

// listWorkflowFiles fetches every workflow file under the repository's
// .github/workflows directory. It's shared by every check that needs to statically
// analyze workflow YAML, so that checking out the directory and downloading each
// file only happens once per repository regardless of how many such checks exist.
func (rc *repositoryCollector) listWorkflowFiles(repoName, org string) []workflowFile {
	const workflowsDir = ".github/workflows"
	_, dirContents, resp, err := rc.Client.Client().Repositories.GetContents(rc.Context, org, repoName, workflowsDir, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil // no workflows directory - nothing to check
		}
		log.Printf("failed to list workflows directory for %s: %s", repoName, err)
		return nil
	}

	var files []workflowFile
	for _, entry := range dirContents {
		if entry.GetType() != "file" {
			continue
		}
		name := entry.GetName()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		fileContent, _, _, err := rc.Client.Client().Repositories.GetContents(rc.Context, org, repoName, entry.GetPath(), nil)
		if err != nil || fileContent == nil {
			log.Printf("failed to fetch workflow file %s for %s: %v", entry.GetPath(), repoName, err)
			continue
		}

		content, err := fileContent.GetContent()
		if err != nil {
			log.Printf("failed to decode workflow file %s for %s: %v", entry.GetPath(), repoName, err)
			continue
		}

		files = append(files, workflowFile{path: entry.GetPath(), content: []byte(content)})
	}

	return files
}

// withUnpinnedActions scans the repository's GitHub Actions workflow files
// (.github/workflows/*) and records every action/reusable-workflow reference that
// isn't pinned to a full-length commit SHA.
func (rc *repositoryCollector) withUnpinnedActions(repo ghcollected.Repository, org string) ghcollected.Repository {
	repo.UnpinnedActions = []ghcollected.UnpinnedAction{}

	for _, f := range rc.listWorkflowFiles(repo.Name(), org) {
		repo.UnpinnedActions = append(repo.UnpinnedActions, unpinnedActionsInWorkflow(f.path, f.content)...)
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
