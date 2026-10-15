package gitlab

import (
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/Legit-Labs/legitify/internal/collected/gitlab_collected"
	gitlab2 "github.com/xanzy/go-gitlab"
	"gopkg.in/yaml.v3"
)

// defaultCIConfigPath is the default location GitLab looks for a project's pipeline
// configuration when the project doesn't override it via CIConfigPath.
const defaultCIConfigPath = ".gitlab-ci.yml"

// maxCIIncludeDepth bounds how many local `include:` hops are followed from the root
// CI config file, as a safety net against include cycles or pathological nesting.
const maxCIIncludeDepth = 10

var fullCommitSHARegex = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

func isFullCommitSHA(s string) bool {
	return fullCommitSHARegex.MatchString(s)
}

// isComponentPinned reports whether a CI/CD component reference
// (e.g. "gitlab.com/my-org/my-component@1.0.0") is pinned to a full-length commit SHA.
func isComponentPinned(component string) bool {
	idx := strings.LastIndex(component, "@")
	if idx == -1 {
		return false
	}
	return isFullCommitSHA(component[idx+1:])
}

// ciIncludeMapping mirrors the shape of a single mapping-style `include:` entry in a
// GitLab CI/CD configuration file. Only one of these fields is expected to be set per
// entry; which one determines the include's kind.
type ciIncludeMapping struct {
	Local     string `yaml:"local"`
	Project   string `yaml:"project"`
	Ref       string `yaml:"ref"`
	Remote    string `yaml:"remote"`
	Component string `yaml:"component"`
	Template  string `yaml:"template"`
}

// localCIInclude represents a same-repository (same-commit) include, which is always
// considered pinned, but still needs to be followed to find any further-nested includes.
type localCIInclude struct {
	path string
}

// externalCIInclude represents an include that crosses a trust boundary outside the
// current commit (a different project, a remote URL, or a versioned CI/CD component).
type externalCIInclude struct {
	kind      string
	reference string
	pinned    bool
}

// extendProjectWithUnpinnedCIIncludes scans the project's CI/CD configuration
// (following local includes within the same commit) and records every external
// include (project/remote/component) that isn't pinned to a full-length commit SHA.
func (rc *repositoryCollector) extendProjectWithUnpinnedCIIncludes(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	extendedProject := project
	extendedProject.UnpinnedCIIncludes = []gitlab_collected.UnpinnedCIInclude{}

	path := project.CIConfigPath
	if path == "" {
		path = defaultCIConfigPath
	} else if idx := strings.Index(path, "@"); idx != -1 {
		// CIConfigPath can point at a file in a *different* project via "path@group/project";
		// following that cross-project reference is out of scope for this check.
		path = path[:idx]
	}

	visited := map[string]bool{}
	includes, err := rc.collectUnpinnedCIIncludes(int(project.ID()), project.DefaultBranch, path, visited, 0)
	if err != nil {
		log.Printf("failed to collect CI includes for project %s: %s", project.Name(), err)
		return extendedProject, nil
	}

	extendedProject.UnpinnedCIIncludes = includes
	return extendedProject, nil
}

func (rc *repositoryCollector) collectUnpinnedCIIncludes(projectID int, ref, path string, visited map[string]bool, depth int) ([]gitlab_collected.UnpinnedCIInclude, error) {
	if depth > maxCIIncludeDepth || visited[path] {
		return nil, nil
	}
	visited[path] = true

	opts := &gitlab2.GetRawFileOptions{}
	if ref != "" {
		opts.Ref = gitlab2.String(ref)
	}

	content, resp, err := rc.Client.Client().RepositoryFiles.GetRawFile(projectID, path, opts)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil // no CI config at this path - nothing to check
		}
		return nil, err
	}

	locals, externals, err := parseCIIncludes(content)
	if err != nil {
		log.Printf("failed to parse CI config %s: %v", path, err)
		return nil, nil
	}

	var found []gitlab_collected.UnpinnedCIInclude
	for _, local := range locals {
		nested, err := rc.collectUnpinnedCIIncludes(projectID, ref, strings.TrimPrefix(local.path, "/"), visited, depth+1)
		if err != nil {
			log.Printf("failed to follow local CI include %s from %s: %v", local.path, path, err)
			continue
		}
		found = append(found, nested...)
	}

	for _, ext := range externals {
		if ext.pinned {
			continue
		}
		found = append(found, gitlab_collected.UnpinnedCIInclude{
			SourceFile: path,
			Type:       ext.kind,
			Reference:  ext.reference,
		})
	}

	return found, nil
}

// parseCIIncludes parses a CI/CD configuration file's top-level `include:` key (which
// may be a single string/mapping, or a list of either) and splits it into local
// includes to be followed further, and external includes to be evaluated for pinning.
func parseCIIncludes(content []byte) ([]localCIInclude, []externalCIInclude, error) {
	var doc struct {
		Include *yaml.Node `yaml:"include"`
	}
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, nil, err
	}
	if doc.Include == nil {
		return nil, nil, nil
	}

	return parseIncludeNode(doc.Include)
}

func parseIncludeNode(node *yaml.Node) ([]localCIInclude, []externalCIInclude, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		// A bare string under `include:` is shorthand for a local include.
		return []localCIInclude{{path: node.Value}}, nil, nil
	case yaml.SequenceNode:
		var locals []localCIInclude
		var externals []externalCIInclude
		for _, child := range node.Content {
			l, e, err := parseIncludeNode(child)
			if err != nil {
				return nil, nil, err
			}
			locals = append(locals, l...)
			externals = append(externals, e...)
		}
		return locals, externals, nil
	case yaml.MappingNode:
		return parseIncludeMapping(node)
	default:
		return nil, nil, nil
	}
}

func parseIncludeMapping(node *yaml.Node) ([]localCIInclude, []externalCIInclude, error) {
	var m ciIncludeMapping
	if err := node.Decode(&m); err != nil {
		return nil, nil, err
	}

	switch {
	case m.Local != "":
		return []localCIInclude{{path: m.Local}}, nil, nil
	case m.Template != "":
		// Built-in GitLab-maintained templates ship with the instance itself and
		// expose no pinning mechanism, so they're not a third-party dependency risk.
		return nil, nil, nil
	case m.Remote != "":
		// A remote URL isn't backed by a Git ref, so there's no way to pin it to a commit.
		return nil, []externalCIInclude{{kind: "remote", reference: m.Remote, pinned: false}}, nil
	case m.Component != "":
		return nil, []externalCIInclude{{kind: "component", reference: m.Component, pinned: isComponentPinned(m.Component)}}, nil
	case m.Project != "":
		reference := m.Project
		if m.Ref != "" {
			reference += "@" + m.Ref
		}
		return nil, []externalCIInclude{{kind: "project", reference: reference, pinned: isFullCommitSHA(m.Ref)}}, nil
	}

	return nil, nil, nil
}
