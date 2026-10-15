package gitlab

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/Legit-Labs/legitify/internal/clients/gitlab"
	"github.com/Legit-Labs/legitify/internal/clients/gitlab/pagination"
	"github.com/Legit-Labs/legitify/internal/collected/gitlab_collected"
	"github.com/Legit-Labs/legitify/internal/collectors"
	"github.com/Legit-Labs/legitify/internal/common/group_waiter"
	"github.com/Legit-Labs/legitify/internal/common/permissions"
	"github.com/Legit-Labs/legitify/internal/common/types"
	"github.com/Legit-Labs/legitify/internal/context_utils"
	gitlab2 "github.com/xanzy/go-gitlab"

	"github.com/Legit-Labs/legitify/internal/common/namespace"
)

// renovateConfigPaths lists the file paths Renovate recognizes as a valid
// onboarding/configuration file. Order matters only for which path gets
// reported first when multiple are present (see renovate docs:
// https://docs.renovatebot.com/configuration-options/).
var renovateConfigPaths = []string{
	"renovate.json",
	"renovate.json5",
	".renovaterc",
	".renovaterc.json",
	".renovaterc.json5",
	".gitlab/renovate.json",
	".gitlab/renovate.json5",
	".github/renovate.json",
	".github/renovate.json5",
}

// renovateBranchPrefix is Renovate's default branchPrefix. Branches created
// by Renovate (self-hosted or via its GitLab integration) are named
// "renovate/<...>" unless the prefix was customized.
const renovateBranchPrefix = "renovate/"

type repositoryCollector struct {
	collectors.BaseCollector
	Client  *gitlab.Client
	Context context.Context
}

func NewRepositoryCollector(ctx context.Context, client *gitlab.Client) collectors.Collector {
	c := &repositoryCollector{
		BaseCollector: collectors.NewBaseCollector(namespace.Repository),
		Client:        client,
		Context:       ctx,
	}
	return c
}

func (rc *repositoryCollector) CollectTotalEntities() int {
	repositories, exist := context_utils.GetRepositories(rc.Context)
	if exist {
		return len(repositories)
	}

	groups, err := rc.Client.Groups()
	if err != nil {
		log.Printf("failed to collect list of groups to get repositories metadata %s", err)
		return 0
	}

	var total atomic.Int64
	gw := group_waiter.New()
	for _, group := range groups {
		group := group
		gw.Do(func() {
			_, resp, err := rc.Client.Client().Groups.ListGroupProjects(group.ID, &gitlab2.ListGroupProjectsOptions{})
			if err != nil {
				log.Printf("failed to collect metadata for repositories of group %s (%d): %s", group.Name, group.ID, err)
			} else {
				total.Add(int64(resp.TotalItems))
			}
		})
	}
	gw.Wait()

	return int(total.Load())
}

func (rc *repositoryCollector) Collect() collectors.SubCollectorChannels {
	repositories, exist := context_utils.GetRepositories(rc.Context)

	if exist {
		return rc.collectSpecific(repositories)
	}

	return rc.collectAll()
}

func (rc *repositoryCollector) collectSpecific(repositories []types.RepositoryWithOwner) collectors.SubCollectorChannels {
	return rc.WrappedCollection(func() {
		gw := group_waiter.New()
		for _, r := range repositories {
			r := r
			gw.Do(func() {
				project, _, err := rc.Client.Client().Projects.GetProject(getRepositoryEncodedName(r), &gitlab2.GetProjectOptions{})
				if err != nil {
					log.Println(err.Error())
					return
				}
				isPremium := rc.Client.IsGroupPremium(r.Owner)
				isUltimate := rc.Client.IsGroupUltimate(r.Owner)
				rc.extendedCollection(project, isPremium, isUltimate)
			})

		}
		gw.Wait()
	})
}

func getRepositoryEncodedName(repo types.RepositoryWithOwner) string {
	return repo.Owner + "/" + repo.Name
}

func (rc *repositoryCollector) extendProjectWithProtectedBranches(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	res, err := pagination.New[*gitlab2.ProtectedBranch](rc.Client.Client().ProtectedBranches.ListProtectedBranches, nil).Sync(int(project.ID()))
	if err != nil {
		log.Printf("failed to list projects %v", err)
		return project, err
	}

	extendedProject := project
	extendedProject.ProtectedBranches = res.Collected
	return extendedProject, nil
}

func (rc *repositoryCollector) extendProjectWithMembers(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	res, err := pagination.New[*gitlab2.ProjectMember](rc.Client.Client().ProjectMembers.ListAllProjectMembers, nil).Sync(int(project.ID()))
	if err != nil {
		log.Printf("failed to list projects %v", err)
		return project, err
	}

	extendedProject := project
	extendedProject.Members = res.Collected
	return extendedProject, nil
}

func (rc *repositoryCollector) extendProjectWithWebhooks(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	res, err := pagination.New[*gitlab2.ProjectHook](rc.Client.Client().Projects.ListProjectHooks, nil).Sync(int(project.ID()))
	if err != nil {
		log.Printf("failed to list project: %s webhook. error message: %s", project.Name(), err)
		return project, err
	}

	extendedProject := project
	extendedProject.Webhooks = res.Collected
	return extendedProject, nil
}

func (rc *repositoryCollector) extendProjectWithPushRules(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	rules, _, err := rc.Client.Client().Projects.GetProjectPushRules(int(project.ID()))
	if err != nil {
		log.Printf("failed to get project push rule %s", err)
		return project, err
	}
	extendedProject := project
	extendedProject.PushRules = rules
	return extendedProject, nil
}

func (rc *repositoryCollector) extendProjectWithMergeRequestApprovalRules(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	rules, _, err := rc.Client.Client().Projects.GetProjectApprovalRules(int(project.ID()), nil)
	if err != nil {
		log.Printf("failed to get project merge request approval rules %s", err)
		return project, err
	}
	extendedProject := project
	extendedProject.ApprovalRules = rules
	return extendedProject, nil
}

func (rc *repositoryCollector) extendProjectWithApprovalConfiguration(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	config, _, err := rc.Client.Client().Projects.GetApprovalConfiguration(int(project.ID()))
	if err != nil {
		log.Printf("failed to get project approval configuration %s", err)
		return project, err
	}
	extendedProject := project
	extendedProject.ApprovalConfiguration = config
	return extendedProject, nil
}

func (rc *repositoryCollector) extendProjectWithRenovateStatus(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	extendedProject := project

	configPath, err := rc.findRenovateConfigFile(project)
	if err != nil {
		log.Printf("failed to check for renovate config file in project %s: %s", project.Name(), err)
	}
	extendedProject.RenovateConfigPath = configPath

	branches, err := rc.findRenovateBranches(project)
	if err != nil {
		log.Printf("failed to list branches to detect renovate for project %s: %s", project.Name(), err)
	}
	extendedProject.RenovateBranches = branches

	return extendedProject, nil
}

func (rc *repositoryCollector) findRenovateConfigFile(project gitlab_collected.Repository) (string, error) {
	ref := project.DefaultBranch

	for _, path := range renovateConfigPaths {
		opts := &gitlab2.GetFileMetaDataOptions{}
		if ref != "" {
			opts.Ref = gitlab2.String(ref)
		}

		_, resp, err := rc.Client.Client().RepositoryFiles.GetFileMetaData(int(project.ID()), path, opts)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				continue // expected: this candidate path doesn't exist, keep trying others
			}
			return "", err
		}

		return path, nil
	}

	return "", nil
}

func (rc *repositoryCollector) findRenovateBranches(project gitlab_collected.Repository) ([]string, error) {
	res, err := pagination.New[*gitlab2.Branch](rc.Client.Client().Branches.ListBranches,
		&gitlab2.ListBranchesOptions{Search: gitlab2.String(renovateBranchPrefix)}).Sync(int(project.ID()))
	if err != nil {
		return nil, err
	}

	var branches []string
	for _, b := range res.Collected {
		// the GitLab "search" filter matches substrings/regex, so re-validate
		// the prefix explicitly rather than trusting the server-side filter.
		if strings.HasPrefix(b.Name, renovateBranchPrefix) {
			branches = append(branches, b.Name)
		}
	}

	return branches, nil
}

func (rc *repositoryCollector) extendProjectWithSecretPushProtection(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	enabled, err := rc.Client.ProjectSecretPushProtectionEnabled(int(project.ID()))
	if err != nil {
		log.Printf("failed to get secret push protection status for project %s: %s", project.Name(), err)
		return project, err
	}
	extendedProject := project
	extendedProject.SecretPushProtectionEnabled = enabled
	return extendedProject, nil
}

func (rc *repositoryCollector) extendProjectWithMinimumRequiredApprovals(project gitlab_collected.Repository) (gitlab_collected.Repository, error) {
	minRequiredApprovals := 0

	for _, rule := range project.ApprovalRules {
		if rule.ApprovalsRequired > minRequiredApprovals {
			minRequiredApprovals = rule.ApprovalsRequired
		}
	}

	project.MinimumRequiredApprovals = minRequiredApprovals
	return project, nil
}

func (rc *repositoryCollector) collectAll() collectors.SubCollectorChannels {
	return rc.WrappedCollection(func() {
		groups, err := rc.Client.Groups()
		if err != nil {
			log.Printf("failed to collect list of groups to get repositories  %s", err)
			return
		}
		gw := group_waiter.New()
		for _, group := range groups {
			g := group
			gw.Do(func() {
				ch := pagination.New[*gitlab2.Project](rc.Client.Client().Groups.ListGroupProjects, nil).Async(g.ID)
				for res := range ch {
					if res.Err != nil {
						log.Printf("failed to list projects for group %s (%d): %v", g.Name, g.ID, res.Err)
						return
					}
					for _, completedProject := range res.Collected {
						completedProject := completedProject
						gw.Do(func() {
							rc.extendedCollection(completedProject, rc.Client.IsGroupPremium(g.FullPath), rc.Client.IsGroupUltimate(g.FullPath))
						})
					}
				}
			})
		}
		gw.Wait()
	})
}

func (rc *repositoryCollector) extendedCollection(completeProjectsList *gitlab2.Project, isPremium bool, isUltimate bool) {
	proj := gitlab_collected.Repository{
		Project: completeProjectsList,
	}
	extensionFunctions := []func(gitlab_collected.Repository) (gitlab_collected.Repository, error){
		rc.extendProjectWithMembers,
		rc.extendProjectWithProtectedBranches,
		rc.extendProjectWithWebhooks,
		rc.extendProjectWithPushRules,
		rc.extendProjectWithMergeRequestApprovalRules,
		rc.extendProjectWithApprovalConfiguration,
		rc.extendProjectWithMinimumRequiredApprovals,
		rc.extendProjectWithRenovateStatus,
		rc.extendProjectWithSecretPushProtection,
	}
	var err error
	for _, f := range extensionFunctions {
		proj, err = f(proj)
		if err != nil {
			log.Printf("project '%s' collection failed with error: %v", proj.Name(), err)
		}
	}

	newContext := newCollectionContext(nil, []permissions.Role{permissions.GroupRoleOwner},
		isPremium, isUltimate)
	rc.CollectDataWithContext(proj, proj.Links.Self, &newContext)
	rc.CollectionChangeByOne()
}
