package gitlab

import (
	"context"
	"log"
	"sync"

	"github.com/Legit-Labs/legitify/internal/clients/gitlab"
	"github.com/Legit-Labs/legitify/internal/clients/gitlab/pagination"
	"github.com/Legit-Labs/legitify/internal/collected/gitlab_collected"
	"github.com/Legit-Labs/legitify/internal/collectors"
	"github.com/Legit-Labs/legitify/internal/common/group_waiter"
	"github.com/Legit-Labs/legitify/internal/common/namespace"
	"github.com/Legit-Labs/legitify/internal/common/permissions"
	gitlab2 "github.com/xanzy/go-gitlab"
)

type runnerCollector struct {
	collectors.BaseCollector
	Client  *gitlab.Client
	Context context.Context
}

func NewRunnerCollector(ctx context.Context, client *gitlab.Client) collectors.Collector {
	return &runnerCollector{
		BaseCollector: collectors.NewBaseCollector(namespace.RunnerGroup),
		Client:        client,
		Context:       ctx,
	}
}

// runnerOwner captures where a runner was discovered. It's used to build a canonical link
// back to the owning group/project, and to approximate the owner's subscription plan.
// It's left zero-valued for instance-wide runners discovered via the admin-only API, since
// those aren't owned by any single group/project.
type runnerOwner struct {
	webURL   string
	fullPath string
}

// discoverRunners finds every runner id the current token can see, along with where it was
// first discovered. GitLab doesn't expose a single "list every runner" endpoint to
// non-admins, and the same runner (in particular: shared/instance runners) can legitimately
// show up under many groups/projects, so discovery falls back to iterating groups (and their
// projects) and de-duplicating by runner ID.
func (c *runnerCollector) discoverRunners() (map[int]runnerOwner, error) {
	if c.Client.IsAdmin() {
		res, err := pagination.New[*gitlab2.Runner](c.Client.Client().Runners.ListAllRunners, nil).Sync()
		if err != nil {
			return nil, err
		}

		owners := make(map[int]runnerOwner, len(res.Collected))
		for _, r := range res.Collected {
			owners[r.ID] = runnerOwner{}
		}
		return owners, nil
	}

	groups, err := c.Client.Groups()
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex
	owners := make(map[int]runnerOwner)
	addRunners := func(runners []*gitlab2.Runner, owner runnerOwner) {
		mu.Lock()
		defer mu.Unlock()
		for _, r := range runners {
			if _, exists := owners[r.ID]; !exists {
				owners[r.ID] = owner
			}
		}
	}

	// Two independent, separately-bounded waiters are used here rather than a single
	// one: groupsGw's work (listing a group's projects) itself submits work to
	// projectsGw. Sharing one semaphore between both levels could deadlock once
	// maxConcurrentRequests groups are all blocked waiting for a projectsGw slot that
	// can only be freed by project work the groupsGw goroutines haven't been able to
	// submit yet.
	groupsGw := group_waiter.NewWithLimit(maxConcurrentRequests)
	projectsGw := group_waiter.NewWithLimit(maxConcurrentRequests)
	for _, g := range groups {
		g := g
		groupsGw.Do(func() {
			groupRunners, err := pagination.New[*gitlab2.Runner](c.Client.Client().Runners.ListGroupsRunners, nil).Sync(g.ID)
			if err != nil {
				log.Printf("failed to list runners for group %s (%d): %v", g.Name, g.ID, err)
			} else {
				addRunners(groupRunners.Collected, runnerOwner{webURL: g.WebURL, fullPath: g.FullPath})
			}

			ch := pagination.New[*gitlab2.Project](c.Client.Client().Groups.ListGroupProjects, nil).Async(g.ID)
			for res := range ch {
				if res.Err != nil {
					log.Printf("failed to list projects for group %s (%d): %v", g.Name, g.ID, res.Err)
					continue
				}
				for _, p := range res.Collected {
					p := p
					projectsGw.Do(func() {
						projectRunners, err := pagination.New[*gitlab2.Runner](c.Client.Client().Runners.ListProjectRunners, nil).Sync(p.ID)
						if err != nil {
							log.Printf("failed to list runners for project %s (%d): %v", p.PathWithNamespace, p.ID, err)
							return
						}
						addRunners(projectRunners.Collected, runnerOwner{webURL: p.WebURL, fullPath: p.PathWithNamespace})
					})
				}
			}
		})
	}
	groupsGw.Wait()
	projectsGw.Wait()

	return owners, nil
}

func (c *runnerCollector) CollectTotalEntities() int {
	owners, err := c.discoverRunners()
	if err != nil {
		log.Printf("failed to collect runners %s", err)
		return 0
	}

	return len(owners)
}

func (c *runnerCollector) Collect() collectors.SubCollectorChannels {
	return c.WrappedCollection(func() {
		owners, err := c.discoverRunners()
		if err != nil {
			log.Printf("failed to collect runners %s", err)
			return
		}

		gw := group_waiter.NewWithLimit(maxConcurrentRequests)
		for id, owner := range owners {
			id, owner := id, owner
			gw.Do(func() {
				details, _, err := c.Client.Client().Runners.GetRunnerDetails(id)
				if err != nil {
					log.Printf("failed to get details for runner %d: %v", id, err)
					return
				}

				var isPremium, isUltimate bool
				if owner.fullPath != "" {
					isPremium = c.Client.IsGroupPremium(owner.fullPath)
					isUltimate = c.Client.IsGroupUltimate(owner.fullPath)
				}

				entity := gitlab_collected.Runner{
					RunnerDetails: details,
					OwnerWebURL:   owner.webURL,
					InstanceURL:   c.Client.ServerUrl(),
				}

				c.CollectDataWithContext(entity, entity.CanonicalLink(),
					newCollectionContext(nil, []permissions.Role{permissions.GroupRoleOwner}, isPremium, isUltimate))
				c.CollectionChangeByOne()
			})
		}
		gw.Wait()
	})
}
