package gitlab

import (
	"context"
	"log"

	"github.com/Legit-Labs/legitify/internal/clients/gitlab"
	"github.com/Legit-Labs/legitify/internal/collected/gitlab_collected"
	"github.com/Legit-Labs/legitify/internal/collectors"
	"github.com/Legit-Labs/legitify/internal/common/group_waiter"
	"github.com/Legit-Labs/legitify/internal/common/permissions"
	gitlab2 "github.com/xanzy/go-gitlab"

	"github.com/Legit-Labs/legitify/internal/common/namespace"
)

type groupCollector struct {
	collectors.BaseCollector
	Client  *gitlab.Client
	Context context.Context
}

func NewGroupCollector(ctx context.Context, client *gitlab.Client) collectors.Collector {
	c := &groupCollector{
		BaseCollector: collectors.NewBaseCollector(namespace.Organization),
		Client:        client,
		Context:       ctx,
	}
	return c
}

func (c *groupCollector) CollectTotalEntities() int {
	groups, err := c.Client.Groups()
	if err != nil {
		log.Printf("failed to collect groups %s", err)
		return 0
	}

	return len(groups)
}

func (c *groupCollector) Collect() collectors.SubCollectorChannels {
	return c.WrappedCollection(func() {
		groups, err := c.Client.Groups()
		if err != nil {
			log.Printf("failed to collect groups %s", err)
			return
		}

		gw := group_waiter.New()

		for _, g := range groups {
			g := g
			gw.Do(func() {
				fullGroup, _, err := c.Client.Client().Groups.GetGroup(g.ID, &gitlab2.GetGroupOptions{})
				if err != nil {
					log.Printf("failed to query group: %d - %s", g.ID, g.Name)
					return
				}

				isPremium := c.Client.IsGroupPremium(g.FullPath)

				hooks, err := c.Client.GroupHooks(fullGroup.ID)

				if err != nil {
					log.Printf("failed to query group hooks: %d - %s", g.ID, g.Name)
				}

				samlEnabled := c.collectGroupSamlData(fullGroup, isPremium)

				entity := gitlab_collected.Organization{
					Group:       fullGroup,
					Hooks:       hooks,
					SamlEnabled: samlEnabled,
				}

				c.CollectDataWithContext(entity, g.WebURL,
					newCollectionContext(g, []permissions.RepositoryRole{permissions.RepoRoleAdmin}, isPremium))
				c.CollectionChangeByOne()
			})
		}

		gw.Wait()
	})
}

// collectGroupSamlData checks whether SAML SSO is configured for the group.
// SSO can only be configured for top-level groups, and the API used to detect it is only
// available on GitLab Premium/Ultimate and requires the Owner role, so it is skipped
// (returning nil, i.e. "unknown") for subgroups, non-premium groups, or when the request
// fails (e.g. due to insufficient permissions).
func (c *groupCollector) collectGroupSamlData(group *gitlab2.Group, isPremium bool) *bool {
	if !isPremium || group.ParentID != 0 {
		return nil
	}

	samlEnabled, err := c.Client.GroupSamlEnabled(group.ID)
	if err != nil {
		log.Printf("failed to collect saml data for group %d - %s: %s", group.ID, group.Name, err)
		return nil
	}

	return samlEnabled
}
