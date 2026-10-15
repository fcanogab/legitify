package gitlab

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Legit-Labs/legitify/internal/clients/gitlab/pagination"
	"github.com/Legit-Labs/legitify/internal/clients/gitlab/transport"
	"github.com/Legit-Labs/legitify/internal/common/permissions"
	"github.com/Legit-Labs/legitify/internal/common/slice_utils"
	"github.com/Legit-Labs/legitify/internal/common/types"
	"github.com/shurcooL/graphql"
	"github.com/xanzy/go-gitlab"
)

const (
	allGroupsFilter = ""
)

type Client struct {
	context       context.Context
	client        *gitlab.Client
	graphQLClient *graphql.Client
	orgs          []string
	isAdmin       bool
	endpoint      string
}

func (c *Client) Client() *gitlab.Client {
	return c.client
}

func (c *Client) GraphQLClient() *graphql.Client {
	return c.graphQLClient
}

func NewClient(ctx context.Context, token string, endpoint string, orgs []string) (*Client, error) {
	var config []gitlab.ClientOptionFunc
	if endpoint != "" {
		config = []gitlab.ClientOptionFunc{
			gitlab.WithBaseURL(endpoint),
			gitlab.WithHTTPClient(transport.NewHttpClient()),
		}
	}

	git, err := gitlab.NewClient(token, config...)
	if err != nil {
		return nil, err
	}

	if len(orgs) == 0 {
		orgs = []string{allGroupsFilter}
	}

	result := &Client{
		context:       ctx,
		client:        git,
		graphQLClient: graphql.NewClient(graphQLUrl(endpoint), transport.NewGraphQLHttpClient(token)),
		orgs:          orgs,
		isAdmin:       IsAdmin(git),
		endpoint:      endpoint,
	}

	return result, nil
}

// graphQLUrl derives the "/api/graphql" endpoint from the configured REST base URL
// (empty for GitLab.com), since GitLab's GraphQL API isn't wrapped by go-gitlab.
func graphQLUrl(endpoint string) string {
	base := endpoint
	if base == "" {
		base = "https://gitlab.com"
	}

	return strings.TrimRight(base, "/") + "/api/graphql"
}

func (c *Client) ServerUrl() string {
	return c.endpoint
}

func (c *Client) IsServer() bool {
	return c.endpoint != ""
}

func (c *Client) IsAnalyzable(repo types.RepositoryWithOwner) (bool, error) {
	_, _, err := c.Client().Projects.GetProject(repo.String(), nil)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) Scopes() permissions.TokenScopes {
	return permissions.TokenScopes{}
}

func (c *Client) Organizations() ([]types.Organization, error) {
	var result []types.Organization

	groups, err := c.Groups()
	if err != nil {
		return nil, err
	}

	for _, g := range groups {
		result = append(result, types.Organization{
			Name: g.Name,
			Role: permissions.OrgRoleOwner,
			ID:   g.ID,
		})
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) Repositories() ([]types.RepositoryWithOwner, error) {
	opts := &gitlab.ListProjectsOptions{}
	if !c.IsAdmin() {
		opts.MinAccessLevel = gitlab.AccessLevel(gitlab.MaintainerPermissions)
	}
	mapper := func(projects []*gitlab.Project) []types.RepositoryWithOwner {
		if projects == nil {
			return []types.RepositoryWithOwner{}
		}
		return slice_utils.Map(projects, func(p *gitlab.Project) types.RepositoryWithOwner {
			return types.NewRepositoryWithOwner(p.PathWithNamespace, permissions.RepoRoleAdmin)
		})
	}
	result, err := pagination.NewMapper(c.Client().Projects.ListProjects, opts, mapper).Sync()

	if err != nil {
		return nil, err
	}
	return result.Collected, nil
}

func (c *Client) GroupMembers(group *gitlab.Group) ([]*gitlab.GroupMember, error) {
	result, err := pagination.New[*gitlab.GroupMember](c.Client().Groups.ListGroupMembers, nil).Sync(group.ID)
	if err != nil {
		return nil, err
	}

	return result.Collected, nil
}

func (c *Client) IsAdmin() bool {
	return c.isAdmin
}

func IsAdmin(client *gitlab.Client) bool {
	res, _, err := client.Users.CurrentUser()
	if err != nil {
		return false // assume false on error
	}
	return res.IsAdmin
}

func (c *Client) Group(name string) (*gitlab.Group, error) {
	ownedGroups := !c.IsAdmin() // list all groups as site admin
	opts := &gitlab.ListGroupsOptions{
		Owned:  &ownedGroups,
		Search: &name,
	}

	res, err := pagination.New[*gitlab.Group](c.Client().Groups.ListGroups, opts).Sync()
	if err != nil {
		return nil, err
	}

	for _, g := range res.Collected {
		if g.FullPath == name {
			return g, nil
		}
	}

	return nil, fmt.Errorf("couldn't find group %s", name)
}

func (c *Client) Groups() ([]*gitlab.Group, error) {
	var result []*gitlab.Group

	ownedGroups := !c.IsAdmin() // list all groups as site admin
	for _, group := range c.orgs {
		opts := &gitlab.ListGroupsOptions{
			Owned:  &ownedGroups,
			Search: &group,
		}
		res, err := pagination.New[*gitlab.Group](c.Client().Groups.ListGroups, opts).Sync()
		if err != nil {
			return nil, err
		}
		result = append(result, res.Collected...)
	}

	return result, nil
}

func (c *Client) GroupHooks(gid int) ([]*gitlab.GroupHook, error) {
	result, err := pagination.New[*gitlab.GroupHook](c.Client().Groups.ListGroupHooks, nil).Sync(gid)
	if err != nil {
		return nil, err
	}

	return result.Collected, nil
}

func (c *Client) GroupPlan(namespace string) (string, error) {
	nss, resp, err := c.Client().Namespaces.SearchNamespace(namespace)
	if err != nil {
		return "", fmt.Errorf("failed to search namespace %s: %v (response: %+v)", namespace, err, resp)
	}

	for _, n := range nss {
		if n.FullPath == namespace {
			return n.Plan, nil
		}
	}

	return "", fmt.Errorf("didn't find namespace for %s", namespace)
}

func (c *Client) IsGroupPremium(group string) bool {
	groupRootNamespace := strings.Split(group, "/")[0]
	plan, err := c.GroupPlan(groupRootNamespace)
	if err != nil {
		log.Printf("failed to get namespace for group %s %v", group, err)
		return false
	}

	return plan != "free"
}

// IsGroupUltimate reports whether the root namespace of the given group/project is on the
// Ultimate plan, which gates features such as audit event streaming. Unlike IsGroupPremium,
// legacy tier aliases (e.g. "gold") aren't handled.
func (c *Client) IsGroupUltimate(group string) bool {
	groupRootNamespace := strings.Split(group, "/")[0]
	plan, err := c.GroupPlan(groupRootNamespace)
	if err != nil {
		log.Printf("failed to get namespace for group %s %v", group, err)
		return false
	}

	return plan == "ultimate"
}

// GroupSamlEnabled reports whether SAML SSO is configured for the given top-level group.
//
// GitLab does not expose a simple "SSO enabled" boolean through the Groups API (REST or
// GraphQL), so this relies on the behavior of the SAML API instead: GET
// /groups/:id/saml/identities returns 400 Bad Request when the group has no SAML provider
// configured, and 200 OK (with a possibly empty list of identities) when it does.
// See: https://docs.gitlab.com/api/saml/#list-all-saml-identities-for-a-group
//
// This endpoint is only available on GitLab Premium/Ultimate and requires the Owner role
// on the (top-level) group, so callers should expect errors for Free-tier groups, non-owner
// tokens, or subgroups (SSO can only be configured on top-level groups).
func (c *Client) GroupSamlEnabled(groupID int) (*bool, error) {
	u := fmt.Sprintf("groups/%d/saml/identities", groupID)
	req, err := c.client.NewRequest(http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, err
	}

	var identities []interface{}
	resp, err := c.client.Do(req, &identities)
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusOK:
			enabled := true
			return &enabled, nil
		case http.StatusBadRequest:
			disabled := false
			return &disabled, nil
		}
	}

	if err != nil {
		return nil, err
	}

	enabled := true
	return &enabled, nil
}

// ProjectSecretPushProtectionEnabled reports whether GitLab's secret push protection is
// enabled for the given project. Secret push protection scans commits for secrets when
// changes are pushed and blocks the push if any high-confidence secrets are detected.
// See: https://docs.gitlab.com/user/application_security/secret_detection/secret_push_protection/
//
// The attribute isn't modeled by go-gitlab's Project struct yet, even though the GitLab
// REST API already returns it as part of the regular project representation (GET
// /projects/:id), so a raw request is used instead of the typed Projects.GetProject call.
func (c *Client) ProjectSecretPushProtectionEnabled(projectID int) (*bool, error) {
	u := fmt.Sprintf("projects/%d", projectID)
	req, err := c.client.NewRequest(http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, err
	}

	var project struct {
		SecretPushProtectionEnabled *bool `json:"secret_push_protection_enabled"`
	}
	_, err = c.client.Do(req, &project)
	if err != nil {
		return nil, err
	}

	return project.SecretPushProtectionEnabled, nil
}

// groupAuditEventDestinationsQuery mirrors the GraphQL query documented at
// https://docs.gitlab.com/api/graphql/audit_event_streaming_groups/#list-streaming-destinations
type groupAuditEventDestinationsQuery struct {
	Group struct {
		ExternalAuditEventDestinations struct {
			Nodes []struct {
				ID string
			}
		} `graphql:"externalAuditEventDestinations"`
	} `graphql:"group(fullPath: $fullPath)"`
}

// GroupAuditEventStreamingEnabled reports whether at least one external audit event
// streaming destination is configured for the given top-level group, i.e. whether the
// group's audit events are being forwarded to an external system (SIEM, log management
// service, etc.) in addition to being retained within GitLab itself.
//
// Audit event streaming is a GitLab Ultimate feature available only for top-level groups,
// and - unlike most of the features legitify checks - it is exposed exclusively through the
// GraphQL API; no REST endpoint exists for it. See:
// https://docs.gitlab.com/user/compliance/audit_event_streaming/
//
// This requires the Owner role on the (top-level) group, so callers should expect errors
// for non-Ultimate groups, subgroups, or insufficient permissions.
func (c *Client) GroupAuditEventStreamingEnabled(fullPath string) (bool, error) {
	var query groupAuditEventDestinationsQuery
	variables := map[string]interface{}{
		"fullPath": graphql.ID(fullPath),
	}

	err := c.GraphQLClient().Query(c.context, &query, variables)
	if err != nil {
		return false, err
	}

	return len(query.Group.ExternalAuditEventDestinations.Nodes) > 0, nil
}
