package transport

import (
	"net/http"

	"github.com/Legit-Labs/legitify/internal/clients/transport"
)

func NewHttpClient() *http.Client {
	return &http.Client{
		Transport: transport.NewCacheTransport(),
	}
}

// bearerAuthTransport adds an "Authorization: Bearer <token>" header to every outgoing
// request. It's used for GitLab's GraphQL API, which (unlike the REST API that go-gitlab
// already authenticates) isn't wrapped by a dedicated client in this codebase.
// See: https://docs.gitlab.com/api/graphql/#authentication
type bearerAuthTransport struct {
	token string
	base  http.RoundTripper
}

func (t *bearerAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := new(http.Request)
	*req2 = *req
	req2.Header = req.Header.Clone()
	req2.Header.Set("Authorization", "Bearer "+t.token)

	return t.base.RoundTrip(req2)
}

// NewGraphQLHttpClient returns an http.Client suitable for use with a GraphQL client
// against GitLab's "/api/graphql" endpoint, authenticated with the given token.
func NewGraphQLHttpClient(token string) *http.Client {
	return &http.Client{
		Transport: &bearerAuthTransport{
			token: token,
			base:  transport.NewCacheTransport(),
		},
	}
}
