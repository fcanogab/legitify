package gitlab

// maxConcurrentRequests caps how many requests the GitLab collectors issue in parallel at
// any single fan-out point (e.g. concurrently-processed groups, projects, or members).
//
// Collectors previously used an unbounded group_waiter.GroupWaiter, spawning one goroutine
// per group/project/member with no limit. On large organizations this creates a massive
// burst of concurrent requests. Self-managed GitLab instances commonly apply stricter,
// separate throttles to specific "expensive" endpoints (e.g. GET
// /projects/:id/members/all) on top of the general API rate limit, and don't necessarily
// advertise those via the standard rate-limit response headers - so go-gitlab's own
// (header-driven) limiter doesn't help here. Bounding fan-out, together with the
// retry/backoff handling in internal/clients/gitlab/transport, keeps legitify from
// tripping those throttles when scanning large orgs.
const maxConcurrentRequests = 10
