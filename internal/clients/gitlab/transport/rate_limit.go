package transport

import (
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

const (
	// MaxRetries bounds how many times go-gitlab's retryablehttp client will retry a
	// request that fails with a 429 or 5xx response. The default (5) pairs poorly with
	// RateLimitBackoff's longer waits on 429s, so it's raised here to give throttled
	// requests more chances to succeed once the server-side window clears.
	MaxRetries = 8

	// defaultRetryAfter is used when a 429 response doesn't carry a Retry-After or
	// RateLimit-Reset header to compute a wait time from - which is the case for many
	// self-managed GitLab "expensive endpoint" throttles (e.g. Rack::Attack-based
	// limits on GET /projects/:id/members/all), as opposed to GitLab.com's general API
	// rate limit, which does advertise RateLimit-Reset.
	defaultRetryAfter = 30 * time.Second

	// maxRetryAfter caps how long a single backoff wait can be, regardless of what a
	// Retry-After/RateLimit-Reset header says, so a single misbehaving response can't
	// stall a whole run.
	maxRetryAfter = 2 * time.Minute
)

// RateLimitBackoff is a retryablehttp.Backoff implementation (for use with go-gitlab's
// gitlab.WithCustomBackoff) that properly honors 429 responses.
//
// go-gitlab's own default backoff only looks at the GitLab.com-style "RateLimit-Reset"
// header. It never checks the standard "Retry-After" header, which is what generic
// throttling middleware (e.g. Rack::Attack, commonly used to protect specific "expensive"
// endpoints on self-managed GitLab instances) sends instead. Without it, a 429 caused by
// such a throttle gets retried with a much-too-short wait (the same jittered ~100-400ms
// window used for plain network errors), so the retries get exhausted almost immediately
// and the request permanently fails even though the server just wanted the client to
// slow down for a while.
func RateLimitBackoff(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		return retryablehttp.LinearJitterBackoff(min, max, attemptNum, resp)
	}

	wait, source := defaultRetryAfter, "default"
	if v := resp.Header.Get("Retry-After"); v != "" {
		if d, ok := parseRetryAfter(v); ok {
			wait, source = d, "Retry-After"
		}
	} else if v := resp.Header.Get("RateLimit-Reset"); v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(secs, 0)); d > 0 {
				wait, source = d, "RateLimit-Reset"
			}
		}
	}

	if wait > maxRetryAfter {
		wait = maxRetryAfter
	} else if wait < 0 {
		wait = defaultRetryAfter
	}

	// A bit of jitter to avoid every throttled goroutine retrying in lockstep.
	jitter := time.Duration(rand.Int63n(int64(time.Second)))

	log.Printf("gitlab API rate limit hit on %s %s, waiting %v (from %s, attempt %d/%d) before retrying",
		resp.Request.Method, resp.Request.URL, wait, source, attemptNum+1, MaxRetries)

	return wait + jitter
}

// parseRetryAfter parses a Retry-After header value, which per RFC 7231 §7.1.3 is either
// a number of seconds or an HTTP-date.
func parseRetryAfter(v string) (time.Duration, bool) {
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t), true
	}
	return 0, false
}
