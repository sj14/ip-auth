package main

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"
)

type BasicAuthCredentials struct {
	Name     string
	Password string
}

// BasicAuth verifies the request credentials and records a failed attempt when
// they don't match. Callers must reject already-banned IPs via evaluate first;
// the ban rule lives there so HandleIP and Status can't disagree about it.
func (c *Controller) BasicAuth(requestIP netip.Addr, r *http.Request) error {
	givenUser, givenPass, _ := r.BasicAuth()

	if len(c.cfg.allowedUsers) == 0 {
		return fmt.Errorf("basic auth disabled (no users specified)")
	}

	for _, user := range c.cfg.allowedUsers {
		userMatch := subtle.ConstantTimeCompare([]byte(givenUser), []byte(user.Name)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(givenPass), []byte(user.Password)) == 1
		if userMatch && passMatch {
			slog.Info("success basic auth (address dynamically added)", "addr", requestIP.String(), "user", user.Name)
			return nil
		}
	}

	c.state.mu.Lock()
	banInfo := c.state.bannedIPs[requestIP]
	// Re-check under the lock (evaluate's check happens outside it, so a
	// concurrent request from the same IP can ban it in between) to make sure an
	// already-banned IP never has its attempts or bannedAt touched again, and
	// thus never has its ban extended.
	if c.cfg.maxAttempts <= 0 || banInfo.attempts < c.cfg.maxAttempts {
		banInfo.attempts += 1
		// Track the time of the latest pre-ban attempt so cleanupFailedAttempts
		// can also expire stale, not-yet-banned entries.
		banInfo.bannedAt = time.Now()
		c.state.bannedIPs[requestIP] = banInfo
	}
	c.state.mu.Unlock()

	// login failed, add a tarpit
	defer func() {
		select {
		case <-r.Context().Done():
			slog.DebugContext(r.Context(), "tarpit: client closed connection")
		case <-time.After(5 * time.Second):
			slog.DebugContext(r.Context(), "tarpit: delayed by 5 seconds")
		}
	}()

	return fmt.Errorf("failed basic auth (user=%s addr=%s attempts=%d)", givenUser, requestIP, banInfo.attempts)
}
