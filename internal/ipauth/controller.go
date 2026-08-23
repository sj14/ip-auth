package ipauth

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
)

type banInfo struct {
	attempts uint64
	bannedAt time.Time
}

// state holds everything that changes while the server is running. Every field
// here is guarded by mu: never read or write one without holding it.
type state struct {
	mu                  sync.RWMutex
	bannedIPs           map[netip.Addr]banInfo
	allowIPsByHost      []netip.Addr
	allowIPsByBasicAuth map[netip.Addr]time.Time // IP -> time it last authenticated
}

type controller struct {
	cfg   Config
	state state
}

func newController(cfg Config) *controller {
	return &controller{
		cfg: cfg,
		state: state{
			bannedIPs:           make(map[netip.Addr]banInfo),
			allowIPsByBasicAuth: make(map[netip.Addr]time.Time),
		},
	}
}

type verdict int

const (
	// verdictChallenge is the zero value: the IP is on no list, so Basic Auth decides.
	verdictChallenge verdict = iota
	verdictAllowed
	verdictDenied
)

// decision is the outcome of evaluating an IP against every allow/deny rule,
// along with a human-readable reason suitable for logs and the status endpoint.
type decision struct {
	verdict verdict
	reason  string
}

// evaluate applies the allow/deny rules in priority order and is the single
// source of truth for that ordering: deny rules win over allow rules, and an
// IP on any allow list is let through regardless of its ban record.
// handleIP and status must both go through here so they can never disagree.
func (c *controller) evaluate(ip netip.Addr) decision {
	// Config is never mutated once the server is running, so it needs no lock.
	if c.cfg.DenyPrivateIPs && isPrivateAddr(ip) {
		return decision{verdictDenied, "denied (private IP)"}
	}

	for _, cidr := range c.cfg.DenyCIDR {
		if cidr.Contains(ip) {
			return decision{verdictDenied, fmt.Sprintf("denied CIDR (%s)", cidr.String())}
		}
	}

	for _, cidr := range c.cfg.AllowCIDR {
		if cidr.Contains(ip) {
			return decision{verdictAllowed, fmt.Sprintf("allowed CIDR (%s)", cidr.String())}
		}
	}

	c.state.mu.RLock()
	defer c.state.mu.RUnlock()

	if slices.Contains(c.state.allowIPsByHost, ip) {
		return decision{verdictAllowed, "allowed IP by host"}
	}

	if allowedAt, ok := c.state.allowIPsByBasicAuth[ip]; ok {
		return decision{verdictAllowed, fmt.Sprintf("allowed IP by Basic Auth at %s", allowedAt)}
	}

	if info, ok := c.state.bannedIPs[ip]; ok && c.cfg.MaxAttempts > 0 && info.attempts >= c.cfg.MaxAttempts {
		return decision{verdictDenied, fmt.Sprintf("banned at %s", info.bannedAt)}
	}

	return decision{verdictChallenge, "denied"}
}

func isPrivateAddr(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
