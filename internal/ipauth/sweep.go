package ipauth

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"time"
)

// How often the background sweeps run. The expiry windows they enforce are
// configurable; how often we check for expiry is not.
const (
	basicAuthSweepInterval = 1 * time.Minute
	banSweepInterval       = 1 * time.Minute
)

// every runs fn immediately and then once per interval until ctx is canceled.
// A non-positive interval runs fn exactly once.
func every(ctx context.Context, interval time.Duration, fn func()) {
	fn()

	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}

// startSweeps launches the background jobs that renew host IPs and expire stale
// Basic Auth grants and bans. They all stop when ctx is canceled.
func (c *controller) startSweeps(ctx context.Context) {
	// Add dynamic IPs and renew frequently.
	if len(c.cfg.AllowHosts) > 0 {
		go every(ctx, c.cfg.HostIPRenewal, func() {
			c.renewAllowIPsByHost(c.cfg.AllowHosts)
		})
	}

	// Cleanup expired Basic Auth IPs.
	if c.cfg.BasicAuthDuration > 0 {
		go every(ctx, basicAuthSweepInterval, func() {
			c.cleanupBasicAuthIPs(c.cfg.BasicAuthDuration)
		})
	}

	// Cleanup bans.
	if c.cfg.BanDuration > 0 {
		go every(ctx, banSweepInterval, func() {
			c.cleanupFailedAttempts(c.cfg.BanDuration)
		})
	}
}

// renewAllowIPsByHost re-resolves every allowed host and replaces the IPs they
// currently map to.
func (c *controller) renewAllowIPsByHost(allowedHosts []string) {
	slog.Info("renewing IPs by hosts")

	var newIPs []netip.Addr
	for _, host := range allowedHosts {
		hostIPs, err := c.hostToIP(host)
		if err != nil {
			slog.Error("hostToIP", "host", host, "error", err)
			continue
		}
		slog.Info("adding", "host", host, "IPs", hostIPs)
		newIPs = append(newIPs, hostIPs...)
	}

	c.state.mu.Lock()
	defer c.state.mu.Unlock()

	c.state.allowIPsByHost = newIPs
}

func (c *controller) cleanupBasicAuthIPs(expireInterval time.Duration) {
	slog.Debug("cleanup allowed Basic Auth IPs", "expire interval", expireInterval.String())

	c.state.mu.Lock()
	defer c.state.mu.Unlock()

	maps.DeleteFunc(c.state.allowIPsByBasicAuth, func(ip netip.Addr, allowedAt time.Time) bool {
		if allowedAt.Add(expireInterval).After(time.Now()) {
			// not yet expired
			return false
		}
		slog.Debug("expired Basic Auth IP",
			"ip", ip.String(),
			"allowed_at", allowedAt,
		)
		return true
	})
}

// cleanupFailedAttempts drops bans and failed login attempts older than banDuration.
func (c *controller) cleanupFailedAttempts(banDuration time.Duration) {
	slog.Debug("cleanup bans and failed logins", "ban duration", banDuration.String())

	c.state.mu.Lock()
	defer c.state.mu.Unlock()

	maps.DeleteFunc(c.state.bannedIPs, func(ip netip.Addr, info banInfo) bool {
		if info.bannedAt.Add(banDuration).After(time.Now()) {
			// still banned, or not yet expired
			return false
		}
		slog.Debug("expired ban",
			"ip", ip.String(),
			"banned_at", info.bannedAt,
			"attempts", info.attempts,
		)
		return true
	})
}

func (c *controller) hostToIP(host string) ([]netip.Addr, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var result []netip.Addr
	for _, ip := range ips {
		nip, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		result = append(result, nip)
	}

	return result, nil
}
