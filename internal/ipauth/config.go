// Package ipauth allows specific IPs access to a service and proxies their
// traffic to it. Allowed IPs can be configured directly or added dynamically by
// passing a Basic Auth login once from any device on the same IP.
package ipauth

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Credentials is a single user:password pair accepted by Basic Auth.
type Credentials struct {
	Name     string
	Password string
}

// Config holds the settings parsed at startup. Run does not mutate it and
// nothing writes to it once the server is running, so it is read without
// synchronization.
type Config struct {
	// Server
	Listen     string
	Network    string
	Target     string
	StatusPath string

	// Access rules
	Users           []Credentials
	AllowCIDR       []netip.Prefix
	DenyCIDR        []netip.Prefix
	AllowHosts      []string
	DenyPrivateIPs  bool
	TrustedIPHeader string

	// Bans
	MaxAttempts uint64
	BanDuration time.Duration

	// Expiry and renewal
	HostIPRenewal     time.Duration
	BasicAuthDuration time.Duration
}

// SplitList splits a comma-separated flag value, trimming spaces and dropping
// empty entries so that an unset flag or a trailing comma yields nothing.
func SplitList(value string) []string {
	var entries []string
	for _, entry := range strings.Split(value, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

// ParsePrefixes parses a comma-separated list of CIDR prefixes.
func ParsePrefixes(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, entry := range SplitList(value) {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR %q: %w", entry, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// ParseUsers parses a comma-separated list of user:password credentials.
func ParseUsers(value string) ([]Credentials, error) {
	var users []Credentials
	for _, entry := range SplitList(value) {
		name, password, ok := strings.Cut(entry, ":")
		if !ok || name == "" {
			return nil, fmt.Errorf("malformed user %q: want the form user:password", entry)
		}
		users = append(users, Credentials{Name: name, Password: password})
	}
	return users, nil
}
