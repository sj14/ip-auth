package main

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// config holds the settings parsed at startup. Nothing mutates it once the
// server is running, so it can be read without synchronization.
type config struct {
	allowedUsers    []BasicAuthCredentials
	denyCIDR        []netip.Prefix
	allowCIDRFix    []netip.Prefix
	denyPrivateIPs  bool
	trustedIPHeader string
	maxAttempts     uint64
}

func lookupEnvString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func lookupEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			log.Fatalf("failed parsing %q as bool (%q): %v", val, key, err)
		}
		return parsed
	}
	return defaultVal
}

func lookupEnvUint(key string, defaultVal uint64) uint64 {
	if val, ok := os.LookupEnv(key); ok {
		parsed, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			log.Fatalf("failed parsing %q as uint (%q): %v", val, key, err)
		}
		return parsed
	}
	return defaultVal
}

func lookupEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok {
		duration, err := time.ParseDuration(val)
		if err != nil {
			log.Fatalf("failed parsing %q as duration (%q): %v", val, key, err)
		}
		return time.Duration(duration)
	}
	return defaultVal
}

// splitList splits a comma-separated flag value, trimming spaces and dropping
// empty entries so that an unset flag or a trailing comma yields nothing.
func splitList(value string) []string {
	var entries []string
	for _, entry := range strings.Split(value, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

// parsePrefixes parses a comma-separated list of CIDR prefixes.
func parsePrefixes(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, entry := range splitList(value) {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR %q: %w", entry, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// parseUsers parses a comma-separated list of user:password credentials.
func parseUsers(value string) ([]BasicAuthCredentials, error) {
	var users []BasicAuthCredentials
	for _, entry := range splitList(value) {
		name, password, ok := strings.Cut(entry, ":")
		if !ok || name == "" {
			return nil, fmt.Errorf("malformed user %q: want the form user:password", entry)
		}
		users = append(users, BasicAuthCredentials{Name: name, Password: password})
	}
	return users, nil
}
