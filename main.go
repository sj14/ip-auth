package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/sj14/ip-auth/internal/ipauth"
)

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
		return duration
	}
	return defaultVal
}

func main() {
	var (
		statusPath                  = flag.String("status-path", lookupEnvString("STATUS_PATH", "/ip-auth"), "show info for the requesting IP")
		listen                      = flag.String("listen", lookupEnvString("LISTEN", ":8080"), "listen for connections")
		network                     = flag.String("network", lookupEnvString("NETWORK", "tcp"), "tcp, tcp4, tcp6, unix, unixpacket")
		target                      = flag.String("target", lookupEnvString("TARGET", ""), "proxy to the given target")
		verbosity                   = flag.String("verbosity", lookupEnvString("VERBOSITY", "Info"), "one of 'Debug', 'Info', 'Warn', or 'Error'")
		maxAttempts                 = flag.Uint64("max-attempts", lookupEnvUint("MAX_ATTEMPTS", 10), "ban IP after max failed auth attempts (0 to disable)")
		banDuration                 = flag.Duration("ban-duration", lookupEnvDuration("BAN_DURATION", 1*time.Hour), "cleanup bans and failed login attempts (0 to disable)")
		usersFlag                   = flag.String("users", lookupEnvString("USERS", ""), "allow the given basic auth credentals (e.g. user1:pass1,user2:pass2)")
		allowHostsFlag              = flag.String("allow-hosts", lookupEnvString("ALLOW_HOSTS", ""), "allow the given host IPs (e.g. example.com)")
		allowCIDRFlag               = flag.String("allow-cidr", lookupEnvString("ALLOW_CIDR", ""), "allow the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)")
		denyCIDRFlag                = flag.String("deny-cidr", lookupEnvString("DENY_CIDR", ""), "block the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)")
		denyPrivateIPs              = flag.Bool("deny-private", lookupEnvBool("DENY_PRIVATE", false), "deny IPs from the private network space")
		trustedIPHeader             = flag.String("ip-header", lookupEnvString("IP_HEADER", ""), "e.g. 'X-Real-Ip' or 'X-Forwarded-For' when you want to extract the IP from the given header (uses the rightmost entry, so put this behind exactly one trusted proxy)")
		cleanupHostIPsInterval      = flag.Duration("host-ip-renewal", lookupEnvDuration("HOST_IP_RENEWAL", 1*time.Hour), "Renew host IPs (0 to resolve once and disable renewal)")
		cleanupBasicAuthIPsInterval = flag.Duration("basic-auth-duration", lookupEnvDuration("BASIC_AUTH_DURATION", 12*time.Hour), "Cleanup Basic Auth authentications (0 to disable)")
	)
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*verbosity)); err != nil {
		log.Fatalf("failed parsing log level: %v", err)
	}

	slog.SetLogLoggerLevel(level)

	users, err := ipauth.ParseUsers(*usersFlag)
	if err != nil {
		log.Fatalf("failed parsing -users: %v", err)
	}

	allowCIDR, err := ipauth.ParsePrefixes(*allowCIDRFlag)
	if err != nil {
		log.Fatalf("failed parsing -allow-cidr: %v", err)
	}

	denyCIDR, err := ipauth.ParsePrefixes(*denyCIDRFlag)
	if err != nil {
		log.Fatalf("failed parsing -deny-cidr: %v", err)
	}

	cfg := ipauth.Config{
		Listen:            *listen,
		Network:           *network,
		Target:            *target,
		StatusPath:        *statusPath,
		Users:             users,
		AllowCIDR:         allowCIDR,
		DenyCIDR:          denyCIDR,
		AllowHosts:        ipauth.SplitList(*allowHostsFlag),
		DenyPrivateIPs:    *denyPrivateIPs,
		TrustedIPHeader:   *trustedIPHeader,
		MaxAttempts:       *maxAttempts,
		BanDuration:       *banDuration,
		HostIPRenewal:     *cleanupHostIPsInterval,
		BasicAuthDuration: *cleanupBasicAuthIPsInterval,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := ipauth.Run(ctx, cfg); err != nil {
		log.Fatalf("ip-auth: %v", err)
	}

	slog.Info("shut down")
}
