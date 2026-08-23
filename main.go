package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"
)

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
	err := level.UnmarshalText([]byte(*verbosity))
	if err != nil {
		log.Fatalf("failed parsing log level: %s\n", err)
	}

	slog.SetLogLoggerLevel(level)

	allowedUsers, err := parseUsers(*usersFlag)
	if err != nil {
		log.Fatalf("failed parsing -users: %v", err)
	}

	allowCIDR, err := parsePrefixes(*allowCIDRFlag)
	if err != nil {
		log.Fatalf("failed parsing -allow-cidr: %v", err)
	}

	denyCIDR, err := parsePrefixes(*denyCIDRFlag)
	if err != nil {
		log.Fatalf("failed parsing -deny-cidr: %v", err)
	}

	cfg := config{
		maxAttempts:     *maxAttempts,
		denyPrivateIPs:  *denyPrivateIPs,
		trustedIPHeader: *trustedIPHeader,
		allowedUsers:    allowedUsers,
		allowCIDRFix:    allowCIDR,
		denyCIDR:        denyCIDR,
	}

	c := Controller{
		cfg: cfg,
		state: state{
			bannedIPs:           make(map[netip.Addr]banInfo),
			allowIPsByBasicAuth: make(map[netip.Addr]time.Time),
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Add dynamic IPs and renew frequently
	allowedHosts := splitList(*allowHostsFlag)
	if len(allowedHosts) > 0 {
		go every(ctx, *cleanupHostIPsInterval, func() {
			c.renewAllowIPsByHost(allowedHosts)
		})
	}

	// Cleanup expired Basic Auth IPs
	if *cleanupBasicAuthIPsInterval > 0 {
		go every(ctx, basicAuthSweepInterval, func() {
			c.cleanupBasicAuthIPs(*cleanupBasicAuthIPsInterval)
		})
	}

	// Cleanup bans
	if *banDuration > 0 {
		go every(ctx, banSweepInterval, func() {
			c.cleanupFailedAttempts(*banDuration)
		})
	}

	proxy, err := NewProxy(*target)
	if err != nil {
		log.Fatalf("failed setting up the proxy: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", c.ProxyRequestHandler(proxy))
	mux.HandleFunc(*statusPath, c.Status)

	c.listen(ctx, *listen, *network, mux)

	slog.Info("shut down")
}
