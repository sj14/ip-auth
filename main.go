package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
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
		return time.Duration(duration)
	}
	return defaultVal
}

type banInfo struct {
	attempts uint64
	bannedAt time.Time
}

type basicAuthIP struct {
	ip        netip.Addr
	allowedAt time.Time
}

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

// state holds everything that changes while the server is running. Every field
// here is guarded by mu: never read or write one without holding it.
type state struct {
	mu                  sync.RWMutex
	bannedIPs           map[netip.Addr]banInfo
	allowIPsByHost      []netip.Addr
	allowIPsByBasicAuth []basicAuthIP
}

type Controller struct {
	cfg   config
	state state
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
		trustedIPHeader             = flag.String("ip-header", lookupEnvString("IP_HEADER", ""), "e.g. 'X-Real-Ip' or 'X-Forwarded-For' when you want to extract the IP from the given header")
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

	cfg := config{
		maxAttempts:     *maxAttempts,
		denyPrivateIPs:  *denyPrivateIPs,
		trustedIPHeader: *trustedIPHeader,
	}

	allowedUsers := strings.Split(*usersFlag, ",")
	for _, user := range allowedUsers {
		if user == "" {
			continue
		}
		namePass := strings.SplitN(user, ":", 2)
		if len(namePass) != 2 {
			slog.Error("malformed user", "user", namePass)
			continue
		}
		cfg.allowedUsers = append(cfg.allowedUsers, BasicAuthCredentials{Name: namePass[0], Password: namePass[1]})
	}

	allowedIPs := strings.Split(*allowCIDRFlag, ",")
	if len(allowedIPs) > 0 && allowedIPs[0] != "" {
		for _, ip := range allowedIPs {
			cfg.allowCIDRFix = append(cfg.allowCIDRFix, netip.MustParsePrefix(ip))
		}
	}

	deniedIPs := strings.Split(*denyCIDRFlag, ",")
	if len(deniedIPs) > 0 && deniedIPs[0] != "" {
		for _, ip := range deniedIPs {
			cfg.denyCIDR = append(cfg.denyCIDR, netip.MustParsePrefix(ip))
		}
	}

	c := Controller{
		cfg:   cfg,
		state: state{bannedIPs: make(map[netip.Addr]banInfo)},
	}

	// Add dynamic IPs and renew frequently
	allowedHosts := strings.Split(*allowHostsFlag, ",")
	if len(allowedHosts) > 0 && allowedHosts[0] != "" {
		go c.generateAllowIPsByHost(*cleanupHostIPsInterval, allowedHosts)
	}

	// Cleanup expired Basic Auth IPs
	if *cleanupBasicAuthIPsInterval > 0 {
		go func() {
			for {
				time.Sleep(1 * time.Minute)
				c.cleanupBasicAuthIPs(*cleanupBasicAuthIPsInterval)
			}
		}()
	}

	// Cleanup bans
	if *banDuration > 0 {
		go c.cleanupFailedAttempts(*banDuration)
	}

	proxy, err := NewProxy(*target)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", c.ProxyRequestHandler(proxy))
	mux.HandleFunc(*statusPath, c.Status)

	c.listen(*listen, *network, mux)

	slog.Info("shut down")
}

func (c *Controller) listen(addr, network string, handler http.Handler) {
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	listen, err := net.Listen(network, addr)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

		<-sig
		cancel()
	}()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		slog.Info("listening", "addr", addr, "network", network)
		return srv.Serve(listen)
	})

	g.Go(func() error {
		<-ctx.Done()
		slog.Info("shutting down")
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	})

	if err := g.Wait(); err != nil {
		slog.Info("exit", "reason", err)
	}
}

// Will recheck IPs from hosts and cleanup all dynamic IPs added by basic auth.
func (c *Controller) generateAllowIPsByHost(resetInterval time.Duration, allowedHosts []string) {
	for {
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
		c.state.allowIPsByHost = newIPs
		c.state.mu.Unlock()

		if resetInterval <= 0 {
			// resolve once, renewal disabled
			return
		}

		time.Sleep(resetInterval)
	}
}

func (c *Controller) cleanupBasicAuthIPs(expireInterval time.Duration) {
	slog.Debug("cleanup allowed Basic Auth IPs", "expire interval", expireInterval.String())

	var newIPs []basicAuthIP

	c.state.mu.Lock()
	for _, ipInfo := range c.state.allowIPsByBasicAuth {
		if ipInfo.allowedAt.Add(expireInterval).After(time.Now()) {
			// not yet expired
			newIPs = append(newIPs, ipInfo)
		} else {
			slog.Debug("expired Basic Auth IP",
				"ip", ipInfo.ip.String(),
				"allowed_at", ipInfo.allowedAt,
			)
		}
	}

	c.state.allowIPsByBasicAuth = newIPs
	c.state.mu.Unlock()
}

// Cleanup bans and failed login attempts.
func (c *Controller) cleanupFailedAttempts(banDuration time.Duration) {
	for {
		time.Sleep(5 * time.Minute)

		slog.Debug("cleanup bans and failed logins")

		remainingBans := make(map[netip.Addr]banInfo)

		c.state.mu.Lock()
		for ip, info := range c.state.bannedIPs {
			if info.bannedAt.Add(banDuration).After(time.Now()) {
				// still banned, or not yet expired
				remainingBans[ip] = info
			}
		}

		c.state.bannedIPs = remainingBans
		c.state.mu.Unlock()
	}
}

func isPrivateAddr(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func (c *Controller) hostToIP(host string) ([]netip.Addr, error) {
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

func NewProxy(targetHost string) (*httputil.ReverseProxy, error) {
	url, err := url.Parse(targetHost)
	if err != nil {
		return nil, err
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(url)
			r.Out.Host = r.In.Host // if desired
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				slog.DebugContext(r.Context(), "proxy: client canceled request", "url", r.URL.String())
				return
			}
			slog.ErrorContext(r.Context(), "proxy error", "err", err)
			http.Error(w, "proxy error", http.StatusBadGateway)
		},
	}

	return proxy, nil
}

type BasicAuthCredentials struct {
	Name     string
	Password string
}

// BasicAuth verifies the request credentials and records a failed attempt when
// they don't match. Callers must reject already-banned IPs via evaluate first;
// the ban rule lives there so HandleIP and Status can't disagree about it.
func (c *Controller) BasicAuth(requestIP netip.Addr, w http.ResponseWriter, r *http.Request) error {
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

func (c *Controller) HandleIPWrapper(w http.ResponseWriter, r *http.Request) {
	err := c.HandleIP(w, r)
	if err != nil {
		slog.Error("failed handling ip", "error", err)
	}
}

func (c *Controller) ReadUserIP(r *http.Request) (netip.Addr, error) {
	if c.cfg.trustedIPHeader != "" {
		if ip := r.Header.Get(c.cfg.trustedIPHeader); ip != "" {
			slog.Debug("IP from header", "header", c.cfg.trustedIPHeader, "addr", ip)
			return netip.ParseAddr(ip)
		}
	}

	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("split host port: %w", err)
	}

	slog.Debug("IP from request", "addr", addr)

	return netip.ParseAddr(addr)
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
// HandleIP and Status must both go through here so they can never disagree.
func (c *Controller) evaluate(ip netip.Addr) decision {
	// These fields are only written during startup, before any handler runs,
	// so they need no lock.
	if c.cfg.denyPrivateIPs && isPrivateAddr(ip) {
		return decision{verdictDenied, "denied (private IP)"}
	}

	for _, cidr := range c.cfg.denyCIDR {
		if cidr.Contains(ip) {
			return decision{verdictDenied, fmt.Sprintf("denied CIDR (%s)", cidr.String())}
		}
	}

	for _, cidr := range c.cfg.allowCIDRFix {
		if cidr.Contains(ip) {
			return decision{verdictAllowed, fmt.Sprintf("allowed CIDR (%s)", cidr.String())}
		}
	}

	c.state.mu.RLock()
	defer c.state.mu.RUnlock()

	if slices.Contains(c.state.allowIPsByHost, ip) {
		return decision{verdictAllowed, "allowed IP by host"}
	}

	for _, ipInfo := range c.state.allowIPsByBasicAuth {
		if ipInfo.ip == ip {
			return decision{verdictAllowed, fmt.Sprintf("allowed IP by Basic Auth at %s", ipInfo.allowedAt)}
		}
	}

	if info, ok := c.state.bannedIPs[ip]; ok && c.cfg.maxAttempts > 0 && info.attempts >= c.cfg.maxAttempts {
		return decision{verdictDenied, fmt.Sprintf("banned at %s", info.bannedAt)}
	}

	return decision{verdictChallenge, "denied"}
}

func (c *Controller) HandleIP(w http.ResponseWriter, r *http.Request) (err error) {
	defer func() {
		if err == nil {
			return
		}
		slog.Error("failed allow IP", "error", err)
		w.Header().Set("WWW-Authenticate", `Basic realm=""`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}()

	requestIP, err := c.ReadUserIP(r)
	if err != nil {
		return err
	}

	switch d := c.evaluate(requestIP); d.verdict {
	case verdictAllowed:
		slog.Debug("in allow list", "addr", requestIP.String(), "reason", d.reason)
		return nil
	case verdictDenied:
		return fmt.Errorf("%s (addr=%s)", d.reason, requestIP.String())
	}

	slog.Debug("not in allow list", "addr", requestIP)

	err = c.BasicAuth(requestIP, w, r)
	if err != nil {
		return err
	}

	slog.Debug("allowed by Basic Auth", "addr", requestIP)
	c.state.mu.Lock()
	c.state.allowIPsByBasicAuth = append(c.state.allowIPsByBasicAuth, basicAuthIP{ip: requestIP, allowedAt: time.Now()})
	delete(c.state.bannedIPs, requestIP)
	c.state.mu.Unlock()
	return nil
}

func (c *Controller) ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := c.HandleIP(w, r)
		if err != nil {
			return
		}

		proxy.ServeHTTP(w, r)
	}
}

func (c *Controller) Status(w http.ResponseWriter, r *http.Request) {
	requestIP, err := c.ReadUserIP(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	d := c.evaluate(requestIP)

	fmt.Fprintf(w, "ip: %s\n", requestIP)
	fmt.Fprintf(w, "status: %s\n", d.reason)
}
