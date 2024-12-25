package main

import (
	"context"
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

func lookupEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		parsed, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalf("failed parsing %q as int (%q): %v", val, key, err)
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
	attempts uint
	bannedAt time.Time
}

type basicAuthIP struct {
	ip        netip.Addr
	allowedAt time.Time
}

type Controller struct {
	mutex               sync.RWMutex // one to rule them all
	allowedUsers        []BasicAuthCredentials
	bannedIPs           map[netip.Addr]banInfo
	denyCIDR            []netip.Prefix
	allowCIDRFix        []netip.Prefix
	allowIPsByHost      []netip.Addr
	allowIPsByBasicAuth []basicAuthIP
	denyPrivateIPs      bool
	trustedIPHeader     string
	maxAttempts         int
	mux                 *http.ServeMux
}

func main() {
	var (
		statusPath                  = flag.String("status-path", lookupEnvString("STATUS_PATH", "/ip-auth"), "show info for the requesting IP")
		listen                      = flag.String("listen", lookupEnvString("LISTEN", ":8080"), "listen for connections")
		network                     = flag.String("network", lookupEnvString("NETWORK", "tcp"), "tcp, tcp4, tcp6, unix, unixpacket")
		target                      = flag.String("target", lookupEnvString("TARGET", ""), "proxy to the given target")
		verbosity                   = flag.String("verbosity", lookupEnvString("VERBOSITY", "Info"), "one of 'Debug', 'Info', 'Warn', or 'Error'")
		maxAttempts                 = flag.Int("max-attempts", lookupEnvInt("MAX_ATTEMPTS", 10), "ban IP after max failed auth attempts (0 to disable)")
		banDuration                 = flag.Duration("ban-duration", lookupEnvDuration("BAN_DURATION", 1*time.Hour), "cleanup bans and failed login attempts (0 to disable)")
		usersFlag                   = flag.String("users", lookupEnvString("USERS", ""), "allow the given basic auth credentals (e.g. user1:pass1,user2:pass2)")
		allowHostsFlag              = flag.String("allow-hosts", lookupEnvString("ALLOW_HOSTS", ""), "allow the given host IPs (e.g. example.com)")
		allowCIDRFlag               = flag.String("allow-cidr", lookupEnvString("ALLOW_CIDR", ""), "allow the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)")
		denyCIDRFlag                = flag.String("deny-cidr", lookupEnvString("DENY_CIDR", ""), "block the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)")
		denyPrivateIPs              = flag.Bool("deny-private", lookupEnvBool("DENY_PRIVATE", false), "deny IPs from the private network space")
		trustedIPHeader             = flag.String("ip-header", lookupEnvString("IP_HEADER", ""), "e.g. 'X-Real-Ip' or 'X-Forwarded-For' when you want to extract the IP from the given header")
		cleanupHostIPsInterval      = flag.Duration("host-ip-renewal", lookupEnvDuration("HOST_IP_RENEWAL", 1*time.Hour), "Renew host IPs")
		cleanupBasicAuthIPsInterval = flag.Duration("basic-auth-duration", lookupEnvDuration("BASIC_AUTH_DURATION", 1*time.Hour), "Cleanup Basic Auth authentications (0 to disable)")
	)
	flag.Parse()

	var level slog.Level
	err := level.UnmarshalText([]byte(*verbosity))
	if err != nil {
		log.Fatalf("failed parsing log level: %s\n", err)
	}

	slog.SetLogLoggerLevel(level)

	c := Controller{
		maxAttempts:     *maxAttempts,
		bannedIPs:       make(map[netip.Addr]banInfo),
		denyPrivateIPs:  *denyPrivateIPs,
		trustedIPHeader: *trustedIPHeader,
	}

	allowedUsers := strings.Split(*usersFlag, ",")
	for _, user := range allowedUsers {
		if user == "" {
			continue
		}
		namePass := strings.Split(user, ":")
		if len(namePass) != 2 {
			slog.Error("malformed user", "user", namePass)
			continue
		}
		c.allowedUsers = append(c.allowedUsers, BasicAuthCredentials{Name: namePass[0], Password: namePass[1]})
	}

	allowedIPs := strings.Split(*allowCIDRFlag, ",")
	if len(allowedIPs) > 0 && allowedIPs[0] != "" {
		for _, ip := range allowedIPs {
			c.allowCIDRFix = append(c.allowCIDRFix, netip.MustParsePrefix(ip))
		}
	}

	deniedIPs := strings.Split(*denyCIDRFlag, ",")
	if len(deniedIPs) > 0 && deniedIPs[0] != "" {
		for _, ip := range deniedIPs {
			c.denyCIDR = append(c.denyCIDR, netip.MustParsePrefix(ip))
		}
	}

	// Add dynamic IPs and renew frequently
	allowedHosts := strings.Split(*allowHostsFlag, ",")
	if len(allowedHosts) > 0 && allowedHosts[0] != "" {
		go c.generateAllowIPsByHost(*cleanupHostIPsInterval, allowedHosts)
	}

	// Cleanup expired Basic Auth IPs
	if *cleanupBasicAuthIPsInterval > 0 {
		go c.cleanupBasicAuthIPs(*cleanupBasicAuthIPsInterval)
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

	c.mux = mux

	c.listen(*listen, *network)

	slog.Info("shut down")
}

func (c *Controller) listen(addr, network string) {
	srv := &http.Server{
		Addr:    addr,
		Handler: c.mux,
	}

	listen, err := net.Listen(network, addr)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)

		<-c
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
			newIPs = append(newIPs, hostIPs...)
		}

		c.mutex.Lock()
		c.allowIPsByHost = newIPs
		c.mutex.Unlock()

		time.Sleep(resetInterval)
	}
}

func (c *Controller) cleanupBasicAuthIPs(resetInterval time.Duration) {
	for {
		time.Sleep(5 * time.Minute)

		slog.Info("cleanup allowed Basic Auth IPs", "expire interval", resetInterval.String())

		var newIPs []basicAuthIP

		c.mutex.Lock()
		for _, ipInfo := range c.allowIPsByBasicAuth {
			if ipInfo.allowedAt.Add(resetInterval).Before(time.Now()) {
				// not yet expired
				newIPs = append(newIPs, ipInfo)
			} else {
				slog.Debug("expired Basic Auth IP", "ip", ipInfo.ip.String())
			}
		}

		c.allowIPsByBasicAuth = newIPs
		c.mutex.Unlock()
	}
}

// Cleanup bans and failed login attempts.
func (c *Controller) cleanupFailedAttempts(banDuration time.Duration) {
	for {
		time.Sleep(5 * time.Minute)

		slog.Info("cleanup bans and failed logins")

		remainingBans := make(map[netip.Addr]banInfo)

		c.mutex.Lock()
		for ip, info := range c.bannedIPs {
			if info.bannedAt.Add(banDuration).Before(time.Now()) {
				// still banned
				remainingBans[ip] = info
			}
		}

		c.bannedIPs = remainingBans
		c.mutex.Unlock()
	}
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
	}

	return proxy, nil
}

type BasicAuthCredentials struct {
	Name     string
	Password string
}

func (c *Controller) BasicAuth(requestIP netip.Addr, w http.ResponseWriter, r *http.Request) error {
	c.mutex.Lock()
	banInfo := c.bannedIPs[requestIP]
	c.mutex.Unlock()

	if c.maxAttempts > 0 && banInfo.attempts >= uint(c.maxAttempts) {
		return fmt.Errorf("IP is banned (addr=%s)", requestIP.String())
	}

	givenUser, givenPass, _ := r.BasicAuth()

	if len(c.allowedUsers) == 0 {
		return fmt.Errorf("basic auth disabled (no users specified)")
	}

	for _, user := range c.allowedUsers {
		if givenUser == user.Name && givenPass == user.Password {
			slog.Info("success basic auth (address dynamically added)", "addr", requestIP.String(), "user", user.Name)
			return nil
		}
	}

	c.mutex.Lock()
	banInfo = c.bannedIPs[requestIP]
	banInfo.attempts += 1
	if banInfo.attempts == uint(c.maxAttempts) {
		banInfo.bannedAt = time.Now()
	}
	c.bannedIPs[requestIP] = banInfo
	c.mutex.Unlock()

	// login failed, add a tarpit
	defer func() {
		select {
		case <-r.Context().Done():
			slog.DebugContext(r.Context(), "tarpit: client closed connection")
		case <-time.After(3 * time.Second):
			slog.DebugContext(r.Context(), "tarpit: delayed by 3 seconds")
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
	if c.trustedIPHeader != "" {
		if ip := r.Header.Get(c.trustedIPHeader); ip != "" {
			slog.Debug("IP from header", "header", c.trustedIPHeader, "addr", ip)
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

	if c.denyPrivateIPs {
		if requestIP.IsPrivate() || requestIP.IsLoopback() || requestIP.IsLinkLocalUnicast() || requestIP.IsLinkLocalMulticast() {
			return fmt.Errorf("private IPs are blocked (addr=%s)", requestIP.String())
		}
	}

	for _, cidr := range c.denyCIDR {
		if cidr.Contains(requestIP) {
			return fmt.Errorf("in deny list (addr=%s)", requestIP.String())
		}
	}

	for _, cidr := range c.allowCIDRFix {
		if cidr.Contains(requestIP) {
			slog.Debug("in allow list (fixed ip)", "addr", requestIP.String())
			return nil
		}
	}

	if slices.Contains(c.allowIPsByHost, requestIP) {
		slog.Debug("in allow list (host)", "addr", requestIP.String())
		return nil
	}

	for _, ipInfo := range c.allowIPsByBasicAuth {
		if ipInfo.ip == requestIP {
			slog.Debug("in allow list (basic auth)", "addr", requestIP.String())
			return nil
		}
	}

	slog.Debug("not in allow list", "addr", requestIP)

	err = c.BasicAuth(requestIP, w, r)
	if err != nil {
		return err
	}

	slog.Debug("allowed by Basic Auth", "addr", requestIP)
	c.mutex.Lock()
	c.allowIPsByBasicAuth = append(c.allowIPsByBasicAuth, basicAuthIP{ip: requestIP, allowedAt: time.Now()})
	c.mutex.Unlock()
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

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	status := "denied"

	if requestIP.IsPrivate() && c.denyPrivateIPs {
		status = "denied (private IP)"
	}

	for ip, banInfo := range c.bannedIPs {
		if ip == requestIP && banInfo.attempts >= uint(c.maxAttempts) {
			status = fmt.Sprintf("banned at %s", banInfo.bannedAt)
			break
		}
	}

	for _, cidr := range c.denyCIDR {
		if cidr.Contains(requestIP) {
			status = fmt.Sprintf("denied CIDR (%s)", cidr.String())
			break
		}
	}
	for _, cidr := range c.allowCIDRFix {
		if cidr.Contains(requestIP) {
			status = fmt.Sprintf("allowed CIDR (%s)", cidr.String())
			break
		}
	}
	if slices.Contains(c.allowIPsByHost, requestIP) {
		status = "allowed IP by host"
	}

	for _, ipInfo := range c.allowIPsByBasicAuth {
		if ipInfo.ip == requestIP {
			status = fmt.Sprintf("allowed IP by Basic Auth at %s", ipInfo.allowedAt)
			break
		}
	}

	w.Write([]byte(fmt.Sprintf("ip: %s\n", requestIP)))
	w.Write([]byte(fmt.Sprintf("status: %s\n", status)))
}
