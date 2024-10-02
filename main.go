package main

import (
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
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
		parsed, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			log.Fatalf("failed parsing %q as duration (%q): %v", val, key, err)
		}
		return time.Duration(parsed)
	}
	return defaultVal
}

type Controller struct {
	mutex           sync.Mutex // one to rule them all
	allowedUsers    []User
	bannedIPs       map[netip.Addr]uint
	denyCIDR        []netip.Prefix
	allowCIDRFix    []netip.Prefix
	allowIPsDynamic []netip.Addr
	denyPrivateIPs  bool
	trustHeaders    bool
	maxAttempts     int
}

func main() {
	var (
		listenAddrAny    = flag.String("listen", lookupEnvString("LISTEN", ":8080"), "listen for IPv4/IPv6 connections")
		listenAddr4      = flag.String("listen4", lookupEnvString("LISTEN4", ":8084"), "listen for IPv4 connections")
		listenAddr6      = flag.String("listen6", lookupEnvString("LISTEN6", ":8086"), "listen for IPv6 connections")
		tlsCert          = flag.String("tls-cert", lookupEnvString("TLS_CERT", ""), "path to TLS cert file")
		tlsKey           = flag.String("tls-key", lookupEnvString("TLS_KEY", ""), "path to TLS key file")
		listenAddrTLSAny = flag.String("tls-listen", lookupEnvString("TLS_LISTEN", ":8180"), "listen for IPv4/IPv6 TLS connections")
		listenAddrTLS4   = flag.String("tls-listen4", lookupEnvString("TLS_LISTEN4", ":8184"), "listen for IPv4 TLS connections")
		listenAddrTLS6   = flag.String("tls-listen6", lookupEnvString("TLS_LISTEN6", ":8186"), "listen for IPv6 TLS connections")
		target           = flag.String("target", lookupEnvString("TARGET", ""), "proxy to the given target")
		verbosity        = flag.Int("verbosity", lookupEnvInt("VERBOSITY", 0), "-4 Debug, 0 Info, 4 Warn, 8 Error")
		maxAttempts      = flag.Int("max-attempts", lookupEnvInt("MAX_ATTEMPTS", 10), "ban IP after max failed auth attempts")
		usersFlag        = flag.String("users", lookupEnvString("USERS", ""), "allow the given basic auth credentals (e.g. user1:pass1,user2:pass2)")
		allowHostsFlag   = flag.String("allow-hosts", lookupEnvString("ALLOW_HOSTS", ""), "allow the given host IPs (e.g. example.com)")
		allowCIDRFlag    = flag.String("allow-cidr", lookupEnvString("ALLOW_CIDR", ""), "allow the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)")
		denyCIDRFlag     = flag.String("deny-cidr", lookupEnvString("DENY_CIDR", ""), "block the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)")
		denyPrivateIPs   = flag.Bool("deny-private", lookupEnvBool("DENY_PRIVATE", false), "deny IPs from the private network space")
		trustHeaders     = flag.Bool("trust-headers", lookupEnvBool("TRUST_HEADERS", false), "trust X-Real-Ip and X-Forwarded-For headers")
		resetInterval    = flag.Duration("reset-interval", lookupEnvDuration("RESET_INTERVAL", 7*24*time.Hour), "Cleanup dynamic IPs and renew host IPs")
	)
	flag.Parse()

	slog.SetLogLoggerLevel(slog.Level(*verbosity))

	c := Controller{
		maxAttempts:    *maxAttempts,
		bannedIPs:      make(map[netip.Addr]uint),
		denyPrivateIPs: *denyPrivateIPs,
		trustHeaders:   *trustHeaders,
	}

	allowedUsers := strings.Split(*usersFlag, ",")
	for _, user := range allowedUsers {
		namePass := strings.Split(user, ":")
		if len(namePass) != 2 {
			slog.Error("malformed user", "user", namePass)
			continue
		}
		c.allowedUsers = append(c.allowedUsers, User{Name: namePass[0], Password: namePass[1]})
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
		go c.generateDynamicIPs(*resetInterval, allowedHosts)
	}

	proxy, err := NewProxy(*target)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", c.ProxyRequestHandler(proxy))

	listen(
		mux,
		*listenAddr4,
		*listenAddr6,
		*listenAddrAny,
	)

	listenTLS(
		mux,
		*tlsCert,
		*tlsKey,
		*listenAddrTLS4,
		*listenAddrTLS6,
		*listenAddrTLSAny,
	)

	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Wait()
}

func listen(mux http.Handler, addrV4, addrV6, addrAny string) {
	go func() {
		if addrV4 == "" {
			return
		}
		listen, err := net.Listen("tcp4", addrV4)
		if err != nil {
			log.Fatalf("failed to listen IPv4 server: %v\n", err)
		}

		slog.Info("listen IPv4", "addr", addrV4)
		err = http.Serve(listen, mux)
		if err != nil {
			log.Fatalf("failed to serve IPv4 server: %v\n", err)
		}
	}()

	go func() {
		if addrV6 == "" {
			return
		}
		listen, err := net.Listen("tcp6", addrV6)
		if err != nil {
			log.Fatalf("failed to listen IPv6 server: %v\n", err)
		}

		slog.Info("listen IPv6", "addr", addrV6)
		err = http.Serve(listen, mux)
		if err != nil {
			log.Fatalf("failed to serve IPv6 server: %v\n", err)
		}
	}()

	go func() {
		if addrAny == "" {
			return
		}
		slog.Info("listen IPv4/IPv6", "addr", addrAny)
		log.Fatal(http.ListenAndServe(addrAny, mux))
	}()
}

func listenTLS(mux http.Handler, cert, key, addrV4, addrV6, addrAny string) {
	if cert == "" || key == "" {
		return
	}

	go func() {
		if addrV4 == "" {
			return
		}
		listen, err := net.Listen("tcp4", addrV4)
		if err != nil {
			log.Fatalf("failed to listen IPv4 TLS server: %v\n", err)
		}

		slog.Info("listen IPv4 TLS", "addr", addrV4)
		err = http.ServeTLS(listen, mux, cert, key)
		if err != nil {
			log.Fatalf("failed to serve IPv4 TLS server: %v\n", err)
		}
	}()

	go func() {
		if addrV6 == "" {
			return
		}
		listen, err := net.Listen("tcp6", addrV6)
		if err != nil {
			log.Fatalf("failed to listen IPv6 TLS server: %v\n", err)
		}

		slog.Info("listen IPv6 TLS", "addr", addrV6)
		err = http.ServeTLS(listen, mux, cert, key)
		if err != nil {
			log.Fatalf("failed to serve IPv6 TLS server: %v\n", err)
		}
	}()

	go func() {
		if addrAny == "" {
			return
		}
		slog.Info("listen IPv4/IPv6 TLS", "addr", addrAny)
		log.Fatal(http.ListenAndServeTLS(addrAny, cert, key, mux))
	}()
}

// Will recheck IPs from hosts and cleanup all dynamic IPs added by basic auth.
func (c *Controller) generateDynamicIPs(resetInterval time.Duration, allowedHosts []string) {
	for {
		for _, host := range allowedHosts {
			c.allowHost(host)
		}

		time.Sleep(resetInterval)
		slog.Info("renewing dynamic IPs")
		c.mutex.Lock()
		c.allowIPsDynamic = []netip.Addr{}
		c.mutex.Unlock()
	}
}

func (c *Controller) allowHost(host string) {
	ips, err := net.LookupIP(host)
	if err != nil {
		slog.Error("lookup ip", "host", host, "error", err)
		return
	}

	for _, ip := range ips {
		nip, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		c.mutex.Lock()
		c.allowIPsDynamic = append(c.allowIPsDynamic, nip)
		c.mutex.Unlock()
		slog.Info("added ip from host", "host", host, "ip", nip.String())
	}
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

type User struct {
	Name     string
	Password string
}

func (c *Controller) BasicAuth(requestIP netip.Addr, w http.ResponseWriter, r *http.Request) error {
	c.mutex.Lock()
	attempts := c.bannedIPs[requestIP]
	c.mutex.Unlock()

	if attempts >= uint(c.maxAttempts) {
		return fmt.Errorf("IP is banned (addr=%s)", requestIP.String())
	}

	givenUser, givenPass, _ := r.BasicAuth()

	if len(c.allowedUsers) == 0 {
		return fmt.Errorf("basic auth disable (no users specified)")
	}

	for _, user := range c.allowedUsers {
		if givenUser == user.Name && givenPass == user.Password {
			slog.Info("success basic auth (address dynamically added)", "user", user.Name)
			return nil
		}
	}

	c.mutex.Lock()
	attempts = c.bannedIPs[requestIP]
	c.bannedIPs[requestIP] = attempts + 1
	c.mutex.Unlock()

	return fmt.Errorf("failed basic auth (user=%s addr=%s attempts=%d)", givenUser, requestIP, attempts)
}

func (c *Controller) HandleIPWrapper(w http.ResponseWriter, r *http.Request) {
	err := c.HandleIP(w, r)
	if err != nil {
		slog.Error("failed handling ip", "error", err)
	}
}

func (c *Controller) ReadUserIP(r *http.Request) (string, error) {
	if c.trustHeaders {
		if ip := r.Header.Get("X-Real-Ip"); ip != "" {
			return ip, nil
		}
		if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			return ip, nil
		}
	}

	addr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("split host port: %w", err)
	}

	return addr, nil
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

	addr, err := c.ReadUserIP(r)
	if err != nil {
		return err
	}

	requestIP := netip.MustParseAddr(addr)
	slog.Debug("request", "addr", requestIP)

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

	if slices.Contains(c.allowIPsDynamic, requestIP) {
		slog.Debug("in allow list (dynamic ip)", "addr", requestIP.String())
		return nil
	}

	slog.Debug("not in allow list", "addr", requestIP)

	err = c.BasicAuth(requestIP, w, r)
	if err != nil {
		return err
	}

	slog.Debug("allowed", "addr", addr)
	c.mutex.Lock()
	c.allowIPsDynamic = append(c.allowIPsDynamic, netip.MustParseAddr(addr))
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
