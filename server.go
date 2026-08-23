package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

func (c *Controller) listen(ctx context.Context, addr, network string, handler http.Handler) {
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	listen, err := net.Listen(network, addr)
	if err != nil {
		log.Fatalln(err)
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		slog.Info("listening", "addr", addr, "network", network)
		return srv.Serve(listen)
	})

	g.Go(func() error {
		<-gctx.Done()
		slog.Info("shutting down")
		// Derive the timeout from a live context: gctx is already canceled by
		// the time we get here, so deriving from it would cancel Shutdown
		// immediately instead of letting it drain open connections.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(gctx), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	})

	if err := g.Wait(); err != nil {
		slog.Info("exit", "reason", err)
	}
}

func NewProxy(targetHost string) (*httputil.ReverseProxy, error) {
	if targetHost == "" {
		return nil, errors.New("no target specified")
	}

	// url.Parse accepts almost anything, so check the parts we actually need:
	// without a scheme and host the proxy would silently rewrite every request
	// to an empty URL.
	target, err := url.Parse(targetHost)
	if err != nil {
		return nil, fmt.Errorf("parsing target %q: %w", targetHost, err)
	}

	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("target %q: want an http:// or https:// URL", targetHost)
	}

	if target.Host == "" {
		return nil, fmt.Errorf("target %q: missing host", targetHost)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
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

// rightmostHeaderIP returns the last entry of the last instance of the given
// header, or "" when the header is absent or empty.
//
// Headers like X-Forwarded-For carry a "client, proxy1, proxy2" list in which
// every entry except the last was supplied by something upstream that we do not
// control - a client can simply send its own X-Forwarded-For to forge them.
// Only the rightmost entry is appended by our own immediate proxy, so it is the
// one to trust. That assumes exactly one trusted proxy sits in front of us; with
// more hops the rightmost entry is the previous proxy rather than the client.
func rightmostHeaderIP(r *http.Request, header string) string {
	values := r.Header.Values(header)
	if len(values) == 0 {
		return ""
	}

	// A proxy may append to the existing header line or add another one; either
	// way the last entry of the last line is the most recently appended.
	last := values[len(values)-1]
	if i := strings.LastIndex(last, ","); i >= 0 {
		last = last[i+1:]
	}

	return strings.TrimSpace(last)
}

func (c *Controller) ReadUserIP(r *http.Request) (netip.Addr, error) {
	if c.cfg.trustedIPHeader != "" {
		if ip := rightmostHeaderIP(r, c.cfg.trustedIPHeader); ip != "" {
			slog.Debug("IP from header", "header", c.cfg.trustedIPHeader, "addr", ip)

			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return netip.Addr{}, fmt.Errorf("parsing %q from header %q: %w", ip, c.cfg.trustedIPHeader, err)
			}
			return addr, nil
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

	switch d := c.evaluate(requestIP); d.verdict {
	case verdictAllowed:
		slog.Debug("in allow list", "addr", requestIP.String(), "reason", d.reason)
		return nil
	case verdictDenied:
		return fmt.Errorf("%s (addr=%s)", d.reason, requestIP.String())
	}

	slog.Debug("not in allow list", "addr", requestIP)

	err = c.BasicAuth(requestIP, r)
	if err != nil {
		return err
	}

	slog.Debug("allowed by Basic Auth", "addr", requestIP)
	c.state.mu.Lock()
	c.state.allowIPsByBasicAuth[requestIP] = time.Now()
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
