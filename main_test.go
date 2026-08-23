package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestControllerEvaluate(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.5")
	banTime := time.Now().Add(-5 * time.Minute)
	authTime := time.Now().Add(-1 * time.Minute)

	tests := []struct {
		name             string
		controller       *Controller
		addr             netip.Addr
		wantVerdict      verdict
		wantReasonPrefix string
	}{
		{
			name:             "unknown IP falls through to Basic Auth",
			controller:       &Controller{cfg: config{maxAttempts: 10}},
			addr:             ip,
			wantVerdict:      verdictChallenge,
			wantReasonPrefix: "denied",
		},
		{
			name:             "private IP denied",
			controller:       &Controller{cfg: config{denyPrivateIPs: true}},
			addr:             ip,
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied (private IP)",
		},
		{
			// Regression: deny-private must cover loopback, not just IsPrivate().
			name:             "loopback denied as private",
			controller:       &Controller{cfg: config{denyPrivateIPs: true}},
			addr:             netip.MustParseAddr("127.0.0.1"),
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied (private IP)",
		},
		{
			// Regression: link-local must be covered too.
			name:             "link-local denied as private",
			controller:       &Controller{cfg: config{denyPrivateIPs: true}},
			addr:             netip.MustParseAddr("169.254.1.1"),
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied (private IP)",
		},
		{
			name:             "public IP allowed through deny-private",
			controller:       &Controller{cfg: config{denyPrivateIPs: true, maxAttempts: 10}},
			addr:             netip.MustParseAddr("203.0.113.7"),
			wantVerdict:      verdictChallenge,
			wantReasonPrefix: "denied",
		},
		{
			name:             "deny CIDR",
			controller:       &Controller{cfg: config{denyCIDR: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}},
			addr:             ip,
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied CIDR (10.0.0.0/8)",
		},
		{
			name:             "allow CIDR",
			controller:       &Controller{cfg: config{allowCIDRFix: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}},
			addr:             ip,
			wantVerdict:      verdictAllowed,
			wantReasonPrefix: "allowed CIDR (10.0.0.0/8)",
		},
		{
			// Regression: deny must win over allow, and Status must agree with HandleIP.
			name: "deny CIDR wins over allow CIDR",
			controller: &Controller{cfg: config{
				denyCIDR:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
				allowCIDRFix: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			}},
			addr:             ip,
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied CIDR (10.0.0.0/8)",
		},
		{
			name:             "allowed by host",
			controller:       &Controller{state: state{allowIPsByHost: []netip.Addr{ip}}},
			addr:             ip,
			wantVerdict:      verdictAllowed,
			wantReasonPrefix: "allowed IP by host",
		},
		{
			name:             "allowed by Basic Auth",
			controller:       &Controller{state: state{allowIPsByBasicAuth: map[netip.Addr]time.Time{ip: authTime}}},
			addr:             ip,
			wantVerdict:      verdictAllowed,
			wantReasonPrefix: "allowed IP by Basic Auth at",
		},
		{
			name: "banned IP denied",
			controller: &Controller{
				cfg:   config{maxAttempts: 10},
				state: state{bannedIPs: map[netip.Addr]banInfo{ip: {attempts: 10, bannedAt: banTime}}},
			},
			addr:             ip,
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "banned at",
		},
		{
			name: "attempts below threshold still challenges",
			controller: &Controller{
				cfg:   config{maxAttempts: 10},
				state: state{bannedIPs: map[netip.Addr]banInfo{ip: {attempts: 9, bannedAt: banTime}}},
			},
			addr:             ip,
			wantVerdict:      verdictChallenge,
			wantReasonPrefix: "denied",
		},
		{
			// Regression: max-attempts=0 disables banning, so a recorded
			// attempt must not read as banned.
			name: "banning disabled reports not banned",
			controller: &Controller{
				cfg:   config{maxAttempts: 0},
				state: state{bannedIPs: map[netip.Addr]banInfo{ip: {attempts: 99, bannedAt: banTime}}},
			},
			addr:             ip,
			wantVerdict:      verdictChallenge,
			wantReasonPrefix: "denied",
		},
		{
			// An allow list wins over a ban record: HandleIP returns before
			// ever reaching the Basic Auth challenge.
			name: "allow list beats ban record",
			controller: &Controller{
				cfg: config{maxAttempts: 10},
				state: state{
					bannedIPs:      map[netip.Addr]banInfo{ip: {attempts: 99, bannedAt: banTime}},
					allowIPsByHost: []netip.Addr{ip},
				},
			},
			addr:             ip,
			wantVerdict:      verdictAllowed,
			wantReasonPrefix: "allowed IP by host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.controller
			if c.state.bannedIPs == nil {
				c.state.bannedIPs = map[netip.Addr]banInfo{}
			}

			got := c.evaluate(tt.addr)

			if got.verdict != tt.wantVerdict {
				t.Errorf("verdict = %v, want %v (reason %q)", got.verdict, tt.wantVerdict, got.reason)
			}
			if !strings.HasPrefix(got.reason, tt.wantReasonPrefix) {
				t.Errorf("reason = %q, want prefix %q", got.reason, tt.wantReasonPrefix)
			}
		})
	}
}

func TestParseUsers(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []BasicAuthCredentials
		wantErr bool
	}{
		{name: "empty", value: "", want: nil},
		{
			name:  "single",
			value: "alice:secret",
			want:  []BasicAuthCredentials{{Name: "alice", Password: "secret"}},
		},
		{
			name:  "multiple",
			value: "alice:secret,bob:hunter2",
			want:  []BasicAuthCredentials{{Name: "alice", Password: "secret"}, {Name: "bob", Password: "hunter2"}},
		},
		{
			name:  "spaces around separators",
			value: "alice:secret, bob:hunter2",
			want:  []BasicAuthCredentials{{Name: "alice", Password: "secret"}, {Name: "bob", Password: "hunter2"}},
		},
		{
			name:  "trailing comma",
			value: "alice:secret,",
			want:  []BasicAuthCredentials{{Name: "alice", Password: "secret"}},
		},
		{
			// Regression: a colon in the password must not drop the user.
			name:  "colon in password",
			value: "alice:p@ss:word",
			want:  []BasicAuthCredentials{{Name: "alice", Password: "p@ss:word"}},
		},
		{name: "missing colon", value: "alice", wantErr: true},
		{name: "missing name", value: ":secret", wantErr: true},
		{name: "one bad entry fails the lot", value: "alice:secret,bob", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUsers(tt.value)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseUsers(%q) = %v, want an error", tt.value, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseUsers(%q) returned unexpected error: %v", tt.value, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("parseUsers(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestParsePrefixes(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []string
		wantErr bool
	}{
		{name: "empty", value: "", want: nil},
		{name: "single", value: "10.0.0.0/8", want: []string{"10.0.0.0/8"}},
		{
			name:  "multiple",
			value: "10.0.0.0/8,192.168.0.0/16",
			want:  []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		{
			name:  "spaces around separators",
			value: "10.0.0.0/8, 192.168.0.0/16",
			want:  []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
		{name: "trailing comma", value: "10.0.0.0/8,", want: []string{"10.0.0.0/8"}},
		{name: "IPv6", value: "2001:db8::/32", want: []string{"2001:db8::/32"}},
		{name: "bare IP without mask", value: "10.0.0.1", wantErr: true},
		{name: "nonsense", value: "not-a-cidr", wantErr: true},
		{name: "one bad entry fails the lot", value: "10.0.0.0/8,nope", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePrefixes(tt.value)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePrefixes(%q) = %v, want an error", tt.value, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("parsePrefixes(%q) returned unexpected error: %v", tt.value, err)
			}

			var gotStr []string
			for _, p := range got {
				gotStr = append(gotStr, p.String())
			}
			if !slices.Equal(gotStr, tt.want) {
				t.Errorf("parsePrefixes(%q) = %v, want %v", tt.value, gotStr, tt.want)
			}
		})
	}
}

func TestControllerReadUserIP(t *testing.T) {
	tests := []struct {
		name       string
		header     string   // configured -ip-header
		headerVals []string // instances of that header on the request
		remoteAddr string
		want       string
		wantErr    bool
	}{
		{
			name:       "no header configured uses RemoteAddr",
			remoteAddr: "203.0.113.7:5555",
			want:       "203.0.113.7",
		},
		{
			name:       "configured header absent falls back to RemoteAddr",
			header:     "X-Forwarded-For",
			remoteAddr: "203.0.113.7:5555",
			want:       "203.0.113.7",
		},
		{
			name:       "empty header value falls back to RemoteAddr",
			header:     "X-Forwarded-For",
			headerVals: []string{""},
			remoteAddr: "203.0.113.7:5555",
			want:       "203.0.113.7",
		},
		{
			name:       "X-Real-Ip single value",
			header:     "X-Real-Ip",
			headerVals: []string{"198.51.100.9"},
			remoteAddr: "10.0.0.1:5555",
			want:       "198.51.100.9",
		},
		{
			// Regression: the whole list used to be handed to ParseAddr, which
			// rejected it, so every request behind a proxy chain got a 401.
			name:       "X-Forwarded-For chain takes rightmost",
			header:     "X-Forwarded-For",
			headerVals: []string{"203.0.113.7, 70.41.3.18, 150.172.238.178"},
			remoteAddr: "10.0.0.1:5555",
			want:       "150.172.238.178",
		},
		{
			// A client forging the header cannot displace the entry its own
			// proxy appends to the right of it.
			name:       "forged leftmost entry is ignored",
			header:     "X-Forwarded-For",
			headerVals: []string{"1.2.3.4, 198.51.100.9"},
			remoteAddr: "10.0.0.1:5555",
			want:       "198.51.100.9",
		},
		{
			name:       "repeated header lines take the last",
			header:     "X-Forwarded-For",
			headerVals: []string{"1.2.3.4", "198.51.100.9"},
			remoteAddr: "10.0.0.1:5555",
			want:       "198.51.100.9",
		},
		{
			name:       "no spaces after comma",
			header:     "X-Forwarded-For",
			headerVals: []string{"203.0.113.7,198.51.100.9"},
			remoteAddr: "10.0.0.1:5555",
			want:       "198.51.100.9",
		},
		{
			name:       "IPv6 value",
			header:     "X-Forwarded-For",
			headerVals: []string{"2001:db8::1, 2001:db8::2"},
			remoteAddr: "10.0.0.1:5555",
			want:       "2001:db8::2",
		},
		{
			name:       "malformed header errors",
			header:     "X-Forwarded-For",
			headerVals: []string{"not-an-ip"},
			remoteAddr: "10.0.0.1:5555",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{cfg: config{trustedIPHeader: tt.header}}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			for _, v := range tt.headerVals {
				r.Header.Add(tt.header, v)
			}

			got, err := c.ReadUserIP(r)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("ReadUserIP() = %v, want an error", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("ReadUserIP() returned unexpected error: %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("ReadUserIP() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestNewProxy(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{name: "http", target: "http://example.com", wantErr: false},
		{name: "https with port and path", target: "https://example.com:8443/base", wantErr: false},
		{name: "localhost", target: "http://127.0.0.1:9000", wantErr: false},
		{name: "empty", target: "", wantErr: true},
		{name: "no scheme", target: "example.com:9000", wantErr: true},
		{name: "scheme relative", target: "//example.com", wantErr: true},
		{name: "missing host", target: "http://", wantErr: true},
		{name: "unsupported scheme", target: "ftp://example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := NewProxy(tt.target)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("NewProxy(%q) = nil error, want an error", tt.target)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewProxy(%q) returned unexpected error: %v", tt.target, err)
			}
			if proxy == nil {
				t.Fatalf("NewProxy(%q) returned a nil proxy", tt.target)
			}
		})
	}
}

func TestControllerCleanupBasicAuthIPs(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")

	tests := []struct {
		name           string
		allowedAt      time.Time
		expireInterval time.Duration
		wantIPlen      int
	}{
		{
			name:           "not-expire",
			allowedAt:      time.Now(),
			expireInterval: 1 * time.Hour,
			wantIPlen:      1,
		},
		{
			name:           "expire",
			allowedAt:      time.Now().Add(-1 * time.Hour),
			expireInterval: 1 * time.Minute,
			wantIPlen:      0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{
				state: state{
					allowIPsByBasicAuth: map[netip.Addr]time.Time{ip: tt.allowedAt},
				},
			}

			c.cleanupBasicAuthIPs(tt.expireInterval)

			if got := len(c.state.allowIPsByBasicAuth); got != tt.wantIPlen {
				t.Errorf("allowIPsByBasicAuth len = %d, want %d", got, tt.wantIPlen)
			}
		})
	}
}
