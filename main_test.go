package main

import (
	"net/http"
	"net/netip"
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
			controller:       &Controller{maxAttempts: 10},
			addr:             ip,
			wantVerdict:      verdictChallenge,
			wantReasonPrefix: "denied",
		},
		{
			name:             "private IP denied",
			controller:       &Controller{denyPrivateIPs: true},
			addr:             ip,
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied (private IP)",
		},
		{
			// Regression: deny-private must cover loopback, not just IsPrivate().
			name:             "loopback denied as private",
			controller:       &Controller{denyPrivateIPs: true},
			addr:             netip.MustParseAddr("127.0.0.1"),
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied (private IP)",
		},
		{
			// Regression: link-local must be covered too.
			name:             "link-local denied as private",
			controller:       &Controller{denyPrivateIPs: true},
			addr:             netip.MustParseAddr("169.254.1.1"),
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied (private IP)",
		},
		{
			name:             "public IP allowed through deny-private",
			controller:       &Controller{denyPrivateIPs: true, maxAttempts: 10},
			addr:             netip.MustParseAddr("203.0.113.7"),
			wantVerdict:      verdictChallenge,
			wantReasonPrefix: "denied",
		},
		{
			name:             "deny CIDR",
			controller:       &Controller{denyCIDR: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
			addr:             ip,
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied CIDR (10.0.0.0/8)",
		},
		{
			name:             "allow CIDR",
			controller:       &Controller{allowCIDRFix: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
			addr:             ip,
			wantVerdict:      verdictAllowed,
			wantReasonPrefix: "allowed CIDR (10.0.0.0/8)",
		},
		{
			// Regression: deny must win over allow, and Status must agree with HandleIP.
			name: "deny CIDR wins over allow CIDR",
			controller: &Controller{
				denyCIDR:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
				allowCIDRFix: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			},
			addr:             ip,
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "denied CIDR (10.0.0.0/8)",
		},
		{
			name:             "allowed by host",
			controller:       &Controller{allowIPsByHost: []netip.Addr{ip}},
			addr:             ip,
			wantVerdict:      verdictAllowed,
			wantReasonPrefix: "allowed IP by host",
		},
		{
			name:             "allowed by Basic Auth",
			controller:       &Controller{allowIPsByBasicAuth: []basicAuthIP{{ip: ip, allowedAt: authTime}}},
			addr:             ip,
			wantVerdict:      verdictAllowed,
			wantReasonPrefix: "allowed IP by Basic Auth at",
		},
		{
			name: "banned IP denied",
			controller: &Controller{
				maxAttempts: 10,
				bannedIPs:   map[netip.Addr]banInfo{ip: {attempts: 10, bannedAt: banTime}},
			},
			addr:             ip,
			wantVerdict:      verdictDenied,
			wantReasonPrefix: "banned at",
		},
		{
			name: "attempts below threshold still challenges",
			controller: &Controller{
				maxAttempts: 10,
				bannedIPs:   map[netip.Addr]banInfo{ip: {attempts: 9, bannedAt: banTime}},
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
				maxAttempts: 0,
				bannedIPs:   map[netip.Addr]banInfo{ip: {attempts: 99, bannedAt: banTime}},
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
				maxAttempts:    10,
				bannedIPs:      map[netip.Addr]banInfo{ip: {attempts: 99, bannedAt: banTime}},
				allowIPsByHost: []netip.Addr{ip},
			},
			addr:             ip,
			wantVerdict:      verdictAllowed,
			wantReasonPrefix: "allowed IP by host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.controller
			if c.bannedIPs == nil {
				c.bannedIPs = map[netip.Addr]banInfo{}
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

func TestControllerCleanupBasicAuthIPs(t *testing.T) {
	type fields struct {
		allowedUsers        []BasicAuthCredentials
		bannedIPs           map[netip.Addr]banInfo
		denyCIDR            []netip.Prefix
		allowCIDRFix        []netip.Prefix
		allowIPsByHost      []netip.Addr
		allowIPsByBasicAuth []basicAuthIP
		denyPrivateIPs      bool
		trustedIPHeader     string
		maxAttempts         uint64
		mux                 *http.ServeMux
	}
	type args struct {
		resetInterval time.Duration
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantIPlen int
	}{
		{
			name: "not-expire",
			fields: fields{
				allowIPsByBasicAuth: []basicAuthIP{
					{
						ip:        netip.MustParseAddr("10.0.0.1"),
						allowedAt: time.Now(),
					},
				},
			},
			args: args{
				resetInterval: 1 * time.Hour,
			},
			wantIPlen: 1,
		},
		{
			name: "expire",
			fields: fields{
				allowIPsByBasicAuth: []basicAuthIP{
					{
						ip:        netip.MustParseAddr("10.0.0.1"),
						allowedAt: time.Now().Add(-1 * time.Hour),
					},
				},
			},
			args: args{
				resetInterval: 1 * time.Minute,
			},
			wantIPlen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{
				allowedUsers:        tt.fields.allowedUsers,
				bannedIPs:           tt.fields.bannedIPs,
				denyCIDR:            tt.fields.denyCIDR,
				allowCIDRFix:        tt.fields.allowCIDRFix,
				allowIPsByHost:      tt.fields.allowIPsByHost,
				allowIPsByBasicAuth: tt.fields.allowIPsByBasicAuth,
				denyPrivateIPs:      tt.fields.denyPrivateIPs,
				trustedIPHeader:     tt.fields.trustedIPHeader,
				maxAttempts:         tt.fields.maxAttempts,
				mux:                 tt.fields.mux,
			}

			c.cleanupBasicAuthIPs(tt.args.resetInterval)

			if len(c.allowIPsByBasicAuth) != int(tt.wantIPlen) {
				t.Fail()
			}
		})
	}
}
