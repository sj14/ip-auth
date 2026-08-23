package main

import (
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
