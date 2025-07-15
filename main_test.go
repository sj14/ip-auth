package main

import (
	"net/http"
	"net/netip"
	"testing"
	"time"
)

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
		maxAttempts         int
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
