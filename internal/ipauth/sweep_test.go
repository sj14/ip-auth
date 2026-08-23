package ipauth

import (
	"net/netip"
	"testing"
	"time"
)

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
			c := &controller{
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
