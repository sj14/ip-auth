package ipauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// newAuthRequest builds a request carrying the given credentials, or none when
// creds is nil. Its context is already canceled so that BasicAuth's 5 second
// failure tarpit returns immediately instead of stalling the test.
func newAuthRequest(creds *Credentials) *http.Request {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	if creds != nil {
		r.SetBasicAuth(creds.Name, creds.Password)
	}
	return r
}

func newAuthController(users []Credentials, maxAttempts uint64) *controller {
	return &controller{
		cfg:   Config{Users: users, MaxAttempts: maxAttempts},
		state: state{bannedIPs: map[netip.Addr]banInfo{}},
	}
}

func TestControllerBasicAuth(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.7")
	users := []Credentials{
		{Name: "alice", Password: "secret"},
		{Name: "bob", Password: "hunter2"},
	}

	tests := []struct {
		name         string
		users        []Credentials
		creds        *Credentials
		wantErr      bool
		wantAttempts uint64
	}{
		{
			name:    "first user matches",
			users:   users,
			creds:   &Credentials{Name: "alice", Password: "secret"},
			wantErr: false,
		},
		{
			name:    "later user in the list matches",
			users:   users,
			creds:   &Credentials{Name: "bob", Password: "hunter2"},
			wantErr: false,
		},
		{
			// Regression: a colon in the password must survive parsing and compare.
			name:    "password containing a colon",
			users:   []Credentials{{Name: "alice", Password: "p@ss:word"}},
			creds:   &Credentials{Name: "alice", Password: "p@ss:word"},
			wantErr: false,
		},
		{
			name:         "wrong password",
			users:        users,
			creds:        &Credentials{Name: "alice", Password: "wrong"},
			wantErr:      true,
			wantAttempts: 1,
		},
		{
			name:         "wrong user",
			users:        users,
			creds:        &Credentials{Name: "mallory", Password: "secret"},
			wantErr:      true,
			wantAttempts: 1,
		},
		{
			name:         "right password but wrong user",
			users:        users,
			creds:        &Credentials{Name: "bob", Password: "secret"},
			wantErr:      true,
			wantAttempts: 1,
		},
		{
			// An empty name and password compare equal to an absent header, so
			// this must not be mistaken for a match against a configured user.
			name:         "no credentials sent",
			users:        users,
			creds:        nil,
			wantErr:      true,
			wantAttempts: 1,
		},
		{
			// No users configured means Basic Auth is off; it must reject without
			// recording an attempt, since no credential could ever succeed.
			name:         "no users configured",
			users:        nil,
			creds:        &Credentials{Name: "alice", Password: "secret"},
			wantErr:      true,
			wantAttempts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newAuthController(tt.users, 10)

			err := c.basicAuth(ip, newAuthRequest(tt.creds))

			if tt.wantErr && err == nil {
				t.Fatal("BasicAuth() = nil, want an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("BasicAuth() returned unexpected error: %v", err)
			}

			if got := c.state.bannedIPs[ip].attempts; got != tt.wantAttempts {
				t.Errorf("attempts = %d, want %d", got, tt.wantAttempts)
			}
		})
	}
}

func TestControllerBasicAuthAttemptsAccumulate(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.7")
	c := newAuthController([]Credentials{{Name: "alice", Password: "secret"}}, 10)

	for want := uint64(1); want <= 3; want++ {
		if err := c.basicAuth(ip, newAuthRequest(&Credentials{Name: "alice", Password: "wrong"})); err == nil {
			t.Fatalf("attempt %d: BasicAuth() = nil, want an error", want)
		}
		if got := c.state.bannedIPs[ip].attempts; got != want {
			t.Fatalf("after %d failures attempts = %d, want %d", want, got, want)
		}
	}

	// A success does not clear the record here; HandleIP does that once the IP
	// has been added to the Basic Auth allow list.
	if err := c.basicAuth(ip, newAuthRequest(&Credentials{Name: "alice", Password: "secret"})); err != nil {
		t.Fatalf("BasicAuth() with valid credentials returned: %v", err)
	}
	if got := c.state.bannedIPs[ip].attempts; got != 3 {
		t.Errorf("a success changed attempts to %d, want it left at 3", got)
	}
}

func TestControllerBasicAuthDoesNotExtendBan(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.7")
	const maxAttempts = 3
	c := newAuthController([]Credentials{{Name: "alice", Password: "secret"}}, maxAttempts)

	bad := func() { _ = c.basicAuth(ip, newAuthRequest(&Credentials{Name: "alice", Password: "wrong"})) }

	for range maxAttempts {
		bad()
	}

	banned := c.state.bannedIPs[ip]
	if banned.attempts != maxAttempts {
		t.Fatalf("attempts = %d, want %d", banned.attempts, maxAttempts)
	}
	if banned.bannedAt.IsZero() {
		t.Fatal("bannedAt is zero, want the time of the ban-triggering attempt")
	}

	// Keep hammering once banned: neither the counter nor the ban start may move,
	// otherwise a banned client could keep extending its own ban indefinitely.
	time.Sleep(2 * time.Millisecond)
	bad()
	bad()

	after := c.state.bannedIPs[ip]
	if after.attempts != maxAttempts {
		t.Errorf("attempts after further tries = %d, want it frozen at %d", after.attempts, maxAttempts)
	}
	if !after.bannedAt.Equal(banned.bannedAt) {
		t.Errorf("bannedAt moved from %v to %v, want it frozen", banned.bannedAt, after.bannedAt)
	}
}

func TestControllerBasicAuthMaxAttemptsDisabled(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.7")
	// maxAttempts 0 disables banning, so attempts keep counting and never freeze.
	c := newAuthController([]Credentials{{Name: "alice", Password: "secret"}}, 0)

	for want := uint64(1); want <= 4; want++ {
		if err := c.basicAuth(ip, newAuthRequest(&Credentials{Name: "alice", Password: "wrong"})); err == nil {
			t.Fatalf("attempt %d: BasicAuth() = nil, want an error", want)
		}
		if got := c.state.bannedIPs[ip].attempts; got != want {
			t.Errorf("attempts = %d, want %d", got, want)
		}
	}

	// evaluate must still not treat that record as a ban while banning is off.
	if d := c.evaluate(ip); d.verdict == verdictDenied {
		t.Errorf("evaluate() = denied (%q), want it not banned while max-attempts is 0", d.reason)
	}
}
