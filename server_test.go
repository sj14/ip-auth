package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
