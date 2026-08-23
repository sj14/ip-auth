package main

import (
	"slices"
	"testing"
)

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
