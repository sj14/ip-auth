# IP Auth

There are circumstances where properly setup Basic Auth won't work [[1]](https://github.com/jellyfin/jellyfin-android/issues/123).
IP Auth is a workaround by allowing specific IPs access to the service and proxying the traffic to the original service. Allowed IPs can be specified or dynamically added by passing a Basic Auth login *once* from *any* device on the same IP. Everything is stored in memory and will be lost on restarts.

## Installation

### Binaries

Binaries are available for all major platforms. See the [releases](https://github.com/sj14/ip-auth/releases) page.

### Container

```bash
# do not use the 'main' tag and specify a version or hash instead!
docker pull ghcr.io/sj14/ip-auth:main
```

Add the container as a sidecar and point your endpoints to it.

### Homebrew

Using the [Homebrew](https://brew.sh/) package manager for macOS:

``` text
brew install sj14/tap/ip-auth
```

### Go

It's also possible to install via `go install`:

```console
go install github.com/sj14/ip-auth@latest
```

## Usage

```text
  -allow-cidr string
        allow the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)
  -allow-hosts string
        allow the given host IPs (e.g. example.com)
  -ban-duration duration
        cleanup bans and failed login attempts (0 to disable) (default 1h0m0s)
  -basic-auth-duration duration
        Cleanup Basic Auth authentications (0 to disable) (default 1h0m0s)
  -deny-cidr string
        block the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)
  -deny-private
        deny IPs from the private network space
  -host-ip-renewal duration
        Renew host IPs (0 to resolve once and disable renewal) (default 1h0m0s)
  -ip-header string
        e.g. 'X-Real-Ip' or 'X-Forwarded-For' when you want to extract the IP from the given header (uses the rightmost entry, so put this behind exactly one trusted proxy)
  -listen string
        listen for connections (default ":8080")
  -max-attempts int
        ban IP after max failed auth attempts (0 to disable) (default 10)
  -network string
        tcp, tcp4, tcp6, unix, unixpacket (default "tcp")
  -status-path string
        show info for the requesting IP (default "/ip-auth")
  -target string
        proxy to the given target
  -users string
        allow the given basic auth credentals (e.g. user1:pass1,user2:pass2)
  -verbosity string
        one of 'Debug', 'Info', 'Warn', or 'Error' (default "Info")
```

All options can also be set as environment variables by using their uppercase flag names and changing dashes (-) with underscores (_).

### Running behind a proxy

By default the client IP is taken from the connection itself. When IP Auth runs behind a reverse proxy, that address is the proxy's, so use `-ip-header` to read the client IP from a forwarding header instead.

`X-Forwarded-For` holds a `client, proxy1, proxy2` list, and only the **rightmost** entry is appended by the proxy directly in front of IP Auth — everything to its left can be forged by the client simply sending its own `X-Forwarded-For`. IP Auth therefore uses the rightmost entry, which assumes **exactly one trusted proxy** sits in front of it. With additional hops the rightmost entry is the previous proxy rather than the client.

Only set `-ip-header` when a proxy you control always overwrites or appends to that header. If clients can reach IP Auth directly, they can set the header themselves and choose their own identity.
