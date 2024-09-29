# Basic IP Auth

There are circumstances where properly setup Basic Auth won't work [[1]](https://github.com/jellyfin/jellyfin-android/issues/123).
Basic API Auth is a workaround by allowing specific IPs access to the service and proxying the traffic to the original service. Allowed IPs can be specified or dynamically added by passing a Basic Auth login once (from any device on the same IP). Everything is stored in memory and will be lost on restarts.

## Installation

```bash
# do not use latest and specify a hash instead!
docker pull ghcr.io/sj14/basic-ip-auth:latest
```

Add the container as a sidecar and point your endpoints to it.

## Usage

```text
  -allow-cidr string
        allow the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)
  -allow-hosts string
        allow the given host IPs (e.g. example.com)
  -deny-cidr string
        block the given CIDR (e.g. 10.0.0.0/8,192.168.0.0/16)
  -deny-private
        deny IPs from the private network space
  -listen string
        listen for IPv4/IPv6 connections (default ":8080")
  -listen4 string
        listen for IPv4 connections (default ":8084")
  -listen6 string
        listen for IPv6 connections (default ":8086")
  -max-attempts int
        ban IP after max failed auth attempts (default 10)
  -reset-interval duration
        Cleanup dynamic IPs and renew host IPs (default 168h0m0s)
  -target string
        proxy to the given target
  -users string
        allow the given basic auth credentals (e.g. user1:pass1,user2:pass2)
  -verbosity int
        -4 Debug, 0 Info, 4 Warn, 8 Error
```

All options can also be set as environment variables by using their uppercase flag names and changing dashes (-) with underscores (_).
