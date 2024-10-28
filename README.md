# IP Auth

There are circumstances where properly setup Basic Auth won't work [[1]](https://github.com/jellyfin/jellyfin-android/issues/123).
IP Auth is a workaround by allowing specific IPs access to the service and proxying the traffic to the original service. Allowed IPs can be specified or dynamically added by passing a Basic Auth login once (from any device on the same IP). Everything is stored in memory and will be lost on restarts.

## Installation

```bash
# do not use the 'main' tag and specify a hash instead!
docker pull ghcr.io/sj14/ip-auth:main
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
  -ip-header string
    	e.g. 'X-Real-Ip' or 'X-Forwarded-For' when you want to extract the IP from the given header
  -listen string
    	listen for connections (default ":8080")
  -max-attempts int
    	ban IP after max failed auth attempts (default 10)
  -network string
    	tcp, tcp4, tcp6, unix, unixpacket (default "tcp")
  -reset-interval duration
    	Cleanup dynamic IPs and renew host IPs (default 1h0m0s)
  -status-path string
    	show info for the requesting IP (default "/basic-ip-auth")
  -target string
    	proxy to the given target
  -users string
    	allow the given basic auth credentals (e.g. user1:pass1,user2:pass2)
  -verbosity string
    	one of 'Debug', 'Info', 'Warn', or 'Error' (default "Info")
```

All options can also be set as environment variables by using their uppercase flag names and changing dashes (-) with underscores (_).
