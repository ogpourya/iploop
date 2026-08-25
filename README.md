# iploop

SOCKS5 proxy rotator. Feeds proxies through xray, HTTP, HTTPS, SOCKS4/5 — rotates them per request.

```
go install github.com/ogpourya/iploop/cmd/iploop@latest
```

## Examples

```bash
# Rotate through traditional proxies
iploop -proxies "http://p1:8080,socks5://p2:1080"

# Rotate through xray nodes (auto-detected from share links)
iploop -proxies "vless://uuid@host:443?type=ws&security=tls&sni=x.com&path=/ws"

# Mix xray and regular proxies
iploop -proxies "vless://u@a:443?type=ws&path=/,socks5://10.0.0.1:1080"

# Load from file (supports xray links too)
iploop -proxy-file proxies.txt

# Test the SOCKS5 listener
curl --socks5 localhost:33333 https://icanhazip.com
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:33333` | SOCKS5 listen address |
| `-proxies` | | Comma-separated proxy list |
| `-proxy-file` | | Proxy list file (one per line) |
| `-strategy` | `sequential` | `sequential` or `random` |
| `-skip-dead` | `false` | Skip dead proxies instead of retrying |
| `-requests-per-proxy` | `1` | Requests before rotation (`auto` to stay while alive) |
| `-retry-delay` | `100` | Retry delay in ms |
| `-dial-timeout` | `5` | Dial timeout in seconds |
| `-metrics` | `true` | Terminal metrics |
| `-no-dns` | `false` | Skip local DNS; pass hostnames as-is to upstream proxies |
| `-trust-proxy` | `true` | Skip TLS verification for HTTPS proxies |
| `-v` | `false` | Verbose logging |

## Supported inputs

- **HTTP** — `http://host:port`, `http://user:pass@host:port`
- **HTTPS** — `https://host:port`
- **SOCKS4** — `socks4://host:port`
- **SOCKS5** — `socks5://host:port`
- **Xray** — `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `hy2://`, `wireguard://`, `wg://`

Xray binary and geoip/geosite data are auto-downloaded from official repositories on first use if not found in `$PATH` or `~/.local/bin`. SHA256 checksums verified. Each link spawns an xray process with no logging, DNS through outbound, and a SOCKS5 inbound on a random port.

## License

MIT
