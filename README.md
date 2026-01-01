# iploop

Ultra-fast proxy-rotating SOCKS5 server in Go.

## Install

```bash
go install github.com/ogpourya/iploop/cmd/iploop@latest
```

## Usage

```bash
iploop -proxies "http://proxy1:8080,socks5://proxy2:1080"
```

```bash
iploop -proxy-file proxies.txt -strategy sequential
```

Test:
```bash
curl --socks5 localhost:33333 https://icanhazip.com
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:33333` | Listen address |
| `-proxies` | | Comma-separated proxy list |
| `-proxy-file` | | Proxy list file (one per line) |
| `-strategy` | `random` | `random` or `sequential` |
| `-skip-dead` | `false` | Skip failing proxies |
| `-justdoit` | `false` | Keep retrying until success |
| `-trust-proxy` | `true` | Trust upstream proxy TLS certificates (HTTPS proxies only) |
| `-metrics` | `true` | Terminal metrics display |
| `-v` | `false` | Verbose output |

### TLS Note

The `-trust-proxy` flag controls TLS verification when connecting to HTTPS proxy servers (e.g., `https://proxy:8080`). HTTP proxies don't use TLS for the proxy connection itself, so this flag doesn't apply to them. Destination TLS (e.g., when you curl an HTTPS site) is handled end-to-end by your client, not by iploop.

## Supported Proxies

- HTTP (`http://host:port`)
- HTTPS (`https://host:port`)
- SOCKS4 (`socks4://host:port`)
- SOCKS5 (`socks5://host:port`)

Authentication: `http://user:pass@host:port`

## License

MIT
