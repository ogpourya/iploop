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
| `-trust-proxy` | `true` | Skip TLS verification for HTTPS proxies |
| `-metrics` | `true` | Terminal metrics display |
| `-v` | `false` | Verbose output |

## Supported Proxies

- HTTP (`http://host:port`)
- HTTPS (`https://host:port`)
- SOCKS4 (`socks4://host:port`)
- SOCKS5 (`socks5://host:port`)

Authentication: `http://user:pass@host:port`

## License

MIT
