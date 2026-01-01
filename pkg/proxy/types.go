package proxy

import (
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

type ProxyType int

const (
	ProxyTypeHTTP ProxyType = iota
	ProxyTypeHTTPS
	ProxyTypeSOCKS4
	ProxyTypeSOCKS5
)

func (t ProxyType) String() string {
	switch t {
	case ProxyTypeHTTP:
		return "HTTP"
	case ProxyTypeHTTPS:
		return "HTTPS"
	case ProxyTypeSOCKS4:
		return "SOCKS4"
	case ProxyTypeSOCKS5:
		return "SOCKS5"
	default:
		return "UNKNOWN"
	}
}

type Proxy struct {
	Type     ProxyType
	Host     string
	Port     string
	Username string
	Password string

	requests  atomic.Int64
	failures  atomic.Int64
	totalTime atomic.Int64
	alive     atomic.Bool
}

func NewProxy(rawURL string) (*Proxy, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("empty proxy URL")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing hostname")
	}

	p := &Proxy{
		Host: host,
		Port: u.Port(),
	}
	p.alive.Store(true)

	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}

	switch strings.ToLower(u.Scheme) {
	case "http":
		p.Type = ProxyTypeHTTP
		if p.Port == "" {
			p.Port = "80"
		}
	case "https":
		p.Type = ProxyTypeHTTPS
		if p.Port == "" {
			p.Port = "443"
		}
	case "socks4":
		p.Type = ProxyTypeSOCKS4
		if p.Port == "" {
			p.Port = "1080"
		}
	case "socks5":
		p.Type = ProxyTypeSOCKS5
		if p.Port == "" {
			p.Port = "1080"
		}
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}

	return p, nil
}

func (p *Proxy) Address() string {
	return p.Host + ":" + p.Port
}

func (p *Proxy) String() string {
	return fmt.Sprintf("%s://%s:%s", strings.ToLower(p.Type.String()), p.Host, p.Port)
}

func (p *Proxy) RecordRequest(latency time.Duration) {
	p.requests.Add(1)
	p.totalTime.Add(int64(latency))
}

func (p *Proxy) RecordFailure() {
	p.failures.Add(1)
}

func (p *Proxy) MarkDead() {
	p.alive.Store(false)
}

func (p *Proxy) MarkAlive() {
	p.alive.Store(true)
}

func (p *Proxy) IsAlive() bool {
	return p.alive.Load()
}

func (p *Proxy) Stats() (requests, failures int64, avgLatency time.Duration) {
	requests = p.requests.Load()
	failures = p.failures.Load()
	total := p.totalTime.Load()
	if requests > 0 {
		avgLatency = time.Duration(total / requests)
	}
	return
}
