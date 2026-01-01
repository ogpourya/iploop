package proxy

import (
	"testing"
)

func TestNewProxy(t *testing.T) {
	tests := []struct {
		url      string
		wantType ProxyType
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"http://localhost:3333", ProxyTypeHTTP, "localhost", "3333", false},
		{"https://proxy.example.com:8080", ProxyTypeHTTPS, "proxy.example.com", "8080", false},
		{"socks4://127.0.0.1:1080", ProxyTypeSOCKS4, "127.0.0.1", "1080", false},
		{"socks5://localhost:9050", ProxyTypeSOCKS5, "localhost", "9050", false},
		{"http://user:pass@proxy.com:8080", ProxyTypeHTTP, "proxy.com", "8080", false},
		{"invalid://proxy.com", ProxyTypeHTTP, "", "", true},
		{"", ProxyTypeHTTP, "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			p, err := NewProxy(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProxy(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if p.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", p.Type, tt.wantType)
			}
			if p.Host != tt.wantHost {
				t.Errorf("Host = %v, want %v", p.Host, tt.wantHost)
			}
			if p.Port != tt.wantPort {
				t.Errorf("Port = %v, want %v", p.Port, tt.wantPort)
			}
		})
	}
}

func TestProxyStats(t *testing.T) {
	p, _ := NewProxy("http://localhost:8080")

	p.RecordRequest(100_000_000)
	p.RecordRequest(200_000_000)

	reqs, fails, avg := p.Stats()
	if reqs != 2 {
		t.Errorf("requests = %d, want 2", reqs)
	}
	if fails != 0 {
		t.Errorf("failures = %d, want 0", fails)
	}
	if avg != 150_000_000 {
		t.Errorf("avg latency = %d, want 150000000", avg)
	}

	p.RecordFailure()
	_, fails, _ = p.Stats()
	if fails != 1 {
		t.Errorf("failures after RecordFailure = %d, want 1", fails)
	}
}

func TestProxyAlive(t *testing.T) {
	p, _ := NewProxy("http://localhost:8080")

	if !p.IsAlive() {
		t.Error("new proxy should be alive")
	}

	p.MarkDead()
	if p.IsAlive() {
		t.Error("proxy should be dead after MarkDead")
	}

	p.MarkAlive()
	if !p.IsAlive() {
		t.Error("proxy should be alive after MarkAlive")
	}
}
