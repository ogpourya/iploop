package server

// Benchmarks for the dial (connection-setup) hot path. Each talks to a fake
// in-process upstream over localhost so results measure our code, not network.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ogpourya/iploop/pkg/proxy"
)

// Minimal interface satisfied by both *testing.T and *testing.B.
type tb interface {
	Helper()
	Fatal(args ...any)
	Cleanup(f func())
}

// ---- fake SOCKS5 upstream (no-auth, always succeeds) ----

func startFakeSocks5(t tb) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				io.CopyN(io.Discard, c, int64(hdr[1]))
				c.Write([]byte{0x05, 0x00})
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				switch req[3] {
				case 0x01:
					io.CopyN(io.Discard, c, 4)
				case 0x03:
					l := make([]byte, 1)
					io.ReadFull(c, l)
					io.CopyN(io.Discard, c, int64(l[0]))
				case 0x04:
					io.CopyN(io.Discard, c, 16)
				}
				io.CopyN(io.Discard, c, 2) // port
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				io.Copy(io.Discard, c) // hold open until client closes
			}(c)
		}
	}()
	return ln.Addr().String()
}

// ---- fake HTTP CONNECT upstream (always 200) ----

func startFakeHTTPConnect(t tb) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// ---- fake HTTPS CONNECT upstream (self-signed, counts server-side resumes) ----

func startFakeHTTPSConnect(t tb, resumes *atomic.Int64) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						return
					}
					if tc.ConnectionState().DidResume {
						resumes.Add(1)
					}
				}
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func mustProxyURL(t tb, url string) *proxy.Proxy {
	t.Helper()
	p, err := proxy.NewProxy(url)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustDialTCP(t tb, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Full SOCKS5 dial with a long hostname (exercises request-buffer sizing).
func BenchmarkDialSOCKS5LongHost(b *testing.B) {
	addr := startFakeSocks5(b)
	d := NewDialer(false, 5*time.Second, false, true)
	p := mustProxyURL(b, "socks5://"+addr)
	ctx := context.Background()
	target := "a-much-longer-hostname-than-fifteen-chars.example.com:443"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := d.Dial(ctx, p, target)
		if err != nil {
			b.Fatal(err)
		}
		c.Close()
	}
}

// HTTP CONNECT through an authed proxy (exercises per-dial base64).
func BenchmarkHTTPConnectAuth(b *testing.B) {
	addr := startFakeHTTPConnect(b)
	d := NewDialer(false, 5*time.Second, false, true)
	p := mustProxyURL(b, "http://user:pass@"+addr)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := d.doHTTPConnect(mustDialTCP(b, addr), p, "example.com:443")
		if err != nil {
			b.Fatal(err)
		}
		c.Close()
	}
}

// Full HTTPS dial incl. TCP+TLS+CONNECT (exercises session resumption).
func BenchmarkDialHTTPS(b *testing.B) {
	var resumes atomic.Int64
	addr := startFakeHTTPSConnect(b, &resumes)
	d := NewDialer(true, 5*time.Second, false, true)
	p := mustProxyURL(b, "https://"+addr)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := d.Dial(ctx, p, "example.com:443")
		if err != nil {
			b.Fatal(err)
		}
		c.Close()
	}
	b.ReportMetric(float64(resumes.Load())/float64(b.N)*100, "resume-%")
}

// Correctness: precomputed auth header must equal a live base64 encoding.
func TestProxyAuthHeader(t *testing.T) {
	p := mustProxyURL(t, "http://user:pass@127.0.0.1:8080")
	if p.ProxyAuth != "Basic dXNlcjpwYXNz" {
		t.Fatalf("ProxyAuth = %q, want %q", p.ProxyAuth, "Basic dXNlcjpwYXNz")
	}
	if q := mustProxyURL(t, "http://127.0.0.1:8080"); q.ProxyAuth != "" {
		t.Fatalf("ProxyAuth = %q for credless proxy, want empty", q.ProxyAuth)
	}
}

// Correctness: repeated HTTPS dials must resume sessions (fix 1 regression test).
func TestTLSSessionResume(t *testing.T) {
	var resumes atomic.Int64
	addr := startFakeHTTPSConnect(t, &resumes)
	d := NewDialer(true, 5*time.Second, false, true)
	p := mustProxyURL(t, "https://"+addr)
	ctx := context.Background()
	const n = 10
	for i := 0; i < n; i++ {
		c, err := d.Dial(ctx, p, "example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if got := resumes.Load(); got < n-1 {
		t.Fatalf("resumed %d/%d handshakes, want >= %d", got, n, n-1)
	}
}
