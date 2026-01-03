package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ogpourya/iploop/pkg/proxy"
)

const (
	socks5Version    = 0x05
	authNone         = 0x00
	authNoAccept     = 0xFF
	cmdConnect       = 0x01
	addrIPv4         = 0x01
	addrDomain       = 0x03
	addrIPv6         = 0x04
	replySuccess     = 0x00
	replyGeneralFail = 0x01
	replyHostUnreach = 0x04
	replyCmdNotSupp  = 0x07
	replyAddrNotSupp = 0x08
)

type Stats struct {
	TotalRequests   atomic.Int64
	ActiveConns     atomic.Int64
	SuccessRequests atomic.Int64
	FailedRequests  atomic.Int64
}

type ProxyDialer interface {
	Dial(ctx context.Context, p *proxy.Proxy, target string) (net.Conn, error)
}

type Server struct {
	listener   net.Listener
	rotator    *proxy.Rotator
	dialer     ProxyDialer
	stats      *Stats
	retryDelay time.Duration
	bufPool    sync.Pool
	handshake  sync.Pool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	verbose    bool
}

func NewServer(rotator *proxy.Rotator, trustProxy bool, retryDelay int, dialTimeout int, verbose bool) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		rotator:    rotator,
		dialer:     NewDialer(trustProxy, time.Duration(dialTimeout)*time.Second, verbose),
		stats:      &Stats{},
		retryDelay: time.Duration(retryDelay) * time.Millisecond,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 32*1024)
				return &buf
			},
		},
		handshake: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 262)
				return &buf
			},
		},
		ctx:     ctx,
		cancel:  cancel,
		verbose: verbose,
	}
}

func (s *Server) Stats() *Stats {
	return s.stats
}

func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) Listen(addr string) error {
	lc := net.ListenConfig{Control: setSocketOptions}
	var err error
	s.listener, err = lc.Listen(s.ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	return nil
}

func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		s.stats.ActiveConns.Add(1)
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) Close() error {
	s.cancel()
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		s.stats.ActiveConns.Add(-1)
		s.wg.Done()
	}()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := s.negotiate(conn); err != nil {
		return
	}

	target, err := s.readRequest(conn)
	if err != nil {
		s.sendReply(conn, replyGeneralFail, nil)
		return
	}

	conn.SetDeadline(time.Time{})
	s.stats.TotalRequests.Add(1)

	s.handleNormal(conn, target)
}

func (s *Server) handleNormal(conn net.Conn, target string) {
	start := time.Now()
	targetConn, usedProxy, err := s.connectToTarget(target)
	latency := time.Since(start)

	if s.verbose {
		fmt.Fprintf(os.Stderr, "Connect to target %s took %v (success: %v)\n", target, latency, err == nil)
	}

	if err != nil {
		s.stats.FailedRequests.Add(1)
		if usedProxy != nil {
			usedProxy.RecordFailure()
		}
		s.sendReply(conn, replyHostUnreach, nil)
		return
	}

	s.stats.SuccessRequests.Add(1)
	if usedProxy != nil {
		usedProxy.RecordRequest(latency)
	}

	var bindAddr *net.TCPAddr
	if addr, ok := targetConn.LocalAddr().(*net.TCPAddr); ok {
		bindAddr = addr
	}
	if err := s.sendReply(conn, replySuccess, bindAddr); err != nil {
		return
	}

	s.relay(conn, targetConn)
}

func (s *Server) negotiate(conn net.Conn) error {
	start := time.Now()
	bufp := s.handshake.Get().(*[]byte)
	defer s.handshake.Put(bufp)
	buf := *bufp

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	if buf[0] != socks5Version {
		return fmt.Errorf("bad socks version")
	}
	nmethods := int(buf[1])
	if nmethods > 255 {
		return fmt.Errorf("invalid nmethods")
	}
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return err
	}
	for i := 0; i < nmethods; i++ {
		if buf[i] == authNone {
			if _, err := conn.Write([]byte{socks5Version, authNone}); err != nil {
				return err
			}
			if s.verbose {
				fmt.Fprintf(os.Stderr, "SOCKS5 negotiate took %v\n", time.Since(start))
			}
			return nil
		}
	}
	conn.Write([]byte{socks5Version, authNoAccept})
	return fmt.Errorf("no acceptable auth")
}

func (s *Server) readRequest(conn net.Conn) (string, error) {
	bufp := s.handshake.Get().(*[]byte)
	defer s.handshake.Put(bufp)
	buf := *bufp

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", err
	}
	if buf[0] != socks5Version {
		return "", fmt.Errorf("bad version")
	}
	if buf[1] != cmdConnect {
		s.sendReply(conn, replyCmdNotSupp, nil)
		return "", fmt.Errorf("unsupported cmd")
	}

	var host string
	switch buf[3] {
	case addrIPv4:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", err
		}
		host = net.IP(buf[:4]).String()
	case addrDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", err
		}
		dlen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dlen]); err != nil {
			return "", err
		}
		host = string(buf[:dlen])
	case addrIPv6:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
	default:
		s.sendReply(conn, replyAddrNotSupp, nil)
		return "", fmt.Errorf("bad addr type")
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}
	port := int(buf[0])<<8 | int(buf[1])
	return fmt.Sprintf("%s:%d", host, port), nil
}

func (s *Server) sendReply(conn net.Conn, reply byte, addr *net.TCPAddr) error {
	var resp [22]byte
	resp[0] = socks5Version
	resp[1] = reply
	resp[2] = 0x00

	n := 4
	if addr != nil {
		if ip4 := addr.IP.To4(); ip4 != nil {
			resp[3] = addrIPv4
			copy(resp[4:8], ip4)
			n = 8
		} else if ip6 := addr.IP.To16(); ip6 != nil {
			resp[3] = addrIPv6
			copy(resp[4:20], ip6)
			n = 20
		}
		resp[n] = byte(addr.Port >> 8)
		resp[n+1] = byte(addr.Port)
		n += 2
	} else {
		resp[3] = addrIPv4
		// All other bytes are already 0 from var resp [22]byte
		n = 10
	}

	_, err := conn.Write(resp[:n])
	return err
}

func (s *Server) connectToTarget(target string) (net.Conn, *proxy.Proxy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	maxRetries := 3
	proxies := make([]*proxy.Proxy, 0, maxRetries)
	tried := make(map[*proxy.Proxy]bool)

	for i := 0; i < maxRetries; i++ {
		p, err := s.rotator.Next()
		if err != nil {
			break
		}
		if tried[p] {
			continue
		}
		tried[p] = true
		proxies = append(proxies, p)
	}

	if len(proxies) == 0 {
		return nil, nil, fmt.Errorf("no proxies available")
	}

	type result struct {
		conn  net.Conn
		proxy *proxy.Proxy
		err   error
	}

	resultCh := make(chan result, len(proxies))

	for _, p := range proxies {
		go func(p *proxy.Proxy) {
			conn, err := s.dialer.Dial(ctx, p, target)
			resultCh <- result{conn, p, err}
		}(p)
	}

	var lastErr error
	for i := 0; i < len(proxies); i++ {
		res := <-resultCh
		if res.err == nil {
			cancel()
			if s.verbose {
				fmt.Fprintf(os.Stderr, "Using proxy %s for %s\n", res.proxy, target)
			}
			return res.conn, res.proxy, nil
		}
		if s.verbose {
			fmt.Fprintf(os.Stderr, "Failed to connect via proxy %s to %s: %v\n", res.proxy, target, res.err)
		}
		lastErr = res.err
		s.rotator.MarkDead(res.proxy)
	}

	return nil, nil, lastErr
}

func (s *Server) relay(client, target net.Conn) {
	buf1 := s.bufPool.Get().(*[]byte)
	buf2 := s.bufPool.Get().(*[]byte)
	defer s.bufPool.Put(buf1)
	defer s.bufPool.Put(buf2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.CopyBuffer(target, client, *buf1)
		if tc, ok := target.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		wg.Done()
	}()

	go func() {
		io.CopyBuffer(client, target, *buf2)
		if tc, ok := client.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
		wg.Done()
	}()

	wg.Wait()
}
