package server

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ogpourya/iploop/pkg/proxy"
)

type Dialer struct {
	timeout    time.Duration
	trustProxy bool
}

func NewDialer(trustProxy bool) *Dialer {
	return &Dialer{
		timeout:    10 * time.Second,
		trustProxy: trustProxy,
	}
}

func (d *Dialer) Dial(p *proxy.Proxy, target string) (net.Conn, error) {
	switch p.Type {
	case proxy.ProxyTypeHTTP:
		return d.dialHTTP(p, target)
	case proxy.ProxyTypeHTTPS:
		return d.dialHTTPS(p, target)
	case proxy.ProxyTypeSOCKS4:
		return d.dialSOCKS4(p, target)
	case proxy.ProxyTypeSOCKS5:
		return d.dialSOCKS5(p, target)
	default:
		return nil, fmt.Errorf("unsupported proxy type")
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (d *Dialer) dialHTTP(p *proxy.Proxy, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", p.Address(), d.timeout)
	if err != nil {
		return nil, err
	}
	return d.doHTTPConnect(conn, p, target)
}

func (d *Dialer) dialHTTPS(p *proxy.Proxy, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", p.Address(), d.timeout)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		ServerName:         p.Host,
		InsecureSkipVerify: d.trustProxy,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(d.timeout))

	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return d.doHTTPConnect(tlsConn, p, target)
}

func (d *Dialer) doHTTPConnect(conn net.Conn, p *proxy.Proxy, target string) (net.Conn, error) {
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if p.Username != "" {
		req += "Proxy-Authorization: Basic " + base64Encode(p.Username+":"+p.Password) + "\r\n"
	}
	req += "\r\n"

	conn.SetDeadline(time.Now().Add(d.timeout))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReaderSize(conn, 1024)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy returned %d", resp.StatusCode)
	}

	conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

func (d *Dialer) dialSOCKS4(p *proxy.Proxy, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", p.Address(), d.timeout)
	if err != nil {
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}

	ip := net.ParseIP(host)
	if ip != nil {
		ip = ip.To4()
	}
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			conn.Close()
			return nil, fmt.Errorf("resolve failed: %s", host)
		}
		for _, addr := range ips {
			if v4 := addr.To4(); v4 != nil {
				ip = v4
				break
			}
		}
		if ip == nil {
			conn.Close()
			return nil, fmt.Errorf("no IPv4 for %s", host)
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("invalid port")
	}

	var req [9]byte
	req[0] = 0x04
	req[1] = 0x01
	binary.BigEndian.PutUint16(req[2:4], uint16(port))
	copy(req[4:8], ip)

	conn.SetDeadline(time.Now().Add(d.timeout))
	if _, err = conn.Write(req[:]); err != nil {
		conn.Close()
		return nil, err
	}

	var resp [8]byte
	if _, err = io.ReadFull(conn, resp[:]); err != nil {
		conn.Close()
		return nil, err
	}

	if resp[1] != 0x5A {
		conn.Close()
		return nil, fmt.Errorf("SOCKS4 rejected: %d", resp[1])
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *Dialer) dialSOCKS5(p *proxy.Proxy, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", p.Address(), d.timeout)
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(d.timeout))

	var methods []byte
	if p.Username != "" {
		methods = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		methods = []byte{0x05, 0x01, 0x00}
	}

	if _, err = conn.Write(methods); err != nil {
		conn.Close()
		return nil, err
	}

	var resp [2]byte
	if _, err = io.ReadFull(conn, resp[:]); err != nil {
		conn.Close()
		return nil, err
	}

	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("bad SOCKS5 version")
	}

	if resp[1] == 0x02 {
		if err := d.socks5Auth(conn, p.Username, p.Password); err != nil {
			conn.Close()
			return nil, err
		}
	} else if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("auth not supported: %d", resp[1])
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("invalid port")
	}

	if len(host) > 255 {
		conn.Close()
		return nil, fmt.Errorf("hostname too long")
	}

	req := make([]byte, 0, 22)
	req = append(req, 0x05, 0x01, 0x00)

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))

	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	var hdr [4]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		conn.Close()
		return nil, err
	}

	if hdr[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("bad SOCKS5 response")
	}

	if hdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 failed: %d", hdr[1])
	}

	if err := d.consumeBoundAddr(conn, hdr[3]); err != nil {
		conn.Close()
		return nil, err
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *Dialer) consumeBoundAddr(conn net.Conn, atyp byte) error {
	switch atyp {
	case 0x01:
		var buf [6]byte
		_, err := io.ReadFull(conn, buf[:])
		return err
	case 0x03:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return err
		}
		dlen := int(lenBuf[0])
		buf := make([]byte, dlen+2)
		_, err := io.ReadFull(conn, buf)
		return err
	case 0x04:
		var buf [18]byte
		_, err := io.ReadFull(conn, buf[:])
		return err
	default:
		return fmt.Errorf("unknown atyp: %d", atyp)
	}
}

func (d *Dialer) socks5Auth(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return fmt.Errorf("username or password too long")
	}
	req := make([]byte, 3+len(user)+len(pass))
	req[0] = 0x01
	req[1] = byte(len(user))
	copy(req[2:], user)
	req[2+len(user)] = byte(len(pass))
	copy(req[3+len(user):], pass)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("auth failed")
	}
	return nil
}

func base64Encode(s string) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	data := []byte(s)
	result := make([]byte, 0, (len(data)+2)/3*4)

	for i := 0; i < len(data); i += 3 {
		var n uint32
		rem := len(data) - i
		switch {
		case rem >= 3:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			result = append(result, alpha[n>>18], alpha[(n>>12)&63], alpha[(n>>6)&63], alpha[n&63])
		case rem == 2:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8
			result = append(result, alpha[n>>18], alpha[(n>>12)&63], alpha[(n>>6)&63], '=')
		default:
			n = uint32(data[i]) << 16
			result = append(result, alpha[n>>18], alpha[(n>>12)&63], '=', '=')
		}
	}
	return string(result)
}
