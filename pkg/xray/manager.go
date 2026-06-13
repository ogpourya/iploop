package xray

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Instance struct {
	Port int
	Cmd  *exec.Cmd
	Tag  string
	done chan struct{}
}

type Manager struct {
	mu        sync.Mutex
	once      sync.Once
	instances []*Instance
	binPath   string
	tmpDir    string
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) findXrayBin() (string, error) {
	if m.binPath != "" {
		return m.binPath, nil
	}
	paths := []string{"xray", "/usr/local/bin/xray", "/usr/bin/xray"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			m.binPath = p
			return p, nil
		}
		if path, err := exec.LookPath(p); err == nil {
			m.binPath = path
			return path, nil
		}
	}
	return "", fmt.Errorf("xray binary not found in PATH")
}

func (m *Manager) StartInstance(outbound *XrayOutbound) (*Instance, error) {
	bin, err := m.findXrayBin()
	if err != nil {
		return nil, err
	}

	port, err := findFreePort()
	if err != nil {
		return nil, fmt.Errorf("find free port: %w", err)
	}

	config := m.buildConfig(outbound, port)

	m.once.Do(func() {
		m.tmpDir, err = os.MkdirTemp("", "iploop-xray-*")
	})
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	tag := outbound.Tag
	if tag == "" {
		tag = fmt.Sprintf("xray-%d", port)
	}
	slug := slugTag(tag)
	configPath := filepath.Join(m.tmpDir, fmt.Sprintf("config-%s.json", slug))

	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0644); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	done := make(chan struct{})
	inst := &Instance{
		Port: port,
		Tag:  tag,
		done: done,
	}

	cmd := exec.Command(bin, "-c", configPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	inst.Cmd = cmd

	if err := cmd.Start(); err != nil {
		os.Remove(configPath)
		return nil, fmt.Errorf("start xray: %w", err)
	}

	go func() {
		cmd.Wait()
		close(done)
	}()

	if err := waitForPort(port, 10*time.Second); err != nil {
		cmd.Process.Kill()
		<-done
		os.Remove(configPath)
		return nil, fmt.Errorf("xray not listening on port %d: %w", port, err)
	}

	m.mu.Lock()
	m.instances = append(m.instances, inst)
	m.mu.Unlock()

	return inst, nil
}

func (m *Manager) buildConfig(outbound *XrayOutbound, socksPort int) map[string]any {
	return map[string]any{
		"log": map[string]any{
			"loglevel": "none",
		},
		"dns": map[string]any{
			"servers": []any{
				"https+local://1.1.1.1/dns-query",
				"https+local://1.0.0.1/dns-query",
				"localhost",
			},
			"queryStrategy": "UseIP",
			"disableCache":  false,
			"tag":           "dns-outbound",
		},
		"inbounds": []any{
			map[string]any{
				"tag":      fmt.Sprintf("socks5-%s", slugTag(outbound.Tag)),
				"port":     socksPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]any{
					"udp": true,
					"auth": "noauth",
				},
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
				},
			},
		},
		"outbounds": []any{
			configToRaw(outbound),
			map[string]any{
				"protocol": "dns",
				"tag":      "dns-outbound",
			},
		},
		"routing": map[string]any{
			"domainStrategy": "IPOnDemand",
			"rules": []any{
				map[string]any{
					"type":        "field",
					"inboundTag":  []string{fmt.Sprintf("socks5-%s", slugTag(outbound.Tag))},
					"outboundTag": slugTag(outbound.Tag),
				},
			},
		},
	}
}

func configToRaw(ob *XrayOutbound) map[string]any {
	raw := map[string]any{
		"protocol": ob.Protocol,
		"tag":      slugTag(ob.Tag),
		"settings": ob.Settings,
	}
	if ob.StreamSettings != nil {
		raw["streamSettings"] = ob.StreamSettings
	}
	return raw
}

func (m *Manager) Instances() []*Instance {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Instance, len(m.instances))
	copy(out, m.instances)
	return out
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	instances := make([]*Instance, len(m.instances))
	copy(instances, m.instances)
	m.instances = nil
	m.mu.Unlock()

	for _, inst := range instances {
		if inst.Cmd != nil && inst.Cmd.Process != nil {
			inst.Cmd.Process.Kill()
		}
	}
	for _, inst := range instances {
		<-inst.done
	}
	if m.tmpDir != "" {
		os.RemoveAll(m.tmpDir)
	}
}

func findFreePort() (int, error) {
	for i := 0; i < 10; i++ {
		port := 30000 + rand.N(20000)
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err == nil {
			ln.Close()
			return port, nil
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}

func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	delay := 50 * time.Millisecond
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), delay)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(delay)
		if delay < 500*time.Millisecond {
			delay *= 2
		}
	}
	return fmt.Errorf("timeout waiting for port %d", port)
}

func slugTag(tag string) string {
	if tag == "" {
		return "xray"
	}
	s := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, tag)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if s == "" {
		return "xray"
	}
	return s
}
