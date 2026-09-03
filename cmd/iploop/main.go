package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ogpourya/iploop/pkg/config"
	"github.com/ogpourya/iploop/pkg/metrics"
	"github.com/ogpourya/iploop/pkg/proxy"
	"github.com/ogpourya/iploop/pkg/server"
	"github.com/ogpourya/iploop/pkg/xray"
)

func isXrayLink(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "vless://") ||
		strings.HasPrefix(s, "vmess://") ||
		strings.HasPrefix(s, "trojan://") ||
		strings.HasPrefix(s, "ss://") ||
		strings.HasPrefix(s, "hysteria2://") ||
		strings.HasPrefix(s, "hy2://") ||
		strings.HasPrefix(s, "wireguard://") ||
		strings.HasPrefix(s, "wg://")
}

// classify sorts one -proxies/proxy-file line into an xray link or a plain proxy.
// Blank lines and comments return ("", nil, nil).
func classify(raw string) (string, *proxy.Proxy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw[0] == '#' {
		return "", nil, nil
	}
	if isXrayLink(raw) {
		if _, err := xray.ParseLink(raw); err != nil {
			return "", nil, fmt.Errorf("parsing xray link: %w", err)
		}
		return raw, nil, nil
	}
	p, err := proxy.NewProxy(raw)
	if err != nil {
		return "", nil, err
	}
	return "", p, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// startXrayManager builds a manager for the given xray links, starts it,
// and returns the local SOCKS5 proxies fronting each instance.
func startXrayManager(links []string, verbose bool) (*xray.Manager, []*proxy.Proxy, error) {
	mgr := xray.NewManager()
	mgr.Verbose = verbose
	for _, link := range links {
		ob, err := xray.ParseLink(link)
		if err != nil {
			continue
		}
		if _, err := mgr.AddOutbound(ob); err != nil {
			continue
		}
	}
	if err := mgr.Start(); err != nil {
		mgr.StopAll()
		return nil, nil, err
	}
	var locals []*proxy.Proxy
	for _, inst := range mgr.Instances() {
		p, err := proxy.NewProxy(fmt.Sprintf("socks5://127.0.0.1:%d", inst.Port))
		if err != nil {
			continue
		}
		locals = append(locals, p)
	}
	return mgr, locals, nil
}

func xraySetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	n := make(map[string]int, len(a))
	for _, s := range a {
		n[s]++
	}
	for _, s := range b {
		n[s]--
		if n[s] < 0 {
			return false
		}
	}
	return true
}

// watchProxyFile polls path and hot-reloads the proxy set on change.
// Plain proxies swap in place; xray restarts only when xray links changed.
// On any failure the current set is kept.
func watchProxyFile(path string, rotator *proxy.Rotator, mgr *atomic.Pointer[xray.Manager], flagPlain []*proxy.Proxy, flagXray, fileXray []string, locals []*proxy.Proxy, verbose bool) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	lastMod, lastSize := st.ModTime(), st.Size()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		st, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "proxy file: %v (keeping current proxies)\n", err)
			continue
		}
		if st.ModTime().Equal(lastMod) && st.Size() == lastSize {
			continue
		}
		lastMod, lastSize = st.ModTime(), st.Size()
		time.Sleep(100 * time.Millisecond) // let writers finish
		lines, err := readLines(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "proxy file reload: %v (keeping current proxies)\n", err)
			continue
		}
		var newPlain []*proxy.Proxy
		var newXray []string
		for _, raw := range lines {
			link, p, err := classify(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid proxy: %s: %v\n", strings.TrimSpace(raw), err)
				continue
			}
			if link != "" {
				newXray = append(newXray, link)
			} else if p != nil {
				newPlain = append(newPlain, p)
			}
		}
		if xraySetEqual(newXray, fileXray) {
			fileXray = newXray
			rotator.ReplaceAll(joinProxies(flagPlain, newPlain, locals))
			fmt.Fprintf(os.Stderr, "proxy file reloaded: %d proxies\n", rotator.Count())
			continue
		}
		newMgr, newLocals, err := startXrayManager(append(append([]string{}, flagXray...), newXray...), verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "proxy file reload: xray restart failed: %v (keeping current proxies)\n", err)
			continue
		}
		old := mgr.Swap(newMgr)
		fileXray, locals = newXray, newLocals
		rotator.ReplaceAll(joinProxies(flagPlain, newPlain, locals))
		for _, inst := range newMgr.Instances() {
			fmt.Fprintf(os.Stderr, "Started xray proxy '%s' on SOCKS5 127.0.0.1:%d\n", inst.Tag, inst.Port)
		}
		fmt.Fprintf(os.Stderr, "proxy file reloaded: %d proxies\n", rotator.Count())
		if old != nil {
			old.StopAll()
		}
	}
}

func joinProxies(groups ...[]*proxy.Proxy) []*proxy.Proxy {
	var out []*proxy.Proxy
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

func main() {
	cfg := config.Parse()

	rotator := proxy.NewRotator(cfg.Strategy, cfg.SkipDead, cfg.RequestsPer)
	var xrayMgr atomic.Pointer[xray.Manager]

	var flagPlain []*proxy.Proxy
	var flagXray []string
	for _, raw := range cfg.ProxyList {
		link, p, err := classify(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid proxy: %s: %v\n", raw, err)
			continue
		}
		if link != "" {
			flagXray = append(flagXray, link)
		} else if p != nil {
			flagPlain = append(flagPlain, p)
		}
	}

	var filePlain []*proxy.Proxy
	var fileXray []string
	if cfg.ProxyFile != "" {
		lines, err := readLines(cfg.ProxyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening proxy file: %v\n", err)
			os.Exit(1)
		}
		for _, raw := range lines {
			link, p, err := classify(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid proxy: %s: %v\n", strings.TrimSpace(raw), err)
				continue
			}
			if link != "" {
				fileXray = append(fileXray, link)
			} else if p != nil {
				filePlain = append(filePlain, p)
			}
		}
	}

	mgr, locals, err := startXrayManager(append(append([]string{}, flagXray...), fileXray...), cfg.Verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting xray: %v\n", err)
		os.Exit(1)
	}
	xrayMgr.Store(mgr)
	for _, inst := range mgr.Instances() {
		fmt.Fprintf(os.Stderr, "Started xray proxy '%s' on SOCKS5 127.0.0.1:%d\n", inst.Tag, inst.Port)
	}
	for _, p := range joinProxies(flagPlain, filePlain, locals) {
		rotator.AddProxy(p)
	}

	if rotator.Count() == 0 {
		fmt.Fprintln(os.Stderr, "No proxies configured. Use -proxies or -proxy-file")
		os.Exit(1)
	}

	srv := server.NewServer(rotator, cfg.TrustProxy, cfg.RetryDelay, cfg.DialTimeout, cfg.Verbose, cfg.NoDNS)
	if err := srv.Listen(cfg.ListenAddr); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}
	go srv.Serve()

	fmt.Printf("iploop listening on %s with %d proxies (%s rotation)\n",
		srv.Addr(), rotator.Count(), cfg.Strategy)

	if cfg.ProxyFile != "" {
		go watchProxyFile(cfg.ProxyFile, rotator, &xrayMgr, flagPlain, flagXray, fileXray, locals, cfg.Verbose)
	}

	var display *metrics.Display
	if cfg.MetricsEnabled {
		onAllDead := func() {
			if cfg.SkipDead {
				fmt.Print("\033[?25h")
				fmt.Fprintf(os.Stderr, "\nAll proxies are dead, exiting\n")
				srv.Close()
				os.Exit(1)
			}
		}
		display = metrics.NewDisplay(rotator, srv.Stats(), onAllDead)
		display.Start()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	if display != nil {
		display.Stop()
	}
	srv.Close()
	xrayMgr.Load().StopAll()
}
