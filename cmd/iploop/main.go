package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

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

func main() {
	cfg := config.Parse()

	rotator := proxy.NewRotator(cfg.Strategy, cfg.SkipDead, cfg.RequestsPer)
	xrayMgr := xray.NewManager()

	addProxy := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || raw[0] == '#' {
			return
		}
		var p *proxy.Proxy
		var err error
		if isXrayLink(raw) {
			ob, parseErr := xray.ParseLink(raw)
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "Error parsing xray link: %v\n", parseErr)
				return
			}
			inst, addErr := xrayMgr.AddOutbound(ob)
			if addErr != nil {
				fmt.Fprintf(os.Stderr, "Error adding xray outbound: %v\n", addErr)
				return
			}
			proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", inst.Port)
			p, err = proxy.NewProxy(proxyURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating proxy: %v\n", err)
				return
			}
		} else {
			p, err = proxy.NewProxy(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid proxy: %s: %v\n", raw, err)
				return
			}
		}
		rotator.AddProxy(p)
	}

	if cfg.ProxyFile != "" {
		f, err := os.Open(cfg.ProxyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening proxy file: %v\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			addProxy(scanner.Text())
		}
		f.Close()
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading proxy file: %v\n", err)
			os.Exit(1)
		}
	}
	for _, raw := range cfg.ProxyList {
		addProxy(raw)
	}

	if rotator.Count() == 0 {
		fmt.Fprintln(os.Stderr, "No proxies configured. Use -proxies or -proxy-file")
		os.Exit(1)
	}

	if err := xrayMgr.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting xray: %v\n", err)
		os.Exit(1)
	}
	for _, inst := range xrayMgr.Instances() {
		fmt.Fprintf(os.Stderr, "Started xray proxy '%s' on SOCKS5 127.0.0.1:%d\n", inst.Tag, inst.Port)
	}

	srv := server.NewServer(rotator, cfg.TrustProxy, cfg.RetryDelay, cfg.DialTimeout, cfg.Verbose)
	if err := srv.Listen(cfg.ListenAddr); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}
	go srv.Serve()

	fmt.Printf("iploop listening on %s with %d proxies (%s rotation)\n",
		srv.Addr(), rotator.Count(), cfg.Strategy)

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
	xrayMgr.StopAll()
}
