package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ogpourya/iploop/pkg/config"
	"github.com/ogpourya/iploop/pkg/metrics"
	"github.com/ogpourya/iploop/pkg/proxy"
	"github.com/ogpourya/iploop/pkg/server"
)

func main() {
	cfg := config.Parse()

	rotator := proxy.NewRotator(cfg.Strategy, cfg.SkipDead)

	if cfg.ProxyFile != "" {
		if err := rotator.LoadFromFile(cfg.ProxyFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading proxy file: %v\n", err)
			os.Exit(1)
		}
	}
	if len(cfg.ProxyList) > 0 {
		rotator.LoadFromStrings(cfg.ProxyList)
	}

	if rotator.Count() == 0 {
		fmt.Fprintln(os.Stderr, "No proxies configured. Use -proxies or -proxy-file")
		os.Exit(1)
	}

	srv := server.NewServer(rotator, cfg.TrustProxy, cfg.JustDoIt)
	if err := srv.Listen(cfg.ListenAddr); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		os.Exit(1)
	}

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
}
