package config

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ogpourya/iploop/pkg/proxy"
)

type Config struct {
	ListenAddr     string
	ProxyFile      string
	ProxyList      []string
	Strategy       proxy.RotationStrategy
	SkipDead       bool
	RequestsPer    int // 0 means rotate every request, -1 means 'auto' (don't rotate if alive)
	TrustProxy     bool
	RetryDelay     int // Milliseconds to wait between retries
	DialTimeout    int // Seconds for proxy dial timeout
	MetricsEnabled bool
	Verbose        bool
}

func Parse() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen", ":33333", "Listen address")
	flag.StringVar(&cfg.ProxyFile, "proxy-file", "", "Path to proxy list file")
	var proxyList string
	flag.StringVar(&proxyList, "proxies", "", "Comma-separated proxy list")
	var strategy string
	flag.StringVar(&strategy, "strategy", "sequential", "Rotation strategy: random or sequential")
	flag.BoolVar(&cfg.SkipDead, "skip-dead", false, "Skip dead proxies (default: keep using them)")
	var requestsPer string
	flag.StringVar(&requestsPer, "requests-per-proxy", "1", "Number of requests per proxy before rotation (default: 1, 'auto' to stay on same proxy as long as it is alive)")
	flag.BoolVar(&cfg.TrustProxy, "trust-proxy", true, "Trust HTTPS proxy certificates (skip TLS verification)")
	flag.IntVar(&cfg.RetryDelay, "retry-delay", 100, "Delay in milliseconds between retries")
	flag.IntVar(&cfg.DialTimeout, "dial-timeout", 5, "Timeout in seconds for proxy connections")
	flag.BoolVar(&cfg.MetricsEnabled, "metrics", true, "Enable terminal metrics")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose logging")

	flag.Parse()

	if proxyList != "" {
		cfg.ProxyList = strings.Split(proxyList, ",")
	}

	cfg.Strategy = proxy.ParseRotationStrategy(strategy)

	if requestsPer == "auto" {
		cfg.RequestsPer = -1
	} else {
		fmt.Sscanf(requestsPer, "%d", &cfg.RequestsPer)
		if cfg.RequestsPer < 1 {
			cfg.RequestsPer = 1
		}
	}

	if cfg.ProxyFile == "" {
		cfg.ProxyFile = os.Getenv("IPLOOP_PROXY_FILE")
	}

	return cfg
}
