package config

import (
	"flag"
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
	TrustProxy     bool
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
	flag.StringVar(&strategy, "strategy", "random", "Rotation strategy: random or sequential")
	flag.BoolVar(&cfg.SkipDead, "skip-dead", false, "Skip dead proxies (default: keep using them)")
	flag.BoolVar(&cfg.TrustProxy, "trust-proxy", true, "Trust HTTPS proxy certificates (skip TLS verification)")
	flag.BoolVar(&cfg.MetricsEnabled, "metrics", true, "Enable terminal metrics")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose logging")

	flag.Parse()

	if proxyList != "" {
		cfg.ProxyList = strings.Split(proxyList, ",")
	}

	cfg.Strategy = proxy.ParseRotationStrategy(strategy)

	if cfg.ProxyFile == "" {
		cfg.ProxyFile = os.Getenv("IPLOOP_PROXY_FILE")
	}

	return cfg
}
