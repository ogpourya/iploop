package metrics

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ogpourya/iploop/pkg/proxy"
	"github.com/ogpourya/iploop/pkg/server"
)

type Display struct {
	rotator *proxy.Rotator
	stats   *server.Stats
	enabled atomic.Bool
	stop    chan struct{}
	once    sync.Once
}

func NewDisplay(rotator *proxy.Rotator, stats *server.Stats) *Display {
	return &Display{
		rotator: rotator,
		stats:   stats,
		stop:    make(chan struct{}),
	}
}

func (d *Display) Start() {
	d.enabled.Store(true)
	go d.run()
}

func (d *Display) Stop() {
	d.once.Do(func() {
		d.enabled.Store(false)
		close(d.stop)
	})
}

func (d *Display) run() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h\n")

	for {
		select {
		case <-d.stop:
			return
		case <-ticker.C:
			if d.enabled.Load() {
				d.render()
			}
		}
	}
}

func (d *Display) render() {
	total := d.stats.TotalRequests.Load()
	success := d.stats.SuccessRequests.Load()
	failed := d.stats.FailedRequests.Load()
	active := d.stats.ActiveConns.Load()

	proxies := d.rotator.GetProxies()

	var b strings.Builder
	b.Grow(256)
	for i, p := range proxies {
		if i > 0 {
			b.WriteString(" | ")
		}
		reqs, fails, latency := p.Stats()
		status := "+"
		if !p.IsAlive() {
			status = "-"
		}
		fmt.Fprintf(&b, "%s%s[%d/%d,%.0fms]", status, p.String(), reqs, fails, float64(latency.Milliseconds()))
	}

	line := fmt.Sprintf("\r\033[K[iploop] reqs:%d ok:%d fail:%d active:%d | %s",
		total, success, failed, active, b.String())

	if len(line) > 120 {
		line = line[:117] + "..."
	}

	os.Stdout.WriteString(line)
}
