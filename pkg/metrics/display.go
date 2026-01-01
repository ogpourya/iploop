package metrics

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ogpourya/iploop/pkg/proxy"
	"github.com/ogpourya/iploop/pkg/server"
)

type Display struct {
	rotator   *proxy.Rotator
	stats     *server.Stats
	enabled   atomic.Bool
	stop      chan struct{}
	once      sync.Once
	onDead    func()
	deadFired atomic.Bool
}

func NewDisplay(rotator *proxy.Rotator, stats *server.Stats, onAllDead func()) *Display {
	return &Display{
		rotator: rotator,
		stats:   stats,
		stop:    make(chan struct{}),
		onDead:  onAllDead,
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
	alive := d.rotator.AliveCount()
	totalProxies := d.rotator.Count()

	if alive == 0 && d.onDead != nil && !d.deadFired.Swap(true) {
		d.onDead()
		return
	}

	line := fmt.Sprintf("\r\033[K[iploop] reqs:%d ok:%d fail:%d active:%d proxies:%d/%d",
		total, success, failed, active, alive, totalProxies)

	os.Stdout.WriteString(line)
}
