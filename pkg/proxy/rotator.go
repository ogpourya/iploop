package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
)

var ErrAllProxiesDead = errors.New("all proxies are dead")

type RotationStrategy int

const (
	RotationRandom RotationStrategy = iota
	RotationSequential
)

func (s RotationStrategy) String() string {
	if s == RotationRandom {
		return "random"
	}
	return "sequential"
}

func ParseRotationStrategy(s string) RotationStrategy {
	if s == "sequential" || s == "seq" {
		return RotationSequential
	}
	return RotationRandom
}

type Rotator struct {
	proxies     []*Proxy
	seen        map[string]bool
	strategy    RotationStrategy
	skipDead    bool
	mu          sync.Mutex
	requestsPer int
	current     *Proxy
	counter     int
	seqIndex    int
	shuffled    []*Proxy
	shuffleIdx  int
	poolCache   []*Proxy
}

func NewRotator(strategy RotationStrategy, skipDead bool, requestsPer int) *Rotator {
	return &Rotator{
		proxies:     make([]*Proxy, 0, 64),
		seen:        make(map[string]bool),
		strategy:    strategy,
		skipDead:    skipDead,
		requestsPer: requestsPer,
		poolCache:   make([]*Proxy, 0, 64),
	}
}

func (r *Rotator) AddProxy(p *Proxy) {
	key := p.String()
	r.mu.Lock()
	if r.seen[key] {
		r.mu.Unlock()
		return
	}
	r.seen[key] = true
	r.proxies = append(r.proxies, p)
	r.poolCache = r.poolCache[:0]
	r.shuffled = nil
	r.mu.Unlock()
}

func (r *Rotator) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		p, err := NewProxy(line)
		if err != nil {
			continue
		}
		r.AddProxy(p)
	}
	return scanner.Err()
}

func (r *Rotator) LoadFromStrings(urls []string) error {
	for _, u := range urls {
		p, err := NewProxy(u)
		if err != nil {
			continue
		}
		r.AddProxy(p)
	}
	return nil
}

func (r *Rotator) Count() int {
	r.mu.Lock()
	n := len(r.proxies)
	r.mu.Unlock()
	return n
}

func (r *Rotator) AliveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, p := range r.proxies {
		if p.IsAlive() {
			count++
		}
	}
	return count
}

func (r *Rotator) getPool() ([]*Proxy, error) {
	if !r.skipDead {
		return r.proxies, nil
	}

	r.poolCache = r.poolCache[:0]
	for _, p := range r.proxies {
		if p.IsAlive() {
			r.poolCache = append(r.poolCache, p)
		}
	}

	if len(r.poolCache) == 0 {
		return nil, ErrAllProxiesDead
	}
	return r.poolCache, nil
}

func (r *Rotator) Next() (*Proxy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.proxies) == 0 {
		return nil, fmt.Errorf("no proxies available")
	}

	// Stay on current proxy if requested
	if r.current != nil && (r.requestsPer == -1 || r.counter < r.requestsPer) {
		if !r.skipDead || r.current.IsAlive() {
			r.counter++
			return r.current, nil
		}
	}

	pool, err := r.getPool()
	if err != nil {
		return nil, err
	}

	var proxy *Proxy

	switch r.strategy {
	case RotationSequential:
		r.seqIndex = r.seqIndex % len(pool)
		proxy = pool[r.seqIndex]
		r.seqIndex++

	case RotationRandom:
		needReshuffle := r.shuffled == nil || r.shuffleIdx >= len(r.shuffled)
		if r.skipDead && len(r.shuffled) != len(pool) {
			needReshuffle = true
		}
		if needReshuffle {
			if cap(r.shuffled) < len(pool) {
				r.shuffled = make([]*Proxy, len(pool))
			} else {
				r.shuffled = r.shuffled[:len(pool)]
			}
			copy(r.shuffled, pool)
			rand.Shuffle(len(r.shuffled), func(i, j int) {
				r.shuffled[i], r.shuffled[j] = r.shuffled[j], r.shuffled[i]
			})
			r.shuffleIdx = 0
		}
		proxy = r.shuffled[r.shuffleIdx]
		r.shuffleIdx++
	}

	r.current = proxy
	r.counter = 1
	return proxy, nil
}

func (r *Rotator) MarkDead(p *Proxy) {
	r.mu.Lock()
	p.MarkDead()
	if r.skipDead {
		r.shuffled = nil
		r.poolCache = r.poolCache[:0]
	}
	r.mu.Unlock()
}
