package proxy

import (
	"testing"
)

func TestRotator(t *testing.T) {
	r := NewRotator(RotationSequential, false, 1)

	r.LoadFromStrings([]string{
		"http://localhost:8080",
		"socks5://localhost:9050",
		"http://localhost:3128",
	})

	if r.Count() != 3 {
		t.Errorf("Count() = %d, want 3", r.Count())
	}

	p1, _ := r.Next()
	p2, _ := r.Next()
	p3, _ := r.Next()
	p4, _ := r.Next()

	if p1.Port != "8080" {
		t.Errorf("first proxy port = %s, want 8080", p1.Port)
	}
	if p4.Port != "8080" {
		t.Errorf("fourth proxy port = %s, want 8080 (wrap around)", p4.Port)
	}

	if p1.Port == p2.Port && p2.Port == p3.Port {
		t.Error("sequential rotation should give different proxies")
	}
}

func TestRotatorRandom(t *testing.T) {
	r := NewRotator(RotationRandom, false, 1)

	r.LoadFromStrings([]string{
		"http://localhost:8080",
		"http://localhost:8081",
		"http://localhost:8082",
	})

	seen := make(map[string]bool)

	for i := 0; i < 3; i++ {
		p, _ := r.Next()
		seen[p.Port] = true
	}

	if len(seen) != 3 {
		t.Errorf("random rotation should have used all 3 proxies, got %d", len(seen))
	}
}

func TestRotatorKeepDead(t *testing.T) {
	r := NewRotator(RotationSequential, false, 1)

	r.LoadFromStrings([]string{
		"http://localhost:8080",
		"http://localhost:8081",
	})

	p1, _ := r.Next()
	r.MarkDead(p1)

	p2, _ := r.Next()
	if p2.Port != "8081" {
		t.Errorf("second proxy port = %s, want 8081", p2.Port)
	}

	p3, _ := r.Next()
	if p3.Port != "8080" {
		t.Error("should still use dead proxy when skip-dead=false")
	}
}

func TestRotatorSkipDead(t *testing.T) {
	r := NewRotator(RotationSequential, true, 1)

	r.LoadFromStrings([]string{
		"http://localhost:8080",
		"http://localhost:8081",
	})

	p1, _ := r.Next()
	r.MarkDead(p1)

	p2, _ := r.Next()
	if p2.Port == p1.Port {
		t.Error("should skip dead proxy when skip-dead=true")
	}
}

func TestRotatorAllDeadError(t *testing.T) {
	r := NewRotator(RotationSequential, true, 1)

	r.LoadFromStrings([]string{
		"http://localhost:8080",
	})

	p1, _ := r.Next()
	r.MarkDead(p1)

	_, err := r.Next()
	if err != ErrAllProxiesDead {
		t.Errorf("should return ErrAllProxiesDead, got: %v", err)
	}
}

func TestRotatorAliveCount(t *testing.T) {
	r := NewRotator(RotationSequential, true, 1)

	r.LoadFromStrings([]string{
		"http://localhost:8080",
		"http://localhost:8081",
		"http://localhost:8082",
	})

	if r.AliveCount() != 3 {
		t.Errorf("AliveCount() = %d, want 3", r.AliveCount())
	}

	p1, _ := r.Next()
	r.MarkDead(p1)

	if r.AliveCount() != 2 {
		t.Errorf("AliveCount() = %d, want 2", r.AliveCount())
	}
}

func TestRotationStrategy(t *testing.T) {
	if ParseRotationStrategy("random") != RotationRandom {
		t.Error("should parse random")
	}
	if ParseRotationStrategy("sequential") != RotationSequential {
		t.Error("should parse sequential")
	}
	if ParseRotationStrategy("seq") != RotationSequential {
		t.Error("should parse seq")
	}
	if ParseRotationStrategy("unknown") != RotationRandom {
		t.Error("should default to random")
	}
}

func TestRotatorRequestsPer(t *testing.T) {
	r := NewRotator(RotationSequential, false, 2)
	r.LoadFromStrings([]string{
		"http://localhost:8080",
		"http://localhost:8081",
	})

	p1, _ := r.Next()
	p2, _ := r.Next()
	p3, _ := r.Next()

	if p1.Port != "8080" || p2.Port != "8080" {
		t.Errorf("expected same proxy for first 2 requests, got %s then %s", p1.Port, p2.Port)
	}
	if p3.Port != "8081" {
		t.Errorf("expected rotation on 3rd request, got %s", p3.Port)
	}
}

func TestRotatorAuto(t *testing.T) {
	r := NewRotator(RotationSequential, true, -1) // auto
	r.LoadFromStrings([]string{
		"http://localhost:8080",
		"http://localhost:8081",
	})

	p1, _ := r.Next()
	p2, _ := r.Next()
	if p1.Port != "8080" || p2.Port != "8080" {
		t.Error("auto should stay on same proxy")
	}

	r.MarkDead(p1)
	p3, _ := r.Next()
	if p3.Port != "8081" {
		t.Errorf("auto should rotate when current is dead, got %s", p3.Port)
	}
}
