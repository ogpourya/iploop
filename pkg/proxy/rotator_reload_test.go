package proxy

import "testing"

func mustProxy(t *testing.T, url string) *Proxy {
	t.Helper()
	p, err := NewProxy(url)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReplaceAll(t *testing.T) {
	r := NewRotator(RotationSequential, false, 1)
	a := mustProxy(t, "socks5://1.1.1.1:1080")
	b := mustProxy(t, "socks5://2.2.2.2:1080")
	r.AddProxy(a)
	r.AddProxy(b)

	r.MarkDead(b) // survivor state must carry over the swap

	b2 := mustProxy(t, "socks5://2.2.2.2:1080")
	c := mustProxy(t, "socks5://3.3.3.3:1080")
	r.ReplaceAll([]*Proxy{b2, c, mustProxy(t, "socks5://3.3.3.3:1080")}) // dup c

	if got := r.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2", got)
	}
	if got := r.AliveCount(); got != 1 {
		t.Fatalf("AliveCount = %d, want 1 (b stays dead)", got)
	}
	for i := 0; i < 4; i++ {
		p, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if s := p.String(); s != "socks5://2.2.2.2:1080" && s != "socks5://3.3.3.3:1080" {
			t.Fatalf("Next returned removed proxy %s", s)
		}
	}
}

func TestSkipDeadPool(t *testing.T) {
	r := NewRotator(RotationSequential, true, 1)
	a := mustProxy(t, "socks5://1.1.1.1:1080")
	b := mustProxy(t, "socks5://2.2.2.2:1080")
	r.AddProxy(a)
	r.AddProxy(b)
	r.MarkDead(a)
	for i := 0; i < 10; i++ {
		p, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if p != b {
			t.Fatalf("Next returned dead proxy %s", p)
		}
	}
	r.MarkDead(b)
	if _, err := r.Next(); err != ErrAllProxiesDead {
		t.Fatalf("Next err = %v, want ErrAllProxiesDead", err)
	}
}
