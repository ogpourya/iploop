package proxy

import (
	"fmt"
	"testing"
)

// Next() with skipDead and a large list: exercises the pool fast path.
func BenchmarkNextSkipDeadLarge(b *testing.B) {
	r := NewRotator(RotationSequential, true, 1)
	const n = 2000
	for i := 0; i < n; i++ {
		p, err := NewProxy(fmt.Sprintf("socks5://10.%d.%d.%d:1080", (i>>16)&0xff, (i>>8)&0xff, i&0xff))
		if err != nil {
			b.Fatal(err)
		}
		r.AddProxy(p)
		if i%2 == 0 {
			p.MarkDead()
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Next(); err != nil {
			b.Fatal(err)
		}
	}
}
