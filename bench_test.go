package main

import (
	"math/big"
	"testing"
)

// BenchmarkReferencePerKey measures the original approach: a full scalar
// multiplication + hash160 for every individual key.
func BenchmarkReferencePerKey(b *testing.B) {
	key := new(big.Int).SetInt64(0x123456789)
	one := big.NewInt(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Add(key, one)
		if _, err := privateKeyToHash160(padPrivateKey(key.Bytes(), 32)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBatchedIncremental measures the new approach: one EC addition per
// key with a single batched field inversion amortized over the whole lane set.
func BenchmarkBatchedIncremental(b *testing.B) {
	const lanes = 1024
	bases := make([]*big.Int, lanes)
	for j := 0; j < lanes; j++ {
		bases[j] = new(big.Int).SetInt64(int64(0x123456789 + j*1000000))
	}
	ls := newLaneSet(bases)
	h := newHash160er()
	g := generatorPoint()

	b.ResetTimer()
	keys := 0
	for keys < b.N {
		ls.forEachHash(h, func(lane int, h160 []byte) bool { return false })
		keys += lanes
		ls.advance(&g)
	}
	b.SetBytes(0)
}
