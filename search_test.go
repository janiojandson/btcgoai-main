package main

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

// TestLaneSetMatchesReference verifies that the fast incremental + batched
// pipeline (newLaneSet/forEachHash/advance) produces exactly the same hash160
// as the straightforward full-scalar-multiplication reference
// (privateKeyToHash160) for a spread of keys across several advance steps.
func TestLaneSetMatchesReference(t *testing.T) {
	hexKey := func(s string) *big.Int {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("bad hex %q: %v", s, err)
		}
		return new(big.Int).SetBytes(b)
	}

	bases := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(0x1000),
		big.NewInt(0xdeadbeef),
		hexKey("0000000000000000000000000000000000000000000000000000000123456789"),
		hexKey("00000000000000000000000000000000000000000000000fffffffffffffffff"),
		hexKey("000000000000000000000000000000000000000000000000abcdef0123456789"),
		hexKey("8000000000000000000000000000000000000000000000000000000000000000"),
	}

	ls := newLaneSet(bases)
	h := newHash160er()
	g := generatorPoint()

	const ticks = 6
	for tick := 0; tick < ticks; tick++ {
		ls.forEachHash(h, func(lane int, got []byte) bool {
			key := new(big.Int).Add(bases[lane], big.NewInt(int64(tick)))
			want, err := privateKeyToHash160(padPrivateKey(key.Bytes(), 32))
			if err != nil {
				t.Fatalf("reference hash160 failed for key %x: %v", key.Bytes(), err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("tick %d lane %d key %x:\n  got  %x\n  want %x",
					tick, lane, key.Bytes(), got, want)
			}
			return false
		})
		ls.advance(&g)
	}
}

// TestGeneratorHash160 anchors the reference itself: the compressed public key
// of private key 1 is the secp256k1 generator, whose hash160 is a well-known
// constant.
func TestGeneratorHash160(t *testing.T) {
	got, err := privateKeyToHash160(padPrivateKey(big.NewInt(1).Bytes(), 32))
	if err != nil {
		t.Fatal(err)
	}
	const want = "751e76e8199196d454941c45d1b3a323f1433bd6"
	if hex.EncodeToString(got) != want {
		t.Fatalf("hash160 of generator: got %x want %s", got, want)
	}
}
