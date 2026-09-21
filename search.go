package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
)

// lanesPerWorker is how many independent keys each worker advances in lockstep.
// A larger batch amortizes the single (expensive) field inversion over more
// keys via Montgomery's trick, at the cost of more memory per worker.
const lanesPerWorker = 1024

// generatorPoint returns the secp256k1 generator G as an affine (Z=1) point.
func generatorPoint() btcec.JacobianPoint {
	var one btcec.ModNScalar
	one.SetInt(1)
	var g btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&one, &g)
	g.ToAffine()
	return g
}

// hash160er computes RIPEMD160(SHA256(compressedPubKey)) while reusing its
// hashers and buffers so the hot loop performs no per-key allocations.
type hash160er struct {
	sha    hash.Hash
	rmd    hash.Hash
	pubkey [33]byte
	shaSum [32]byte
	out    [20]byte
}

func newHash160er() *hash160er {
	return &hash160er{sha: sha256.New(), rmd: ripemd160.New()}
}

// compute returns the hash160 of the compressed public key (0x02/0x03 || x).
// The returned slice is backed by the receiver and is only valid until the
// next call.
func (h *hash160er) compute(oddY bool, x *[32]byte) []byte {
	if oddY {
		h.pubkey[0] = 0x03
	} else {
		h.pubkey[0] = 0x02
	}
	copy(h.pubkey[1:], x[:])

	h.sha.Reset()
	h.sha.Write(h.pubkey[:])
	s := h.sha.Sum(h.shaSum[:0])

	h.rmd.Reset()
	h.rmd.Write(s)
	return h.rmd.Sum(h.out[:0])
}

// laneSet holds a batch of curve points that are advanced together. Each
// advance() step adds G to every point (a single EC addition per key instead
// of a full scalar multiplication), and forEachHash() converts the whole batch
// to affine coordinates using one shared modular inversion.
type laneSet struct {
	pts    []btcec.JacobianPoint
	zinv   []btcec.FieldVal
	prefix []btcec.FieldVal
}

// newLaneSet seeds one point per base key with a full scalar multiplication.
// This is the only place full scalar mults happen; everything after is
// incremental.
func newLaneSet(baseKeys []*big.Int) *laneSet {
	n := len(baseKeys)
	ls := &laneSet{
		pts:    make([]btcec.JacobianPoint, n),
		zinv:   make([]btcec.FieldVal, n),
		prefix: make([]btcec.FieldVal, n),
	}
	var k btcec.ModNScalar
	for j, key := range baseKeys {
		k.SetByteSlice(padPrivateKey(key.Bytes(), 32))
		btcec.ScalarBaseMultNonConst(&k, &ls.pts[j])
	}
	return ls
}

// forEachHash converts every point in the batch to affine coordinates using a
// single field inversion (Montgomery's trick) and invokes fn with each lane's
// hash160. It stops early and returns true if fn returns true.
func (ls *laneSet) forEachHash(h *hash160er, fn func(lane int, h160 []byte) bool) bool {
	n := len(ls.pts)

	// Forward pass: prefix[j] = product of Z[0..j-1]; acc = product of all Z.
	// Points at infinity (Z==0, astronomically unlikely) are skipped so they
	// don't zero out the shared product.
	var acc btcec.FieldVal
	acc.SetInt(1)
	for j := 0; j < n; j++ {
		ls.prefix[j].Set(&acc)
		z := &ls.pts[j].Z
		if z.IsZero() {
			continue
		}
		z.Normalize()
		acc.Mul(z)
	}

	// One inversion for the whole batch: acc = 1 / product(Z).
	acc.Normalize()
	acc.Inverse()

	// Backward pass: recover each individual 1/Z[j].
	for j := n - 1; j >= 0; j-- {
		z := &ls.pts[j].Z
		if z.IsZero() {
			continue
		}
		ls.zinv[j].Mul2(&acc, &ls.prefix[j])
		acc.Mul(z)
	}

	// Derive affine x (and y parity) per lane, then hash and test.
	var x, y, zinv2, zinv3 btcec.FieldVal
	for j := 0; j < n; j++ {
		if ls.pts[j].Z.IsZero() {
			continue
		}
		zinv2.SquareVal(&ls.zinv[j])
		x.Mul2(&ls.pts[j].X, &zinv2).Normalize()
		zinv3.Mul2(&zinv2, &ls.zinv[j])
		y.Mul2(&ls.pts[j].Y, &zinv3).Normalize()

		if fn(j, h.compute(y.IsOdd(), x.Bytes())) {
			return true
		}
	}
	return false
}

// advance adds G to every point in the batch (one EC addition per lane).
func (ls *laneSet) advance(g *btcec.JacobianPoint) {
	var tmp btcec.JacobianPoint
	for j := range ls.pts {
		btcec.AddNonConst(&ls.pts[j], g, &tmp)
		ls.pts[j].Set(&tmp)
	}
}

// searchForPrivateKey searches for a private key whose compressed public key
// hashes to targetHash160, within [minKey, maxKey], using one goroutine per CPU
// core. Each worker walks a contiguous slice of the range from a shared random
// offset, advancing a batch of lanes with incremental point addition.
func searchForPrivateKey(minKey, maxKey *big.Int, targetHash160 []byte) {
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	// Inclusive count of keys in the range.
	rangeLen := new(big.Int).Sub(maxKey, minKey)
	rangeLen.Add(rangeLen, big.NewInt(1))

	// Shrink the batch (then the worker count) so we never have more lanes than
	// keys in the range (only relevant for tiny puzzle ranges).
	lanes := lanesPerWorker
	totalLanes := func(l, w int) *big.Int {
		return new(big.Int).Mul(big.NewInt(int64(w)), big.NewInt(int64(l)))
	}
	for lanes > 1 && totalLanes(lanes, numWorkers).Cmp(rangeLen) > 0 {
		lanes /= 2
	}
	for numWorkers > 1 && totalLanes(lanes, numWorkers).Cmp(rangeLen) > 0 {
		numWorkers--
	}
	nLanes := numWorkers * lanes

	// Give every lane its own uniformly-random starting key drawn from the whole
	// [minKey, maxKey] range; each lane then advances forward from its own point.
	// This makes every run sample genuinely random regions of the range instead
	// of always beginning near minKey.
	bases := make([]*big.Int, nLanes)
	for i := range bases {
		off, err := rand.Int(rand.Reader, rangeLen)
		if err != nil {
			off = big.NewInt(0)
		}
		bases[i] = off.Add(off, minKey)
	}

	// maxTickWithinRange reports how many forward steps a lane may take before
	// leaving the range, or -1 when that exceeds int64 (i.e. effectively
	// unbounded for any real run — the normal case for large puzzle ranges).
	maxTickWithinRange := func(base *big.Int) int64 {
		d := new(big.Int).Sub(maxKey, base)
		if d.IsInt64() {
			return d.Int64()
		}
		return -1
	}

	fmt.Printf("%sStarting key search with %d workers x %d lanes...%s\n", ColorBlue, numWorkers, lanes, ColorReset)
	firstLaneBase := bases[0]
	fmt.Printf("%sRandom start point (worker 0, lane 0): %s%s%s\n", ColorCyan, ColorBoldCyan, hex.EncodeToString(firstLaneBase.Bytes()), ColorReset)

	// Coordination state.
	var (
		found     atomic.Bool
		totalIter int64
		lastTick  atomic.Int64
		resultMu  sync.Mutex
		foundKey  []byte
		foundH    []byte
		wg        sync.WaitGroup
		closeOnce sync.Once
		doneCh    = make(chan struct{})
	)
	signalDone := func() { closeOnce.Do(func() { close(doneCh) }) }

	startTime := time.Now()

	// Progress reporter.
	go func() {
		for !found.Load() {
			time.Sleep(10 * time.Second)
			if found.Load() {
				return
			}
			it := atomic.LoadInt64(&totalIter)
			kps := float64(it) / time.Since(startTime).Seconds()
			lastKey := new(big.Int).Add(firstLaneBase, big.NewInt(lastTick.Load()))
			fmt.Printf("%sChecked %d keys (%.2f keys/sec) - Last key: %s%s\n",
				ColorCyan, it, kps, hex.EncodeToString(lastKey.Bytes()), ColorReset)
		}
	}()

	// Workers.
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()

			baseKeys := bases[w*lanes : (w+1)*lanes]
			maxTicks := make([]int64, lanes)
			unbounded := false
			var maxTick int64
			for j, b := range baseKeys {
				mt := maxTickWithinRange(b)
				maxTicks[j] = mt
				if mt < 0 {
					unbounded = true
				} else if mt > maxTick {
					maxTick = mt
				}
			}

			ls := newLaneSet(baseKeys)
			h := newHash160er()
			g := generatorPoint()

			for tick := int64(0); ; tick++ {
				if found.Load() {
					return
				}

				matched := ls.forEachHash(h, func(lane int, h160 []byte) bool {
					if maxTicks[lane] >= 0 && tick > maxTicks[lane] {
						return false // this lane has walked past maxKey
					}
					if !bytes.Equal(h160, targetHash160) {
						return false
					}
					key := new(big.Int).Add(baseKeys[lane], big.NewInt(tick))
					resultMu.Lock()
					if !found.Load() {
						found.Store(true)
						foundKey = padPrivateKey(key.Bytes(), 32)
						foundH = append([]byte(nil), h160...)
					}
					resultMu.Unlock()
					signalDone()
					return true
				})

				atomic.AddInt64(&totalIter, int64(lanes))
				if matched {
					return
				}
				if w == 0 {
					lastTick.Store(tick)
				}

				// Stop once every lane has walked past maxKey. Only reachable for
				// small ranges; large puzzle ranges run until a match is found.
				if !unbounded && tick >= maxTick {
					return
				}
				ls.advance(&g)
			}
		}(w)
	}

	// Signal completion when all workers exit without a match.
	go func() {
		wg.Wait()
		signalDone()
	}()

	<-doneCh

	// Report results.
	resultMu.Lock()
	defer resultMu.Unlock()
	if found.Load() {
		privateKeyHex := hex.EncodeToString(foundKey)
		hash160Hex := hex.EncodeToString(foundH)
		fmt.Printf("\n%sMATCH FOUND!%s\n", ColorBoldGreen, ColorReset)
		fmt.Printf("%sPrivate Key: %s%s%s\n", ColorGreen, ColorBoldGreen, privateKeyHex, ColorReset)
		fmt.Printf("%sHash160: %s%s%s\n", ColorGreen, ColorBoldGreen, hash160Hex, ColorReset)

		filename := "found_key_" + hash160Hex[:8] + ".txt"
		content := fmt.Sprintf("Private Key: %s\nHash160: %s\nFound at: %s", privateKeyHex, hash160Hex, time.Now().Format(time.RFC3339))
		if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
			fmt.Printf("%sError writing key to file: %s%s\n", ColorRed, err, ColorReset)
		} else {
			fmt.Printf("%sPrivate key saved to file: %s%s%s\n", ColorGreen, ColorBoldGreen, filename, ColorReset)
		}
	} else {
		fmt.Printf("\n%sNo match found after checking approximately %d keys.%s\n", ColorYellow, atomic.LoadInt64(&totalIter), ColorReset)
	}
}
