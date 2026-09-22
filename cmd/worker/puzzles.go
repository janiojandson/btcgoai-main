package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// PuzzleMeta describes one of the 160 official Bitcoin puzzles.
type PuzzleMeta struct {
	PuzzleNumber int    `json:"puzzleNumber"`
	Bits         int    `json:"bits"`
	MinHex       string `json:"minHex"`
	MaxHex       string `json:"maxHex"`
	Address      string `json:"address"`
	PubKey       string `json:"pubKey"`
	PrivKey      string `json:"privKey"`
	Hash160      string `json:"hash160"`
	PrizeBTC     float64 `json:"prizeBtc"`
	Status       string `json:"status"`
	Solved       bool   `json:"solved"`
}

type puzzleDataset struct {
	GeneratedAt string        `json:"generatedAt"`
	Total       int           `json:"total"`
	Solved      int           `json:"solved"`
	Puzzles     []PuzzleMeta  `json:"puzzles"`
}

var puzzleCache map[int]PuzzleMeta

// loadPuzzleDataset reads data/puzzles.json relative to CWD or executable dir.
func loadPuzzleDataset() map[int]PuzzleMeta {
	if puzzleCache != nil {
		return puzzleCache
	}
	candidates := []string{
		"data/puzzles.json",
		"../data/puzzles.json",
		"../../data/puzzles.json",
		"cmd/worker/data/puzzles.json",
	}
	if exe, err := os.Executable(); err == nil {
		dir := dirOf(exe)
		candidates = append(candidates,
			dir+"/data/puzzles.json",
			dir+"/../data/puzzles.json",
			dir+"/../../data/puzzles.json",
		)
	}
	var raw []byte
	var err error
	for _, c := range candidates {
		raw, err = os.ReadFile(c)
		if err == nil {
			break
		}
	}
	if err != nil {
		return map[int]PuzzleMeta{}
	}
	var ds puzzleDataset
	if err := json.Unmarshal(raw, &ds); err != nil {
		return map[int]PuzzleMeta{}
	}
	puzzleCache = make(map[int]PuzzleMeta, len(ds.Puzzles))
	for _, p := range ds.Puzzles {
		puzzleCache[p.PuzzleNumber] = p
	}
	return puzzleCache
}

// getPuzzle returns metadata for puzzle n (1-160) or false.
func getPuzzle(n int) (PuzzleMeta, bool) {
	if n < 1 || n > 160 {
		return PuzzleMeta{}, false
	}
	p, ok := loadPuzzleDataset()[n]
	return p, ok
}

// puzzleRangeBounds returns inclusive [min,max] as hex without 0x.
func puzzleRangeBounds(p PuzzleMeta) (startHex, endHex string) {
	startHex = strings.TrimPrefix(strings.ToLower(p.MinHex), "0x")
	endHex = strings.TrimPrefix(strings.ToLower(p.MaxHex), "0x")
	return
}

// defaultBenchmarkRange returns the standard [2^(N-1), 2^N-1] range for puzzle N.
func defaultBenchmarkRange(n int) (startHex, endHex string) {
	if n <= 0 {
		return "1", "1"
	}
	// 2^(n-1) for n<=64 fits uint64; for n>64 use big via hex strings
	if n-1 < 64 {
		s := uint64(1) << uint(n-1)
		e := uint64(1)<<uint(n) - 1
		if n == 64 {
			e = ^uint64(0)
		}
		return fmt.Sprintf("%x", s), fmt.Sprintf("%x", e)
	}
	// Build hex for 2^(n-1): "1" followed by (n-1)/4 zeros plus remainder bits
	return hexPow2(n - 1), hexPow2Minus1(n)
}

func hexPow2(exp int) string {
	if exp < 0 {
		return "0"
	}
	fullBytes := exp / 4
	rem := exp % 4
	var sb strings.Builder
	if rem > 0 {
		// nibble values 1,2,4,8
		nibble := 1 << rem
		sb.WriteString(fmt.Sprintf("%x", nibble))
		// remaining full zero bytes
		for i := 0; i < fullBytes; i++ {
			sb.WriteString("00")
		}
	} else {
		sb.WriteString("1")
		for i := 0; i < fullBytes; i++ {
			sb.WriteString("00")
		}
	}
	return sb.String()
}

func hexPow2Minus1(exp int) string {
	// 2^exp - 1 => exp bits of 1
	if exp <= 0 {
		return "0"
	}
	fullNibbles := exp / 4
	rem := exp % 4
	var sb strings.Builder
	if rem > 0 {
		sb.WriteString(fmt.Sprintf("%x", (1<<rem)-1))
	}
	for i := 0; i < fullNibbles; i++ {
		sb.WriteString("f")
	}
	if rem == 0 && fullNibbles == 0 {
		return "0"
	}
	return sb.String()
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
