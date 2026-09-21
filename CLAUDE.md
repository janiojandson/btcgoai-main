# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build -o bitcoin_finder.exe

# Run
./bitcoin_finder.exe

# Run tests
go test ./...

# Run a single test
go test -run TestName ./...

# Tidy dependencies
go mod tidy
```

The program must be run from the project root directory, as it opens data files relative to the working directory (`data/wallets.json`, `data/ranges.json`, `data/hash160s.json`).

**Build environment note (WSL):** the committed `bitcoin_finder.exe` is a Windows binary; the user normally builds with the Windows Go toolchain. From inside WSL, the Windows `go.exe` (under `/mnt/c/Program Files/Go`) fails with `RLock go.mod: Incorrect function` because it can't lock files on the Linux filesystem. Use a native Linux Go instead (e.g. `mise install go@1.22`; set `GOROOT` to the install dir and prepend its `bin` to `PATH`). Cross-compile the Windows artifact with `GOOS=windows GOARCH=amd64 go build -o bitcoin_finder.exe .`.

## Purpose

This is a CLI tool for participating in the **Bitcoin Puzzle challenges** (the well-known 1000 BTC / 32 BTC puzzle transactions, where keys for puzzles 1–160 are deliberately constrained to known ranges and solving them is the intended goal). The 160 wallets and their key ranges in `data/` correspond to these puzzle entries.

**This code exists solely for the puzzle challenge. It must never be adapted or used to attack regular wallets that don't belong to the puzzle.**

## Architecture

The tool searches private keys within a puzzle's defined range to find the key matching the target puzzle wallet's Hash160 (RIPEMD-160 of SHA-256 of the compressed public key).

### Flow

1. `main.go` — entry point: loads data, prompts for wallet number (1–160), resolves the target Hash160 and key range, then calls `searchForPrivateKey`.
2. `search.go` — parallel search engine. See **Search algorithm** below. Progress is logged every 10 seconds. On match, writes the private key to `found_key_<hash160prefix>.txt`.
3. `bitcoin.go` — cryptographic primitives: `privateKeyToHash160` (the reference/seed path) and `privateKeyToAddress` (unused in the main path). Uses `btcsuite/btcd` for secp256k1 and `btcutil.Hash160`.
4. `data.go` — data loading: reads `data/hash160s.json` as the primary source; falls back to `data/wallets.json` (address strings) but conversion is not implemented.
5. `models.go` — JSON structs (`WalletData`, `RangeData`, `Range`, `Hash160Data`).
6. `colors.go` — ANSI terminal color constants.

### Data files (`data/`)

- `hash160s.json` — array of hex-encoded Hash160 values, one per wallet (preferred input)
- `wallets.json` — array of Bitcoin mainnet addresses (used only if `hash160s.json` is absent; conversion path is a stub)
- `ranges.json` — array of `{min, max, status}` objects with 0x-prefixed hex bounds; index aligns 1-to-1 with `hash160s.json`

### `temp/hash160_generator.go`

A standalone utility (its own `main` package) that converts `data/wallets.json` → `data/hash160s.json`. Run it from the `temp/` directory; it resolves paths relative to its parent directory.

### Search algorithm (`search.go`)

The search avoids a full secp256k1 scalar multiplication per key (~19× faster per key in benchmarks; the hot loop is now bounded by SHA256+RIPEMD160, not the EC math). The design, in `laneSet`:

- **Incremental point addition.** Consecutive keys differ by 1, so consecutive public keys differ by `+G`. Each worker holds a batch of `lanesPerWorker` (1024) points and advances all of them by one EC addition per step (`advance`) instead of recomputing from scratch. Only the initial seed points use a full scalar multiplication (`newLaneSet`).
- **Batched (Montgomery) inversion.** Converting a Jacobian point to affine needs a modular inverse (the expensive field op). `forEachHash` inverts the whole batch's `Z` values with a single `FieldVal.Inverse()` plus multiplications, amortizing one inversion over 1024 keys.
- **Random independent lane starts.** Every lane (`numWorkers × lanesPerWorker` of them) gets its own uniformly-random starting key drawn from the full `[minKey, maxKey]` range and marches forward from there, so each run samples genuinely random regions rather than starting near `minKey`. A per-lane `maxTick` bounds the walk to the range (relevant only for small ranges; large puzzle ranges are effectively unbounded and run until a match). Batch and worker counts shrink automatically for ranges smaller than the lane count.
- These primitives come from `btcec/v2`, which re-exports `secp256k1/v4`'s `JacobianPoint`, `FieldVal`, `ModNScalar`, `AddNonConst`, and `ScalarBaseMultNonConst`. All `FieldVal` ops require magnitude ≤ 8 and output magnitude 1, so chained `Mul`/`Square`/`Inverse` are safe; `Normalize` before `Bytes`/`IsOdd`.

**Correctness is verified by `search_test.go`**, which asserts the batched/incremental pipeline yields byte-identical hash160s to the reference `privateKeyToHash160` across multiple keys and advance steps. Run it (`go test ./...`) after any change to the field/curve math — silent math bugs produce wrong hashes, not crashes. `bench_test.go` compares old-vs-new throughput.

### Other design notes

- Coordination: workers share an `atomic.Bool` (`found`) for the fast stop-check, a mutex-guarded result, and a `sync.Once`-closed `doneCh`.
- `walletNum` input is 1-indexed; it's converted to 0-indexed before array access.
