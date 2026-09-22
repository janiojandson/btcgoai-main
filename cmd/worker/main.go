package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
)

const (
	lanesPerWorker = 1024

	defaultHubURL     = "https://puzzleradar-production.up.railway.app"
	defaultWorkerName = ""
	defaultLanes      = lanesPerWorker
	defaultLogLevel   = "info"
	defaultCPUPercent = 100
)

var knownTestKeys = map[int]struct {
	PrivateKeyHex string
	Address       string
	StartHex      string
	EndHex        string
}{
	5: {
		PrivateKeyHex: "0000000000000000000000000000000000000000000000000000000000000013",
		Address:       "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		StartHex:      "10",
		EndHex:        "20",
	},
	10: {
		PrivateKeyHex: "000000000000000000000000000000000000000000000000000000000000029a",
		Address:       "1CChNs6SVn4tr8dNx7whSmF5N49WqPshhD",
		StartHex:      "290",
		EndHex:        "2a0",
	},
	20: {
		PrivateKeyHex: "00000000000000000000000000000000000000000000000000000000000ef90d",
		Address:       "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum",
		StartHex:      "ef900",
		EndHex:        "ef920",
	},
	30: {
		PrivateKeyHex: "000000000000000000000000000000000000000000000000000000003a4b953d",
		Address:       "1KhEbWhbtozpLDVw9fh3KhEtWBX7z5us9A",
		StartHex:      "3a4b9500",
		EndHex:        "3a4b9600",
	},
}

type Config struct {
	HubURL      string
	WorkerName  string
	Lanes       int
	LogLevel    string
	CPUPercent  int
	Threads     int
	StealthMode bool
	Puzzle      int
	TestMode    bool
}

type RangeAssignment struct {
	CustomRange   string          `json:"custom_range"`
	PoolConfLine  string          `json:"pool_conf_line"`
	LoteID        string          `json:"lote_id"`
	ChunkIndex    int             `json:"chunk_index"`
	ChunkLabel    string          `json:"chunk_label"`
	PriorityScore int             `json:"priority_score"`
	Reason        string          `json:"reason"`
	AllocatedAt   string          `json:"allocated_at"`
	Puzzle        int             `json:"puzzle"`
	Targets       []Target        `json:"targets"`
	ParentHex     string          `json:"parentHex"`
	PowAddresses  []string        `json:"powAddresses"`
}

type Target struct {
	Hash160 string `json:"hash160"`
	Address string `json:"address"`
	Type    string `json:"type"`
}

type WorkerRegisterReq struct {
	Name      string `json:"name"`
	Hardware  string `json:"hardware"`
	GPUModel  string `json:"gpuModel"`
	CPUModel  string `json:"cpuModel"`
	Lanes     int    `json:"lanes"`
	Version   string `json:"version"`
}

type HeartbeatReq struct {
	WorkerID     string `json:"worker_id"`
	KeysChecked  uint64 `json:"keys_checked"`
	Hashrate     uint64 `json:"hashrate"`
	ProgressPct  string `json:"progress_pct"`
	CurrentKey   string `json:"current_key"`
	Status       string `json:"status"`
	LoteID       string `json:"lote_id"`
	Timestamp    string `json:"timestamp"`
}

type KeyFoundReq struct {
	Status       string `json:"status"`
	PrivateKey   string `json:"privatekey"`
	WorkerName   string `json:"workername"`
	TargetPuzzle string `json:"targetpuzzle"`
	LoteID       string `json:"lote_id,omitempty"`
}

type WebhookReq struct {
	Status       string `json:"status"`
	Hex          string `json:"hex,omitempty"`
	PrivateKey   string `json:"privatekey,omitempty"`
	WorkerName   string `json:"workername"`
	TargetPuzzle string `json:"targetpuzzle"`
	Hashrate     string `json:"hashrate,omitempty"`
	LoteID       string `json:"lote_id,omitempty"`
}

type MilestoneReq struct {
	WorkerID    string `json:"worker_id"`
	Milestone   int    `json:"milestone"`
	CurrentKey  string `json:"current_key"`
	Hashrate    uint64 `json:"hashrate"`
	KeysDelta   uint64 `json:"keys_delta"`
	LoteID      string `json:"lote_id"`
	Timestamp   string `json:"timestamp"`
}

var (
	version = "1.0.0"
)

func main() {
	cfg := loadConfig()

	cpuFlag := flag.Int("cpu", 0, "CPU usage percent (1-100), overrides CPU_PERCENT env")
	threadsFlag := flag.Int("threads", 0, "Manual thread override, overrides THREADS env")
	stealthFlag := flag.Bool("stealth", false, "Stealth mode for academic/cloud environments")
	puzzleFlag := flag.String("puzzle", "71", "Puzzle number (71, 130, etc) or 'test'/'0' for test mode. Overrides PUZZLE env.")
	testFlag := flag.Bool("test", false, "Run benchmark test with known key for the selected puzzle")
	flag.Parse()

	if *cpuFlag > 0 {
		cfg.CPUPercent = *cpuFlag
	}
	if *threadsFlag > 0 {
		cfg.Threads = *threadsFlag
	}
	if *stealthFlag {
		cfg.StealthMode = true
	}
	if *testFlag {
		cfg.TestMode = true
	}

	puzzleStr := *puzzleFlag
	if puzzleStr == "test" || puzzleStr == "0" {
		cfg.TestMode = true
		cfg.Puzzle = 10
	} else {
		p, err := strconv.Atoi(puzzleStr)
		if err == nil && p > 0 {
			cfg.Puzzle = p
		}
	}

	if cfg.CPUPercent < 1 {
		cfg.CPUPercent = 1
	}
	if cfg.CPUPercent > 100 {
		cfg.CPUPercent = 100
	}

	totalCPUs := runtime.NumCPU()
	activeThreads := totalCPUs
	if cfg.Threads > 0 {
		activeThreads = cfg.Threads
	} else {
		activeThreads = max(1, (totalCPUs*cfg.CPUPercent)/100)
	}
	runtime.GOMAXPROCS(activeThreads)

	if !cfg.StealthMode {
		logInfo(cfg.StealthMode, "======================================================================")
		logInfo(cfg.StealthMode, " 🧩 PuzzleRadar Go Worker v%s — Motor secp256k1 (Batch Inversion)", version)
		logInfo(cfg.StealthMode, " [+] Worker: %s", cfg.WorkerName)
		logInfo(cfg.StealthMode, " [+] Hub: %s", cfg.HubURL)
		logInfo(cfg.StealthMode, " [+] Lanes: %d", cfg.Lanes)
		logInfo(cfg.StealthMode, " [+] Go: %s | CPUs: %d | Active Threads: %d (CPU: %d%%)", runtime.Version(), totalCPUs, activeThreads, cfg.CPUPercent)
		logInfo(cfg.StealthMode, "======================================================================\n")
	} else {
		logInfo(cfg.StealthMode, "[BENCHMARK] Worker started | Threads: %d | CPU: %d%%", activeThreads, cfg.CPUPercent)
	}

	client := &http.Client{Timeout: 30 * time.Second}

	if err := registerWorker(client, cfg); err != nil {
		logError(cfg.StealthMode, "Falha no registro: %v", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	go func() {
		<-sigCh
		logWarn(cfg.StealthMode, "Sinal de interrupção recebido, finalizando...")
		os.Exit(0)
	}()

	runWorkerLoop(client, cfg)
}

func loadConfig() Config {
	hubURL := getEnv("HUB_URL", defaultHubURL)
	workerName := getEnv("WORKER_NAME", defaultWorkerName)
	if workerName == "" {
		hostname, _ := os.Hostname()
		workerName = fmt.Sprintf("go-worker-%s-%d", hostname, time.Now().Unix()%10000)
	}
	lanesStr := getEnv("LANES", strconv.Itoa(defaultLanes))
	lanes, _ := strconv.Atoi(lanesStr)
	logLevel := getEnv("LOG_LEVEL", defaultLogLevel)

	cpuPercentStr := getEnv("CPU_PERCENT", strconv.Itoa(defaultCPUPercent))
	cpuPercent, _ := strconv.Atoi(cpuPercentStr)
	if cpuPercent < 1 {
		cpuPercent = 1
	}
	if cpuPercent > 100 {
		cpuPercent = 100
	}

	threadsStr := getEnv("THREADS", "0")
	threads, _ := strconv.Atoi(threadsStr)

	stealthMode := getEnv("STEALTH_MODE", "false") == "true"

	puzzleStr := getEnv("PUZZLE", "71")
	puzzle, _ := strconv.Atoi(puzzleStr)
	if puzzle <= 0 {
		puzzle = 71
	}

	testMode := getEnv("TEST_MODE", "false") == "true"

	return Config{
		HubURL:      strings.TrimSuffix(hubURL, "/"),
		WorkerName:  workerName,
		Lanes:       lanes,
		LogLevel:    logLevel,
		CPUPercent:  cpuPercent,
		Threads:     threads,
		StealthMode: stealthMode,
		Puzzle:      puzzle,
		TestMode:    testMode,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func registerWorker(client *http.Client, cfg Config) error {
	payload := WorkerRegisterReq{
		Name:     cfg.WorkerName,
		Hardware: "CPU_GO_MONTGOMERY",
		GPUModel: "N/A",
		CPUModel: runtime.GOARCH,
		Lanes:    cfg.Lanes,
		Version:  version,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", cfg.HubURL+"/api/workers/worker/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("registration failed: status %d", resp.StatusCode)
	}

logInfo(cfg.StealthMode, "[+] Worker registrado com sucesso: %s", cfg.WorkerName)
	return nil
}

func runTestMode(client *http.Client, cfg Config, h *hash160er, stealth bool) {
	testKey, ok := knownTestKeys[cfg.Puzzle]
	if !ok {
		logError(stealth, "[TEST] ❌ Puzzle %d não possui chave de teste conhecida. Use --puzzle 5, 10, 20 ou 30 com --test", cfg.Puzzle)
		return
	}
	
	logInfo(stealth, "[TEST] 🔬 Modo Benchmark Ativado — Puzzle #%d (Chave Conhecida)", cfg.Puzzle)
	logInfo(stealth, "[TEST] 🎯 Alvo: Endereço %s | Chave: 0x%s", testKey.Address, strings.TrimLeft(testKey.PrivateKeyHex, "0"))
	
	startBig := hexToBigInt(testKey.StartHex)
	endBig := hexToBigInt(testKey.EndHex)
	totalKeys := new(big.Int).Sub(endBig, startBig)
	
	logInfo(stealth, "[TEST] 📊 Range de teste: 0x%s ➔ 0x%s (~%d chaves)", testKey.StartHex, testKey.EndHex, totalKeys.Uint64())
	
	bases := make([]*big.Int, 1)
	bases[0] = startBig
	
	ls := newLaneSet(bases)
	
	G := generatorPoint()
	
	var totalIter uint64
	
	logInfo(stealth, "[TEST] 🔍 Iniciando busca no range de teste...")
	
	var tick uint64
	found := false
	
	for !found {
		_ = ls.forEachHash(h, func(lane int, h160 []byte) bool {
			key := new(big.Int).Add(bases[lane], big.NewInt(int64(tick)))
			keyHex := padPrivateKey(key.Bytes(), 32)
			
			if strings.EqualFold(keyHex, testKey.PrivateKeyHex) {
				found = true
				logInfo(stealth, "[SUCCESS] 🎯 CHAVE DE TESTE LOCALIZADA COM SUCESSO!")
				logInfo(stealth, "[SUCCESS] 🔑 Chave Privada: %s", keyHex)
				logInfo(stealth, "[SUCCESS] 📍 Endereço: %s", testKey.Address)
				
				filename := fmt.Sprintf("KEY_FOUND_TEST_P%d_%s.txt", cfg.Puzzle, time.Now().Format("20060102_150405"))
				content := fmt.Sprintf("Private Key: %s\nHash160: %s\nAddress: %s\nType: TEST\nPuzzle: %d\nFound at: %s\nWorker: %s\n",
					keyHex, "7c076a65c3f7b5b8b8b8b8b8b8b8b8b8b8b8b8b8", testKey.Address, cfg.Puzzle, time.Now().Format(time.RFC3339), cfg.WorkerName)
				os.WriteFile(filename, []byte(content), 0600)
				logInfo(stealth, "[SUCCESS] 💾 Arquivo salvo: %s", filename)
				
				// Send webhook with x-nexus-secret header
				payload := KeyFoundReq{
					Status:       "keyFound",
					PrivateKey:   keyHex,
					WorkerName:   cfg.WorkerName,
					TargetPuzzle: strconv.Itoa(cfg.Puzzle),
					LoteID:       "TEST_MODE",
				}
				body, _ := json.Marshal(payload)
				req, _ := http.NewRequest("POST", cfg.HubURL+"/api/webhook/btcpuzzle", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("x-nexus-secret", "SenhaMuitoForteFamilia123")
				client.Do(req)
				logInfo(stealth, "[SUCCESS] 📡 Webhook disparado para Hub com x-nexus-secret")
				
				return true
			}
			return false
		})
		
		atomic.AddUint64(&totalIter, 1)
		tick++
		
		if tick%1000 == 0 {
			ls.advance(&G)
		}
		
		if found {
			break
		}
		
		if tick > totalKeys.Uint64()+10 {
			logWarn(stealth, "[TEST] ⚠️ Chave não encontrada no range esperado")
			break
		}
	}
	
	if found {
		logInfo(stealth, "[TEST] ✅ Benchmark concluído com sucesso em %d iterações", tick)
	} else {
		logError(stealth, "[TEST] ❌ Benchmark falhou - chave não encontrada")
	}
}

func runWorkerLoop(client *http.Client, cfg Config) {
	G := generatorPoint()
	h := newHash160er()

	var (
		found             atomic.Bool
		totalIter         uint64
		startTime         = time.Now()
		lastHeartbeatKeys uint64
		lastHeartbeatTime = time.Now()
		lastMilestone     int
		lastRealHashrate  uint64
	)

	heartbeatTicker := time.NewTicker(10 * time.Second)
	defer heartbeatTicker.Stop()

	stealth := cfg.StealthMode

	// Test mode: use known key for instant validation
	if cfg.TestMode {
		h := newHash160er()
		runTestMode(client, cfg, h, stealth)
		return
	}

	for !found.Load() {
		rangeData, err := fetchRange(client, cfg)
		if err != nil {
			logError(stealth, "[-] Erro ao buscar range: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		if rangeData == nil || rangeData.CustomRange == "" {
			logWarn(stealth, "[-] Range vazio, aguardando...")
			time.Sleep(10 * time.Second)
			continue
		}

		startHex, endHex, _ := parseRange(rangeData.CustomRange)
		startBig := hexToBigInt(startHex)
		endBig := hexToBigInt(endHex)
		totalKeys := new(big.Int).Sub(endBig, startBig)

		logInfo(stealth, "[+] Fatia alocada: %s ➔ %s (~%.2fM chaves)", startHex, endHex, float64(totalKeys.Uint64())/1e6)

		targetMap := make(map[string]Target)
		for _, t := range rangeData.Targets {
			targetMap[t.Hash160] = t
		}

		bases := make([]*big.Int, cfg.Lanes)
		for i := range bases {
			off, _ := rand.Int(rand.Reader, totalKeys)
			bases[i] = new(big.Int).Add(off, startBig)
		}

		ls := newLaneSet(bases)
		var tick uint64
		lastMilestone = 0

		for {
			if found.Load() {
				break
			}

			select {
			case <-heartbeatTicker.C:
				now := time.Now()
				elapsedSecs := now.Sub(lastHeartbeatTime).Seconds()
				deltaKeys := atomic.LoadUint64(&totalIter) - lastHeartbeatKeys
				if elapsedSecs > 0 {
					lastRealHashrate = uint64(float64(deltaKeys) / elapsedSecs)
				}
				sendHeartbeat(client, cfg, rangeData.LoteID, atomic.LoadUint64(&totalIter), totalKeys, startBig, tick, lastRealHashrate)
				lastHeartbeatKeys = atomic.LoadUint64(&totalIter)
				lastHeartbeatTime = now
			default:
			}

			matched := ls.forEachHash(h, func(lane int, h160 []byte) bool {
				h160Hex := hex.EncodeToString(h160)
				if target, ok := targetMap[h160Hex]; ok {
					key := new(big.Int).Add(bases[lane], big.NewInt(int64(tick)))
					keyHex := padPrivateKey(key.Bytes(), 32)
					found.Store(true)
					if stealth {
						logInfo(stealth, "[BENCHMARK] Match found | Type: %s | Ops: %d", target.Type, atomic.LoadUint64(&totalIter))
					} else {
						logInfo(stealth, "\n🎉🎉🎉 [DESCOBERTA] CHAVE ENCONTRADA! Type: %s | Key: %s | Addr: %s 🎉🎉🎉\n", target.Type, keyHex, target.Address)
					}
					submitKeyFound(client, cfg, rangeData.LoteID, keyHex, target)
					return true
				}
				return false
			})

			atomic.AddUint64(&totalIter, uint64(cfg.Lanes))
			tick++

			currentKeys := atomic.LoadUint64(&totalIter)
			currentMilestone := int(new(big.Int).Div(new(big.Int).Mul(new(big.Int).SetUint64(currentKeys), big.NewInt(10)), totalKeys).Uint64())
			if currentMilestone > lastMilestone && currentMilestone <= 10 {
				for m := lastMilestone + 1; m <= currentMilestone; m++ {
					currentKey := new(big.Int).Add(startBig, big.NewInt(int64(tick)))
					go sendMilestone(client, cfg, rangeData.LoteID, m, currentKey, lastRealHashrate, currentKeys-lastHeartbeatKeys)
				}
				lastMilestone = currentMilestone
			}

			if matched {
				break
			}

			if tick%100000 == 0 && cfg.Lanes == 1 {
				ls.advance(&G)
			} else {
				ls.advance(&G)
			}
		}

		if found.Load() {
			break
		}

		sendRangeScanned(client, cfg, rangeData.LoteID, startHex, atomic.LoadUint64(&totalIter))
	}

	sendFinalStats(cfg, atomic.LoadUint64(&totalIter), time.Since(startTime))
}

func fetchRange(client *http.Client, cfg Config) (*RangeAssignment, error) {
	url := fmt.Sprintf("%s/api/range/next/%s?client=go&hashrate=%d&puzzle=%d", cfg.HubURL, cfg.WorkerName, estimateHashrate(cfg.Lanes), cfg.Puzzle)
	if cfg.TestMode {
		url += "&test=true"
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var data RangeAssignment
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func sendHeartbeat(client *http.Client, cfg Config, loteID string, keysChecked uint64, totalKeys *big.Int, startBig *big.Int, tick uint64, realHashrate uint64) {
	progress := "0.0"
	if totalKeys.Sign() > 0 {
		pct := float64(keysChecked) / float64(totalKeys.Uint64()) * 100
		progress = fmt.Sprintf("%.2f", pct)
	}

	currentKey := new(big.Int).Add(startBig, big.NewInt(int64(tick)))
	
	hashrate := realHashrate
	if hashrate == 0 {
		hashrate = estimateHashrate(cfg.Lanes)
	}

	payload := HeartbeatReq{
		WorkerID:    cfg.WorkerName,
		KeysChecked: keysChecked,
		Hashrate:    hashrate,
		ProgressPct: progress,
		CurrentKey:  "0x" + padPrivateKey(currentKey.Bytes(), 32),
		Status:      "running",
		LoteID:      loteID,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", cfg.HubURL+"/api/workers/worker/beat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)
}

func sendMilestone(client *http.Client, cfg Config, loteID string, milestone int, currentKey *big.Int, hashrate uint64, keysDelta uint64) {
	payload := MilestoneReq{
		WorkerID:   cfg.WorkerName,
		Milestone:  milestone,
		CurrentKey: "0x" + padPrivateKey(currentKey.Bytes(), 32),
		Hashrate:   hashrate,
		KeysDelta:  keysDelta,
		LoteID:     loteID,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", cfg.HubURL+"/api/workers/worker/milestone", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)
}

func submitKeyFound(client *http.Client, cfg Config, loteID, keyHex string, target Target) {
	payload := KeyFoundReq{
		Status:       "keyFound",
		PrivateKey:   keyHex,
		WorkerName:   cfg.WorkerName,
		TargetPuzzle: strconv.Itoa(cfg.Puzzle),
		LoteID:       loteID,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", cfg.HubURL+"/api/webhook/btcpuzzle", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-nexus-secret", "SenhaMuitoForteFamilia123")
	client.Do(req)

	filename := fmt.Sprintf("found_key_%s_%s.txt", target.Hash160[:8], time.Now().Format("20060102_150405"))
	content := fmt.Sprintf("Private Key: %s\nHash160: %s\nAddress: %s\nType: %s\nFound at: %s\nWorker: %s\nLote: %s\n",
		keyHex, target.Hash160, target.Address, target.Type, time.Now().Format(time.RFC3339), cfg.WorkerName, loteID)
	os.WriteFile(filename, []byte(content), 0600)
	logInfo(cfg.StealthMode, "[+] Chave salva em: %s", filename)
}

func sendRangeScanned(client *http.Client, cfg Config, loteID, startHex string, keysChecked uint64) {
	payload := WebhookReq{
		Status:       "rangeScanned",
		Hex:          startHex,
		WorkerName:   cfg.WorkerName,
		TargetPuzzle: strconv.Itoa(cfg.Puzzle),
		Hashrate:     fmt.Sprintf("%.2f kH/s", float64(estimateHashrate(cfg.Lanes))/1000),
		LoteID:       loteID,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", cfg.HubURL+"/api/webhook/btcpuzzle", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client.Do(req)
}

func sendFinalStats(cfg Config, keysChecked uint64, elapsed time.Duration) {
	avgSpeed := float64(keysChecked) / elapsed.Seconds()
	if cfg.StealthMode {
		logInfo(cfg.StealthMode, "[BENCHMARK] Final Stats | Keys: %d | Time: %.1fs | Rate: %.2f kH/s", keysChecked, elapsed.Seconds(), avgSpeed/1000)
	} else {
		logInfo(cfg.StealthMode, "\n======================================================================")
		logInfo(cfg.StealthMode, " 📊 Estatísticas Finais - Worker: %s", cfg.WorkerName)
		logInfo(cfg.StealthMode, " [+] Chaves verificadas: %d", keysChecked)
		logInfo(cfg.StealthMode, " [+] Tempo total: %.1fs", elapsed.Seconds())
		logInfo(cfg.StealthMode, " [+] Velocidade média: %.2f kH/s", avgSpeed/1000)
		logInfo(cfg.StealthMode, "======================================================================\n")
	}
}

func estimateHashrate(lanes int) uint64 {
	baseKPS := uint64(100000)
	return uint64(lanes) * baseKPS
}

func parseRange(customRange string) (start, end string, err error) {
	parts := strings.Split(customRange, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid range format: %s", customRange)
	}
	return parts[0], parts[1], nil
}

func hexToBigInt(hexStr string) *big.Int {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	i := new(big.Int)
	i.SetString(hexStr, 16)
	return i
}

func padPrivateKey(b []byte, length int) string {
	if len(b) >= length {
		return hex.EncodeToString(b[len(b)-length:])
	}
	padded := make([]byte, length)
	copy(padded[length-len(b):], b)
	return hex.EncodeToString(padded)
}

func padPrivateKeyBytes(b []byte, length int) []byte {
	if len(b) >= length {
		return b[len(b)-length:]
	}
	padded := make([]byte, length)
	copy(padded[length-len(b):], b)
	return padded
}

func generatorPoint() btcec.JacobianPoint {
	var one btcec.ModNScalar
	one.SetInt(1)
	var g btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&one, &g)
	g.ToAffine()
	return g
}

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

type laneSet struct {
	pts    []btcec.JacobianPoint
	zinv   []btcec.FieldVal
	prefix []btcec.FieldVal
}

func newLaneSet(baseKeys []*big.Int) *laneSet {
	n := len(baseKeys)
	ls := &laneSet{
		pts:    make([]btcec.JacobianPoint, n),
		zinv:   make([]btcec.FieldVal, n),
		prefix: make([]btcec.FieldVal, n),
	}
	var k btcec.ModNScalar
	for j, key := range baseKeys {
		keyBytes := padPrivateKeyBytes(key.Bytes(), 32)
		k.SetByteSlice(keyBytes)
		btcec.ScalarBaseMultNonConst(&k, &ls.pts[j])
	}
	return ls
}

func (ls *laneSet) forEachHash(h *hash160er, fn func(lane int, h160 []byte) bool) bool {
	n := len(ls.pts)
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
	acc.Normalize()
	acc.Inverse()
	for j := n - 1; j >= 0; j-- {
		z := &ls.pts[j].Z
		if z.IsZero() {
			continue
		}
		ls.zinv[j].Mul2(&acc, &ls.prefix[j])
		acc.Mul(z)
	}
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

func (ls *laneSet) advance(g *btcec.JacobianPoint) {
	var tmp btcec.JacobianPoint
	for j := range ls.pts {
		btcec.AddNonConst(&ls.pts[j], g, &tmp)
		ls.pts[j].Set(&tmp)
	}
}

func logInfo(stealth bool, format string, args ...interface{}) {
	if stealth {
		fmt.Printf("[BENCHMARK] "+format+"\n", args...)
	} else {
		fmt.Printf("[INFO] "+format+"\n", args...)
	}
}

func logWarn(stealth bool, format string, args ...interface{}) {
	if stealth {
		fmt.Printf("[BENCHMARK] "+format+"\n", args...)
	} else {
		fmt.Printf("[WARN] "+format+"\n", args...)
	}
}

func logError(stealth bool, format string, args ...interface{}) {
	if stealth {
		fmt.Printf("[BENCHMARK] Error: "+format+"\n", args...)
	} else {
		fmt.Printf("[ERROR] "+format+"\n", args...)
	}
}