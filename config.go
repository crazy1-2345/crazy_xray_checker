package main

import "time"

// пути/файлы
var (
	inputFile   = "input.txt"
	outputDir   = "result"
	allOutFile  = outputDir + "/result.txt"
	workingFile = outputDir + "/working.txt"
	firstOKFile = outputDir + "/first_working.txt"

	configJSONPath = "config.json"
)

// флаги (инициализируются в main)
var (
	workers        int
	bootWait       time.Duration
	testTimeout    time.Duration
	xrayRunBudget  time.Duration
	retrySNI       int
	enableTCPProbe bool
	maxWorkCfg     int
	serveKeep      bool // ← держать веб-сервер после завершения проверки
)

// дефолтные значения
const (
	DefaultBootWait      = 1200 * time.Millisecond
	DefaultTestTimeout   = 10 * time.Second
	DefaultXrayRunBudget = 18 * time.Second
)

var (
	httpFetchTimeout = 15 * time.Second
	maxRemoteSize    = int64(5 * 1024 * 1024)
	testURL          = "http://example.com/"
)

type AppConfig struct {
	APIKey string `json:"api_key"`
	Bind   string `json:"bind"`
	Title  string `json:"title,omitempty"`
}
