package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

func GetProjectRootPath() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	startingPath := ""
	iterations := 0
	for {
		if iterations > 10 {
			panic("Could not find project root path")
		}
		iterations++
		p, err := filepath.Abs(fmt.Sprintf("%s/%s", wd, startingPath))
		if err != nil {
			panic(err)
		}

		match := regexp.MustCompile(`\/eigenx-kms-go([A-Za-z0-9_-]+)?\/?$`)
		if match.MatchString(p) {
			fmt.Printf("Found project root path: %s\n", p)
			return p
		}
		startingPath = startingPath + "/.."
	}
}

type ChainConfig struct {
	AVSAccountAddress          string `json:"avsAccountAddress"`
	AVSAccountPrivateKey       string `json:"avsAccountPk"`
	AVSAccountPublicKey        string `json:"avsAccountPublicKey"`
	OperatorAccountAddress1    string `json:"operatorAccountAddress_1"`
	OperatorAccountPrivateKey1 string `json:"operatorAccountPk_1"`
	OperatorAccountAddress2    string `json:"operatorAccountAddress_2"`
	OperatorAccountPrivateKey2 string `json:"operatorAccountPk_2"`
	OperatorAccountAddress3    string `json:"operatorAccountAddress_3"`
	OperatorAccountPrivateKey3 string `json:"operatorAccountPk_3"`
	OperatorAccountAddress4    string `json:"operatorAccountAddress_4"`
	OperatorAccountPrivateKey4 string `json:"operatorAccountPk_4"`
	OperatorAccountAddress5    string `json:"operatorAccountAddress_5"`
	OperatorAccountPrivateKey5 string `json:"operatorAccountPk_5"`
	ForkL1Block                string `json:"forkL1Block"`
}

func ReadChainConfig(projectRoot string) (*ChainConfig, error) {
	filePath := fmt.Sprintf("%s/internal/testData/chain-config.json", projectRoot)

	// read the file into bytes
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var cf *ChainConfig
	if err := json.Unmarshal(file, &cf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal file: %w", err)
	}
	return cf, nil
}
