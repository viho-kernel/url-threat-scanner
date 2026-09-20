package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type staticAnalysis struct {
	Verdict   string   `json:"verdict"`
	RiskScore int      `json:"risk_score"`
	Flags     []string `json:"flags"`
}

type scannerClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func newScannerClient() (*scannerClient, error) {
	baseURL := strings.TrimRight(os.Getenv("SCANNER_URL"), "/")
	token := os.Getenv("SCANNER_SERVICE_TOKEN")

	if baseURL == "" {
		return nil, errors.New("SCANNER_URL is required")
	}

	if token == "" {
		return nil, errors.New("SCANNER_SERVICE_TOKEN is required")
	}

	return &scannerClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}, nil
}

func (client *scannerClient) analyze(
	ctx context.Context,
	rawURL string,
) (*staticAnalysis, error) {
	requestBody, err := json.Marshal(map[string]string{
		"url": rawURL,
	})
	if err != nil {
		return nil, fmt.Errorf("encode scanner request: %w", err)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		client.baseURL+"/analyze",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return nil, fmt.Errorf("create scanner request: %w", err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Service-Token", client.token)

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call scanner: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))

		return nil, fmt.Errorf(
			"scanner returned status %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var analysis staticAnalysis

	decoder := json.NewDecoder(
		io.LimitReader(response.Body, 16*1024),
	)

	if err := decoder.Decode(&analysis); err != nil {
		return nil, fmt.Errorf("decode scanner response: %w", err)
	}

	return &analysis, nil
}
