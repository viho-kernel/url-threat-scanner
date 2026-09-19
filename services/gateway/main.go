package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type scanRequest struct {
	URL string `json:"url"`
}

type scanResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	URL    string `json:"url"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf(`{"event":"response_encode_failed","error":%q}`, err.Error())
	}
}

func newScanID() (string, error) {
	randomBytes := make([]byte, 16)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(randomBytes), nil
}

func validateURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, errors.New("url is required")
	}

	if len(rawURL) > 2048 {
		return nil, errors.New("url is too long")
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("invalid URL")
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, errors.New("only http and https URLs are allowed")
	}

	if parsedURL.Hostname() == "" {
		return nil, errors.New("URL hostname is required")
	}

	if parsedURL.User != nil {
		return nil, errors.New("credentials in URLs are not allowed")
	}

	if parsedURL.Fragment != "" {
		return nil, errors.New("URL fragments are not allowed")
	}

	port := parsedURL.Port()
	if port != "" && port != "80" && port != "443" {
		return nil, errors.New("only ports 80 and 443 are allowed")
	}

	hostname := strings.ToLower(strings.TrimSuffix(parsedURL.Hostname(), "."))

	if hostname == "localhost" ||
		strings.HasSuffix(hostname, ".localhost") ||
		strings.HasSuffix(hostname, ".local") ||
		strings.HasSuffix(hostname, ".internal") {
		return nil, errors.New("local hostnames are not allowed")
	}

	if ip := net.ParseIP(hostname); ip != nil {
		if ip.IsLoopback() ||
			ip.IsPrivate() ||
			ip.IsUnspecified() ||
			ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() ||
			ip.IsMulticast() {
			return nil, errors.New("private or special-purpose IP addresses are not allowed")
		}
	}

	return parsedURL, nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "gateway",
		"status":  "ok",
	})
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, errorResponse{
			Error: "Content-Type must be application/json",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var request scanRequest

	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error: "invalid JSON request",
		})
		return
	}

	var extra any
	if err := decoder.Decode(&extra); err == nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Error: "request must contain one JSON object",
		})
		return
	}

	validatedURL, err := validateURL(request.URL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	scanID, err := newScanID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: "could not create scan",
		})
		return
	}

	log.Printf(
		`{"event":"scan_accepted","scan_id":%q,"host":%q}`,
		scanID,
		validatedURL.Hostname(),
	)

	writeJSON(w, http.StatusAccepted, scanResponse{
		ID:     scanID,
		Status: "accepted",
		URL:    validatedURL.String(),
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("POST /scans", scanHandler)

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Print(`{"event":"gateway_started","port":8080}`)
	log.Fatal(server.ListenAndServe())
}