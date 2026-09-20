package main

import (
	"context"
	"crypto/rand"
	"database/sql"
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

type application struct {
	database *sql.DB
	queue    *jobQueue
	scanner  *scannerClient
}

type scanResponse struct {
	ID             string          `json:"id"`
	Status         string          `json:"status"`
	URL            string          `json:"url"`
	StaticAnalysis *staticAnalysis `json:"static_analysis"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type scanRequest struct {
	URL string `json:"url"`
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

func (app *application) scanHandler(w http.ResponseWriter, r *http.Request) {
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

	analysis, err := app.scanner.analyze(
		r.Context(),
		validatedURL.String(),
	)
	if err != nil {
		log.Printf(
			`{"event":"scanner_request_failed","error":%q}`,
			err.Error(),
		)

		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error: "scanner service unavailable",
		})
		return
	}

	scanID, err := newScanID()

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: "could not create scan",
		})
		return
	}

	if err := app.saveScan(
		r.Context(),
		scanID,
		validatedURL.String(),
	); err != nil {
		log.Printf(
			`{"event":"scan_persistence_failed","scan_id":%q,"error":%q}`,
			scanID,
			err.Error(),
		)

		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: "could not save scan",
		})
		return
	}

	if err := app.queue.enqueue(r.Context(), scanID); err != nil {
		log.Printf(
			`{"event":"scan_enqueue_failed","scan_id":%q,"error":%q}`,
			scanID,
			err.Error(),
		)

		if updateErr := app.markScanQueueFailed(
			r.Context(),
			scanID,
		); updateErr != nil {
			log.Printf(
				`{"event":"queue_failure_status_update_failed","scan_id":%q,"error":%q}`,
				scanID,
				updateErr.Error(),
			)
		}

		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error: "scan queue unavailable",
		})
		return
	}

	log.Printf(
		`{"event":"scan_accepted","scan_id":%q,"host":%q}`,
		scanID,
		validatedURL.Hostname(),
	)

	writeJSON(w, http.StatusAccepted, scanResponse{
		ID:             scanID,
		Status:         "queued",
		URL:            validatedURL.String(),
		StaticAnalysis: analysis,
	})
}

func (app *application) readinessHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := app.database.PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status":   "not_ready",
			"database": "unavailable",
			"redis":    "unknown",
		})
		return
	}

	if err := app.queue.ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status":   "not_ready",
			"database": "connected",
			"redis":    "unavailable",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "ready",
		"database": "connected",
		"redis":    "connected",
	})
}

func main() {
	database, err := openDatabase()
	if err != nil {
		log.Fatalf(`{"event":"database_connection_failed","error":%q}`, err.Error())
	}
	defer database.Close()
	queue, err := openQueue()
	if err != nil {
		log.Fatalf(
			`{"event":"redis_connection_failed","error":%q}`,
			err.Error(),
		)
	}
	defer queue.close()

	scanner, err := newScannerClient()
	if err != nil {
		log.Fatalf(
			`{"event":"scanner_configuration_failed","error":%q}`,
			err.Error(),
		)
	}

	app := &application{
		database: database,
		queue:    queue,
		scanner:  scanner,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", app.readinessHandler)
	mux.HandleFunc("POST /scans", app.scanHandler)
	mux.HandleFunc("GET /scans/{id}", app.getScanHandler)
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
