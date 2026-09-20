package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

type storedScanResponse struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (app *application) saveScan(
	ctx context.Context,
	id string,
	scanURL string,
) error {
	_, err := app.database.ExecContext(
		ctx,
		`INSERT INTO scans (id, url, status)
		 VALUES ($1, $2, $3)`,
		id,
		scanURL,
		"accepted",
	)

	return err
}

func validScanID(id string) bool {
	if len(id) != 32 {
		return false
	}

	_, err := hex.DecodeString(id)
	return err == nil
}

func (app *application) getScanHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	id := r.PathValue("id")
	if !validScanID(id) {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error: "scan not found",
		})
		return
	}

	var scan storedScanResponse

	err := app.database.QueryRowContext(
		r.Context(),
		`SELECT id, url, status, created_at, updated_at
		 FROM scans
		 WHERE id = $1`,
		id,
	).Scan(
		&scan.ID,
		&scan.URL,
		&scan.Status,
		&scan.CreatedAt,
		&scan.UpdatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error: "scan not found",
		})
		return
	}

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: "could not retrieve scan",
		})
		return
	}

	writeJSON(w, http.StatusOK, scan)
}
