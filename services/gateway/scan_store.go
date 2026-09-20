package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type storedScanResponse struct {
	ID             string          `json:"id"`
	URL            string          `json:"url"`
	Status         string          `json:"status"`
	StaticAnalysis json.RawMessage `json:"static_analysis,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	ErrorMessage   *string         `json:"error_message,omitempty"`
	WorkerAttempts int             `json:"worker_attempts"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func (app *application) saveScan(
	ctx context.Context,
	id string,
	scanURL string,
	userID string,
	analysis *staticAnalysis,
) error {
	analysisJSON, err := json.Marshal(analysis)
	if err != nil {
		return err
	}

	_, err = app.database.ExecContext(
		ctx,
		`INSERT INTO scans (
		     id,
		     url,
		     status,
		     user_id,
		     static_analysis
		 )
		 VALUES ($1, $2, $3, $4, $5::jsonb)`,
		id,
		scanURL,
		"queued",
		userID,
		string(analysisJSON),
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
	user, authenticated := app.authenticateRequest(w, r)
	if !authenticated {
		return
	}

	id := r.PathValue("id")
	if !validScanID(id) {
		writeJSON(w, http.StatusNotFound, errorResponse{
			Error: "scan not found",
		})
		return
	}

	var scan storedScanResponse
	var staticAnalysisJSON []byte
	var resultJSON []byte
	var errorMessage sql.NullString
	var startedAt sql.NullTime
	var completedAt sql.NullTime

	err := app.database.QueryRowContext(
		r.Context(),
		`SELECT
		     id,
		     url,
		     status,
			 static_analysis,
		     result,
		     error_message,
		     worker_attempts,
		     started_at,
		     completed_at,
		     created_at,
		     updated_at
		 FROM scans
		 WHERE id = $1
		   AND user_id = $2`,
		id,
		user.UserID,
	).Scan(
		&scan.ID,
		&scan.URL,
		&scan.Status,
		&staticAnalysisJSON,
		&resultJSON,
		&errorMessage,
		&scan.WorkerAttempts,
		&startedAt,
		&completedAt,
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

	if staticAnalysisJSON != nil {

		scan.StaticAnalysis = json.RawMessage(staticAnalysisJSON)

	}

	if resultJSON != nil {
		scan.Result = json.RawMessage(resultJSON)
	}

	if errorMessage.Valid {
		scan.ErrorMessage = &errorMessage.String
	}

	if startedAt.Valid {
		scan.StartedAt = &startedAt.Time
	}

	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}

	writeJSON(w, http.StatusOK, scan)
}

func (app *application) markScanQueueFailed(
	ctx context.Context,
	id string,
) error {
	_, err := app.database.ExecContext(
		ctx,
		`UPDATE scans
		 SET status = $1,
		     updated_at = NOW()
		 WHERE id = $2`,
		"queue_failed",
		id,
	)

	return err
}
