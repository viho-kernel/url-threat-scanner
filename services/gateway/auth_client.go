package main

import (
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

var errUnauthenticated = errors.New("request is not authenticated")

type authenticatedUser struct {
	UserID string `json:"user_id"`
	Active bool   `json:"active"`
}

type authClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func newAuthClient() (*authClient, error) {
	baseURL := strings.TrimRight(os.Getenv("AUTH_URL"), "/")
	token := os.Getenv("AUTH_SERVICE_TOKEN")

	if baseURL == "" {
		return nil, errors.New("AUTH_URL is required")
	}

	if token == "" {
		return nil, errors.New("AUTH_SERVICE_TOKEN is required")
	}

	return &authClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
	}, nil
}

func (client *authClient) verify(
	ctx context.Context,
	authorization string,
	apiKey string,
) (*authenticatedUser, error) {
	hasAuthorization := authorization != ""
	hasAPIKey := apiKey != ""

	if hasAuthorization == hasAPIKey {
		return nil, errUnauthenticated
	}

	if len(authorization) > 4096 || len(apiKey) > 256 {
		return nil, errUnauthenticated
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		client.baseURL+"/verify",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create auth request: %w", err)
	}

	request.Header.Set("X-Service-Token", client.token)

	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	if apiKey != "" {
		request.Header.Set("X-API-Key", apiKey)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call auth service: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized {
		return nil, errUnauthenticated
	}

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(
			io.LimitReader(response.Body, 1024),
		)

		return nil, fmt.Errorf(
			"auth returned status %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var user authenticatedUser

	decoder := json.NewDecoder(
		io.LimitReader(response.Body, 16*1024),
	)

	if err := decoder.Decode(&user); err != nil {
		return nil, fmt.Errorf(
			"decode auth response: %w",
			err,
		)
	}

	if !user.Active || user.UserID == "" {
		return nil, errUnauthenticated
	}

	return &user, nil
}

func (app *application) authenticateRequest(
	w http.ResponseWriter,
	r *http.Request,
) (*authenticatedUser, bool) {
	user, err := app.auth.verify(
		r.Context(),
		r.Header.Get("Authorization"),
		r.Header.Get("X-API-Key"),
	)

	if errors.Is(err, errUnauthenticated) {
		w.Header().Set("WWW-Authenticate", "Bearer")

		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Error: "authentication required",
		})

		return nil, false
	}

	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Error: "authentication service unavailable",
		})

		return nil, false
	}

	return user, true
}

func (app *application) authProxyHandler(
	path string,
) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		contentType := strings.ToLower(
			r.Header.Get("Content-Type"),
		)

		if !strings.HasPrefix(
			contentType,
			"application/json",
		) {
			writeJSON(
				w,
				http.StatusUnsupportedMediaType,
				errorResponse{
					Error: "Content-Type must be application/json",
				},
			)
			return
		}

		r.Body = http.MaxBytesReader(
			w,
			r.Body,
			4096,
		)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{
				Error: "invalid request body",
			})
			return
		}

		request, err := http.NewRequestWithContext(
			r.Context(),
			http.MethodPost,
			app.auth.baseURL+path,
			strings.NewReader(string(body)),
		)
		if err != nil {
			writeJSON(
				w,
				http.StatusInternalServerError,
				errorResponse{
					Error: "could not create authentication request",
				},
			)
			return
		}

		request.Header.Set(
			"Content-Type",
			"application/json",
		)

		request.Header.Set(
			"X-Service-Token",
			app.auth.token,
		)

		authorization := r.Header.Get("Authorization")
		if authorization != "" {
			request.Header.Set(
				"Authorization",
				authorization,
			)
		}

		response, err := app.auth.httpClient.Do(request)
		if err != nil {
			writeJSON(
				w,
				http.StatusServiceUnavailable,
				errorResponse{
					Error: "authentication service unavailable",
				},
			)
			return
		}
		defer response.Body.Close()

		responseBody, err := io.ReadAll(
			io.LimitReader(
				response.Body,
				32*1024,
			),
		)
		if err != nil {
			writeJSON(
				w,
				http.StatusBadGateway,
				errorResponse{
					Error: "invalid authentication response",
				},
			)
			return
		}

		var responseJSON any

		if err := json.Unmarshal(
			responseBody,
			&responseJSON,
		); err != nil {
			writeJSON(
				w,
				http.StatusBadGateway,
				errorResponse{
					Error: "invalid authentication response",
				},
			)
			return
		}

		writeJSON(
			w,
			response.StatusCode,
			responseJSON,
		)
	}
}
