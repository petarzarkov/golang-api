package httpHelpers

import (
	"encoding/json"
	"log"
	"net/http"
)

type ErrorResponseBody struct {
	Status string    `json:"status"`
	Error  string `json:"error"`
}

func WriteJSONError(w http.ResponseWriter,  message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Prevent browser from trying to guess the content type
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)

	responseBody := ErrorResponseBody{
		Status: http.StatusText(statusCode),
		Error:  message,
	}

	if err := json.NewEncoder(w).Encode(responseBody); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
		http.Error(w, `{"error":"Failed to encode error response"}`, http.StatusInternalServerError)
	}
}