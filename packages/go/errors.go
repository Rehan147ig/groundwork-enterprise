// Package sdk is the zero-dependency Go client for the Groundwork query
// runtime API. It mirrors the TypeScript SDK (@groundwork/sdk) surface:
// the same endpoints, envelopes, and error semantics (GroundworkError
// with Status/Code/Detail), plus an HS256 mintUserAssertion helper.
package sdk

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// GroundworkError is raised for every non-2xx response and transport
// failure. Status is the HTTP status (0 for transport-level failures);
// Code is the server's stable error code ({"error": "<code>"}) or one of
// "network"/"timeout" for transport failures.
type GroundworkError struct {
	Status   int
	Code     string
	Detail   string
	Headers  http.Header
	Response []byte
}

func (e *GroundworkError) Error() string {
	statusText := e.Code
	msg := fmt.Sprintf("Groundwork API error %d", e.Status)
	if statusText != "" {
		msg += ": " + statusText
	}
	return msg
}

// parseErrorResponse builds a GroundworkError from a non-2xx response.
func parseErrorResponse(resp *http.Response, body []byte) *GroundworkError {
	err := &GroundworkError{Status: resp.StatusCode, Code: "", Headers: resp.Header, Response: body}
	var envelope struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if len(body) > 0 {
		if jerr := json.Unmarshal(body, &envelope); jerr == nil {
			err.Code = envelope.Error
			err.Detail = envelope.Detail
		}
	}
	return err
}
