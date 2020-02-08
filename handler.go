package httpflow

import (
	"encoding/json"
	"log"
	"net/http"
)

var (
	// ErrInvalidJSON is returned when request body contains invalid JSON
	// data.
	ErrInvalidJSON = NewError(nil, http.StatusBadRequest,
		"invalid JSON body")
)

// ErrorExec is a function that should be used for calling on
// errors. Useful for error logging etc.
type ErrorExec func(error)

// DefaultErrorExec logs the provided error via global logger.
func DefaultErrorExec(err error) {
	log.Print(err)
}

// Respond sends JSON type response to the client.
func Respond(w http.ResponseWriter, r *http.Request, data interface{},
	code int, onError ErrorExec) {
	w.WriteHeader(code)
	if data == nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.Header().Del("Content-Type")
		w.WriteHeader(http.StatusInternalServerError)
		onError(err)
	}
}

// RespondError sends the provided error in a JSON format to the client.
func RespondError(w http.ResponseWriter, r *http.Request, err error,
	onError ErrorExec) {
	err = DetectError(err)
	code := ErrorCode(err)
	Respond(w, r, err, code, onError)
	if code >= 500 {
		onError(err)
	}
}

// DecodeJSON tries to decode request's JSON body into destination object.
func DecodeJSON(r *http.Request, v interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return ErrInvalidJSON
	}

	return nil
}
