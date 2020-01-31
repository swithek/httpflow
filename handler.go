package httpflow

import (
	"encoding/json"
	"net/http"
)

// ErrorExec is a function that should be delegated for calling on
// errors.
type ErrorExec func(error)

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
