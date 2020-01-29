package httpflow

import (
	"encoding/json"
	"net/http"
)

// Respond sends JSON type response to the client.
func Respond(w http.ResponseWriter, r *http.Request, data interface{},
	code int, fatal func(error)) {
	w.WriteHeader(code)
	if data == nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.Header().Del("Content-Type")
		w.WriteHeader(http.StatusInternalServerError)
		fatal(err)
	}
}

// RespondError sends the provided error in a JSON format to the client.
func RespondError(w http.ResponseWriter, r *http.Request, err error,
	fatal func(error)) {
	err = DetectError(err)
	code := ErrorCode(err)
	Respond(w, r, err, code, fatal)
	if code >= 500 {
		fatal(err)
	}
}
