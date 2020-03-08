package httpflow

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/schema"
)

var (
	// ErrInvalidJSON is returned when request's body contains invalid JSON
	// data.
	ErrInvalidJSON = NewError(nil, http.StatusBadRequest,
		"invalid JSON body")

	// ErrInvalidForm is returned when request's form contains invalid JSON
	// data.
	ErrInvalidForm = NewError(nil, http.StatusBadRequest, "invalid form data")
)

var (
	formDec = schema.NewDecoder()
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

// DecodeJSON decodes request's JSON body into destination object.
func DecodeJSON(r *http.Request, v interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return ErrInvalidJSON
	}

	return nil
}

// DecodeForm decodes request's form values into destination object.
func DecodeForm(r *http.Request, v interface{}) error {
	if err := r.ParseForm(); err != nil {
		return ErrInvalidForm
	}

	if err := formDec.Decode(v, r.Form); err != nil {
		return ErrInvalidForm
	}

	return nil
}

//SessionReject should be used as sessionup's manager's invalid request
// rejection function.
func SessionReject(err error, onError ErrorExec) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		RespondError(w, r, err, onError)
	})
}
