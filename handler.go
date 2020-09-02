// Package httpflow provides helper functions and types to simplify work
// with HTTP requests.
package httpflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi"
	"github.com/gorilla/schema"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/swithek/httpflow/logutil"
	"github.com/swithek/sessionup"
)

var (
	// ErrInvalidJSON is returned when request's body contains invalid
	// JSON data.
	ErrInvalidJSON = NewError(nil, http.StatusBadRequest, "invalid JSON body")

	// ErrInvalidForm is returned when request's form contains invalid
	// JSON data.
	ErrInvalidForm = NewError(nil, http.StatusBadRequest, "invalid form data")
)

var _formDec = schema.NewDecoder()

// Respond sends JSON type response to the client.
func Respond(log zerolog.Logger, w http.ResponseWriter, r *http.Request, data interface{}, code int) {
	if data == nil {
		w.WriteHeader(code)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		logutil.Critical(log, err).Msg("cannot send a response")

		err = NewError(nil, http.StatusInternalServerError, "")
		json.NewEncoder(w).Encode(err) //nolint:errcheck,gosec // error provides no meaningful info
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// RespondError sends the provided error in a JSON format to the client.
func RespondError(log zerolog.Logger, w http.ResponseWriter, r *http.Request, err error) {
	err = DetectError(err)
	code := ErrorCode(err)

	Respond(log, w, r, err, code)

	if code >= 500 {
		logutil.Critical(log, err).Msg("internal server error")
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
		// unlikely to happen
		return ErrInvalidForm
	}

	if err := _formDec.Decode(v, r.Form); err != nil {
		return ErrInvalidForm
	}

	return nil
}

// SessionReject should be used as sessionup's rejection function.
func SessionReject(log zerolog.Logger) func(error) http.Handler {
	return func(err error) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			RespondError(log, w, r, err)
		})
	}
}

// NotFound handles cases when request is sent to a non-existing endpoint.
func NotFound(log zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		RespondError(log, w, r, ErrNotFound)
	}
}

// MethodNotAllowed handles cases when request's method is not supported for
// the requested endpoint.
func MethodNotAllowed(log zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		RespondError(log, w, r, ErrMethodNotAllowed)
	}
}

// ExtractTargetID extracts ID from the URL.
func ExtractTargetID(r *http.Request) (xid.ID, error) {
	strID, err := ExtractParam(r, "id")
	if err != nil {
		return xid.ID{}, NewError(nil, http.StatusBadRequest, "invalid id")
	}

	id, err := xid.FromString(strID)
	if err != nil {
		return xid.ID{}, NewError(nil, http.StatusBadRequest, "invalid id")
	}

	return id, nil
}

// ExtractParam extracts a value by the the provided parameter name from
// the URL.
func ExtractParam(r *http.Request, p string) (string, error) {
	id := chi.URLParam(r, p)
	if id == "" {
		return "", NewError(nil, http.StatusBadRequest, fmt.Sprintf("invalid %s parameter", p))
	}

	return id, nil
}

// ExtractIP extracts request origin's IP address.
func ExtractIP(r *http.Request) (net.IP, error) {
	ip := r.Header.Get("X-Real-IP")

	if ip == "" {
		ips := strings.Split(r.Header.Get("X-Forwarded-For"), ", ")
		ip = ips[len(ips)-1]
	}

	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}

	if ip == "" {
		return nil, NewError(nil, http.StatusBadRequest, "invalid ip address")
	}

	return net.ParseIP(ip), nil
}

// ExtractSession checks whether the session is present and returns it as
// well as user's ID.
func ExtractSession(ctx context.Context) (sessionup.Session, xid.ID, error) {
	ses, ok := sessionup.FromContext(ctx)
	if !ok {
		return sessionup.Session{}, xid.ID{}, ErrUnauthorized
	}

	id, err := xid.FromString(ses.UserKey)
	if err != nil {
		return sessionup.Session{}, xid.ID{}, ErrUnauthorized
	}

	return ses, id, nil
}

var _locRe = regexp.MustCompile(`{loc}`)

// Location is a middleware that adds or expands location header.
// It will only execute after the next http handler completes.
// If the location header is already present, it is not possible
// to overwrite it, but you may use {loc} in the provided location
// string to embed the previous value into the new one:
//    // Existing Location header: userID123
//    Location("/users/{loc}") // header will be set to "/users/userID123"
func Location(loc string) func(http.Handler) http.Handler {
	plain := !_locRe.MatchString(loc)

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)

			if loc == "" {
				return
			}

			loc1 := w.Header().Get("Location")

			if loc1 != "" && !plain {
				loc1 = _locRe.ReplaceAllString(loc, loc1)
			} else if loc1 == "" && plain {
				loc1 = loc
			}

			if loc1 != "" {
				w.Header().Set("Location", loc1)
			}
		}

		return http.HandlerFunc(fn)
	}
}
