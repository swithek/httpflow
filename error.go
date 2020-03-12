package httpflow

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/swithek/sessionup"
)

var (
	// ErrNotFound is returned when target resources is not found.
	ErrNotFound = NewError(nil, http.StatusNotFound,
		strings.ToLower(http.StatusText(http.StatusNotFound)))

	// ErrUnauthorized is returned when authorization process fails.
	ErrUnauthorized = NewError(nil, http.StatusUnauthorized,
		strings.ToLower(http.StatusText(http.StatusUnauthorized)))
)

// statusError is a custom error type used to carry both error
// message and status code.
type statusError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	err     error
}

// NewError creates a new status error by optionally wrapping another error.
func NewError(err error, code int, msg string, args ...interface{}) error {
	return &statusError{
		Code:    code,
		Message: fmt.Sprintf(msg, args...),
		err:     err,
	}
}

// Error converts the error to string.
func (e *statusError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%d - %s: %v", e.Code, e.Message, e.err)
	}
	return fmt.Sprintf("%d - %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error, if it exists.
func (e *statusError) Unwrap() error {
	return e.err
}

// DetectError wraps the provided error with additional information
// useful for applications.
func DetectError(err error) error {
	if _, ok := err.(*statusError); ok {
		return err
	}

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case errors.Is(err, http.ErrNoCookie):
		return NewError(err, http.StatusBadRequest,
			"session cookie is invalid")
	case errors.Is(err, sessionup.ErrUnauthorized):
		return NewError(err, http.StatusUnauthorized,
			strings.ToLower(http.StatusText(http.StatusUnauthorized)))
	}

	return NewError(err, http.StatusInternalServerError,
		strings.ToLower(http.StatusText(http.StatusInternalServerError)))
}

// ErrorCode returns status code associated with the error.
func ErrorCode(err error) int {
	var serr *statusError
	if !errors.As(err, &serr) {
		return http.StatusInternalServerError
	}
	return serr.Code
}

// ErrorMessage returns message assocaited with the error.
func ErrorMessage(err error) string {
	var serr *statusError
	if !errors.As(err, &serr) {
		return strings.ToLower(http.StatusText(
			http.StatusInternalServerError))
	}
	return serr.Message
}
