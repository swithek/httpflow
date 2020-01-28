package httpuser

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type statusError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	err     error
}

func NewError(err error, code int, msg string, args ...interface{}) error {
	return &statusError{
		Code:    code,
		Message: fmt.Sprintf(msg, args...),
		err:     err,
	}
}

func (e *statusError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%d - %s: %v", e.Code, e.Message, e.err)
	}
	return fmt.Sprintf("%d - %s", e.Code, e.Message)
}

func (e *statusError) Unwrap() error {
	return e.err
}

func ErrorCode(err error) int {
	var serr *statusError
	if !errors.As(err, &serr) {
		return http.StatusInternalServerError
	}
	return serr.Code
}

func ErrorMessage(err error) string {
	var serr *statusError
	if !errors.As(err, &serr) {
		return strings.ToLower(http.StatusText(
			http.StatusInternalServerError))
	}
	return serr.Message
}
