package httpflow

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewError(t *testing.T) {
	err := NewError(assert.AnError, 400, "bad request %s", "123")

	require.IsType(t, &statusError{}, err)
	sErr := err.(*statusError)

	assert.Equal(t, sErr.err, assert.AnError)
	assert.Equal(t, sErr.Code, 400)
	assert.Equal(t, sErr.Message, "bad request 123")
}

func TestStatusErrorError(t *testing.T) {
	sErr := statusError{
		Code:    400,
		Message: "bad request",
	}

	assert.Equal(t, "400 - bad request", sErr.Error())

	sErr.err = errors.New("invalid JSON body")

	assert.Equal(t, "400 - bad request: invalid JSON body", sErr.Error())
}

func TestStatusErrorUnwrap(t *testing.T) {
	sErr := statusError{err: assert.AnError}
	assert.Equal(t, assert.AnError, sErr.Unwrap())
}

func TestDetectError(t *testing.T) {
	cc := map[string]struct {
		Err     error
		Message string
		Code    int
	}{
		"Status error pass through": {
			Err:     NewError(errors.New("error"), 400, "error"),
			Message: "error",
			Code:    400,
		},
		"SQL rows not found": {
			Err: sql.ErrNoRows,
			Message: strings.ToLower(
				http.StatusText(http.StatusNotFound)),
			Code: http.StatusNotFound,
		},
		"Undefined error": {
			Err: errors.New("error"),
			Message: strings.ToLower(
				http.StatusText(http.StatusInternalServerError)),
			Code: http.StatusInternalServerError,
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			err := DetectError(c.Err)
			require.IsType(t, &statusError{}, err)
			sErr := err.(*statusError)
			assert.Equal(t, c.Message, sErr.Message)
			assert.Equal(t, c.Code, sErr.Code)
			assert.NotNil(t, sErr.err)
		})
	}
}

func TestErrorCode(t *testing.T) {
	assert.Equal(t, http.StatusInternalServerError, ErrorCode(
		errors.New("error")))
	assert.Equal(t, 400, ErrorCode(NewError(nil, 400, "error")))
}

func TestErrorMessage(t *testing.T) {
	assert.Equal(t, strings.ToLower(http.StatusText(
		http.StatusInternalServerError)), ErrorMessage(errors.New("error")))
	assert.Equal(t, "error", ErrorMessage(NewError(nil, 400, "error")))
}
