package httpflow

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swithek/sessionup"
)

func Test_NewError(t *testing.T) {
	err := NewError(assert.AnError, http.StatusBadRequest, "")
	require.IsType(t, &statusError{}, err)
	sErr := err.(*statusError)
	assert.Equal(t, sErr.err, assert.AnError)
	assert.Equal(t, sErr.code, http.StatusBadRequest)
	assert.Equal(t, sErr.Message, "bad request")

	err = NewError(assert.AnError, http.StatusBadRequest, "bad request %s", "123")
	require.IsType(t, &statusError{}, err)
	sErr = err.(*statusError)
	assert.Equal(t, sErr.err, assert.AnError)
	assert.Equal(t, sErr.code, http.StatusBadRequest)
	assert.Equal(t, sErr.Message, "bad request 123")
}

func Test_statusError_Error(t *testing.T) {
	sErr := statusError{
		code:    400,
		Message: "bad request",
	}

	assert.Equal(t, "[400] bad request", sErr.Error())

	sErr.err = errors.New("invalid JSON body")

	assert.Equal(t, "[400] bad request: invalid JSON body", sErr.Error())
}

func Test_statusError_Unwrap(t *testing.T) {
	sErr := statusError{err: assert.AnError}
	assert.Equal(t, assert.AnError, sErr.Unwrap())
}

func Test_DetectError(t *testing.T) {
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
		"No rows found error": {
			Err:     sql.ErrNoRows,
			Message: strings.ToLower(http.StatusText(http.StatusNotFound)),
			Code:    http.StatusNotFound,
		},
		"No cookie error": {
			Err:     http.ErrNoCookie,
			Message: "session cookie is invalid",
			Code:    http.StatusBadRequest,
		},
		"Unauthorized error": {
			Err:     sessionup.ErrUnauthorized,
			Message: strings.ToLower(http.StatusText(http.StatusUnauthorized)),
			Code:    http.StatusUnauthorized,
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
			assert.Equal(t, c.Code, sErr.code)
		})
	}
}

func Test_ErrorCode(t *testing.T) {
	assert.Equal(t, http.StatusInternalServerError, ErrorCode(errors.New("error")))
	assert.Equal(t, 400, ErrorCode(NewError(nil, 400, "error")))
}

func Test_ErrorMessage(t *testing.T) {
	assert.Equal(t, strings.ToLower(http.StatusText(
		http.StatusInternalServerError)), ErrorMessage(errors.New("error")))
	assert.Equal(t, "error", ErrorMessage(NewError(nil, 400, "error")))
}
