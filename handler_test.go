package httpflow

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultErrorExec(t *testing.T) {
	DefaultErrorExec(errors.New("error")) // nothing to test
}

func TestRespond(t *testing.T) {
	cc := map[string]struct {
		Code int
		Data interface{}
		Body bool
	}{
		"Successful response with body": {
			Code: 400,
			Data: &statusError{Message: "error"},
			Body: true,
		},
		"Successful response without body": {
			Code: 200,
			Body: false,
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/", nil)
			rec := httptest.NewRecorder()

			Respond(rec, req, c.Data, c.Code, DefaultErrorExec)

			assert.Equal(t, c.Code, rec.Code)
			if c.Body {
				assert.Equal(t, "application/json",
					rec.Header().Get("Content-Type"))
				assert.NotZero(t, rec.Body.String())
				return
			}

			assert.Zero(t, rec.Header().Get("Content-Type"))
			assert.Zero(t, rec.Body.String())
		})
	}
}

func TestRespondError(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	rec := httptest.NewRecorder()

	RespondError(rec, req, errors.New("error"), DefaultErrorExec)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json",
		rec.Header().Get("Content-Type"))
	assert.NotZero(t, rec.Body.String())
}

func TestDecodeJSON(t *testing.T) {
	sErr := statusError{}
	req := httptest.NewRequest("GET", "http://test.com/",
		strings.NewReader("{"))
	err := DecodeJSON(req, &sErr)
	assert.Equal(t, ErrInvalidJSON, err)
	assert.Zero(t, sErr)

	req = httptest.NewRequest("GET", "http://test.com/",
		strings.NewReader("{\"message\":\"error\"}"))
	err = DecodeJSON(req, &sErr)
	assert.Nil(t, err)
	assert.Equal(t, "error", sErr.Message)
}
