package httpflow

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultErrorExec(t *testing.T) {
	DefaultErrorExec(assert.AnError) // nothing to test
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

	RespondError(rec, req, assert.AnError, func(error) {})

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json",
		rec.Header().Get("Content-Type"))
	assert.NotZero(t, rec.Body.String())
}

func TestDecodeJSON(t *testing.T) {
	v := struct {
		Msg string `json:"msg"`
	}{}
	req := httptest.NewRequest("GET", "http://test.com/",
		strings.NewReader("{"))
	err := DecodeJSON(req, &v)
	assert.Equal(t, ErrInvalidJSON, err)
	assert.Zero(t, v)

	req = httptest.NewRequest("GET", "http://test.com/",
		strings.NewReader("{\"msg\":\"test\"}"))
	err = DecodeJSON(req, &v)
	assert.Nil(t, err)
	assert.Equal(t, "test", v.Msg)
}

func TestDecodeForm(t *testing.T) {
	v := struct{ Msg string }{}
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	assert.Equal(t, ErrInvalidForm, DecodeForm(req, v))

	req = httptest.NewRequest("GET", "http://test.com/", nil)
	q := req.URL.Query()
	q.Add("msg", "test")
	req.URL.RawQuery = q.Encode()
	assert.Nil(t, DecodeForm(req, &v))
	assert.Equal(t, "test", v.Msg)
}

func TestSessionReject(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	rec := httptest.NewRecorder()
	SessionReject(assert.AnError, func(error) {}).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json",
		rec.Header().Get("Content-Type"))
	assert.NotZero(t, rec.Body.String())
}
