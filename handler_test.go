package httpflow

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/swithek/sessionup"
)

func Test_DefaultErrorExec(t *testing.T) {
	DefaultErrorExec(assert.AnError) // nothing to test
}

func Test_Respond(t *testing.T) {
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

func Test_RespondError(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	rec := httptest.NewRecorder()

	RespondError(rec, req, assert.AnError, func(error) {})

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json",
		rec.Header().Get("Content-Type"))
	assert.NotZero(t, rec.Body.String())
}

func Test_DecodeJSON(t *testing.T) {
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
	assert.NoError(t, err)
	assert.Equal(t, "test", v.Msg)
}

func Test_DecodeForm(t *testing.T) {
	v := struct{ Msg string }{}
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	assert.Equal(t, ErrInvalidForm, DecodeForm(req, v))

	req = httptest.NewRequest("GET", "http://test.com/", nil)
	q := req.URL.Query()
	q.Add("msg", "test")
	req.URL.RawQuery = q.Encode()
	assert.NoError(t, DecodeForm(req, &v))
	assert.Equal(t, "test", v.Msg)
}

func Test_SessionReject(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	rec := httptest.NewRecorder()
	SessionReject(func(error) {})(assert.AnError).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json",
		rec.Header().Get("Content-Type"))
	assert.NotZero(t, rec.Body.String())
}

func Test_NotFound(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	rec := httptest.NewRecorder()
	NotFound(func(error) {})(rec, req)
	assert.Equal(t, "application/json",
		rec.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotZero(t, rec.Body.Len())
}

func Test_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	rec := httptest.NewRecorder()
	MethodNotAllowed(func(error) {})(rec, req)
	assert.Equal(t, "application/json",
		rec.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.NotZero(t, rec.Body.Len())
}

func Test_ExtractID(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	id, err := ExtractID(req)
	assert.Zero(t, id)
	assert.Error(t, err)

	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("id", "123")
	req = req.WithContext(context.WithValue(context.Background(),
		chi.RouteCtxKey, ctx))

	id, err = ExtractID(req)
	assert.Zero(t, id)
	assert.Error(t, err)

	inpID := xid.New()
	ctx = chi.NewRouteContext()
	ctx.URLParams.Add("id", inpID.String())
	req = req.WithContext(context.WithValue(context.Background(),
		chi.RouteCtxKey, ctx))

	id, err = ExtractID(req)
	assert.Equal(t, inpID, id)
	assert.NoError(t, err)
}

func Test_ExtractParam(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/", nil)
	val, err := ExtractParam(req, "key")
	assert.Zero(t, val)
	assert.Error(t, err)

	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("key", "123")
	req = req.WithContext(context.WithValue(context.Background(),
		chi.RouteCtxKey, ctx))

	val, err = ExtractParam(req, "key")
	assert.Equal(t, "123", val)
	assert.NoError(t, err)
}

func Test_ExtractIP(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = ""
	ip1, err := ExtractIP(req)
	assert.Nil(t, ip1)
	assert.Error(t, err)

	req = httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("X-Real-IP", "127.0.0.1")
	ip1, err = ExtractIP(req)
	assert.Equal(t, ip, ip1)
	assert.NoError(t, err)

	req = httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.2, 127.0.0.1")
	ip1, err = ExtractIP(req)
	assert.Equal(t, ip, ip1)
	assert.NoError(t, err)

	req = httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "127.0.0.1:3000"
	ip1, err = ExtractIP(req)
	assert.Equal(t, ip, ip1)
	assert.NoError(t, err)
}

func Test_ExtractSession(t *testing.T) {
	s, id, err := ExtractSession(context.Background())
	assert.Zero(t, s)
	assert.Zero(t, id)
	assert.Equal(t, ErrUnauthorized, err)

	s, id, err = ExtractSession(sessionup.NewContext(context.Background(),
		sessionup.Session{UserKey: "12345"}))
	assert.Zero(t, s)
	assert.Zero(t, id)
	assert.Equal(t, ErrUnauthorized, err)

	inpID := xid.New()
	s, id, err = ExtractSession(sessionup.NewContext(context.Background(),
		sessionup.Session{UserKey: inpID.String()}))
	assert.NotZero(t, s)
	assert.Equal(t, inpID, id)
	assert.NoError(t, err)
}
