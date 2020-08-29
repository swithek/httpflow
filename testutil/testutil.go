// Package testutil implements helper functions for more convenient testing
// and may be imported in '_test.go' files only.
// Usage of some of these functions would have to be replaced by the ones
// provided by the official testing toolkit packages, should they decide
// to include helper functions of similar logic and kind.
package testutil

import (
	"net/http"
	"net/url"

	"reflect"
	"testing"

	"github.com/jarcoal/httpmock"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AssertEqualError uses testify's assert package to check if errors
// are equal or, if assert.AnError is expected, whether an error exists
// or not.
func AssertEqualError(t *testing.T, exp, err error) {
	t.Helper()

	if exp != nil {
		if exp == assert.AnError { //nolint:goerr113 // direct check is needed
			assert.Error(t, err)
			return
		}

		assert.Equal(t, exp, err)

		return
	}

	assert.NoError(t, err)
}

// RequireEqualError uses testify's require package to check if errors
// are equal or, if assert.AnError is expected, whether an error exists
// or not.
func RequireEqualError(t *testing.T, exp, err error) {
	t.Helper()

	if exp != nil {
		if exp == assert.AnError { //nolint:goerr113 // direct check is needed
			require.Error(t, err)
			return
		}

		require.Equal(t, exp, err)

		return
	}

	require.NoError(t, err)
}

// AssertFilterEqual asserts that two objects are equal.
// All ignored types found on any of the provided objects will not
// be compared.
func AssertFilterEqual(t *testing.T, v1, v2 interface{}, ignoreTypes []interface{}) {
	t.Helper()

	diff := cmp.Diff(v1, v2, cmpopts.IgnoreTypes(ignoreTypes...),
		cmp.Exporter(func(reflect.Type) bool { return true }))
	if diff != "" {
		t.Errorf("Not equal:\n%s", diff)
	}
}

// RequireFilterEqual asserts that two objects are equal.
// All ignored types found on any of the provided objects will not be compared.
func RequireFilterEqual(t *testing.T, v1, v2 interface{}, ignoreTypes []interface{}) {
	t.Helper()

	diff := cmp.Diff(v1, v2, cmpopts.IgnoreTypes(ignoreTypes...),
		cmp.Exporter(func(reflect.Type) bool { return true }))
	if diff != "" {
		t.Errorf("Not equal:\n%s", diff)
		t.FailNow()
	}
}

// MockHTTP returns mocked http environment.
func MockHTTP() (*http.Client, *httpmock.MockTransport) {
	t := httpmock.NewMockTransport()
	return &http.Client{Transport: t}, t
}

// QueryResponder asserts the required query values are present in the
// request.
func QueryResponder(t *testing.T, resp httpmock.Responder, q url.Values) httpmock.Responder {
	return func(r *http.Request) (*http.Response, error) {
		t.Helper()

		for k := range q {
			if q.Get(k) != "" {
				assert.Equal(t, q.Get(k), r.URL.Query().Get(k))
				continue
			}

			assert.Zero(t, r.URL.Query().Get(k))
		}

		return resp(r)
	}
}
