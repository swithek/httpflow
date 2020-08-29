package logutil

import (
	"bufio"
	"bytes"
	"errors"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Recover(t *testing.T) {
	cc := map[string]struct {
		Panic   interface{}
		Message string
		Fn      bool
		Result  string
	}{
		"Successful recovery from string type panic": {
			Panic:   "error",
			Message: "test",
			Fn:      true,
			Result:  `{"level":"error", "error":"internal error", "message":"test"}`,
		},
		"Successful recovery from error type panic": {
			Panic:   errors.New("error"),
			Message: "test",
			Fn:      true,
			Result:  `{"level":"error", "error":"internal error", "message":"test"}`,
		},
		"Successful recovery from unknown type panic": {
			Panic:   123,
			Message: "test",
			Fn:      true,
			Result:  `{"level":"error", "error":"internal error", "message":"test"}`,
		},
		"Successful recovery from panic without fn": {
			Panic:   "error",
			Message: "test",
			Result:  `{"level":"error", "error":"internal error", "message":"test"}`,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			var called bool
			var b bytes.Buffer
			out := bufio.NewWriter(&b)
			log := zerolog.New(out)

			var fn func()
			if c.Fn {
				fn = func() {
					called = true
				}
			}

			assert.NotPanics(t, func() {
				defer Recover(log, c.Message, nil, fn)
				panic(c.Panic)
			})

			require.NoError(t, out.Flush())
			assert.JSONEq(t, c.Result, b.String())
			assert.Equal(t, c.Fn, called)
		})
	}
}
