package httpflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueryValidate(t *testing.T) {
	cc := map[string]struct {
		FilterKeyCheck func(string, string) error
		SortKeyCheck   func(string) error
		Query          Query
		Err            error
	}{
		"Error returned by filter key checking func": {
			FilterKeyCheck: func(_, _ string) error {
				return assert.AnError
			},
			SortKeyCheck: func(_ string) error {
				return nil
			},
			Query: Query{
				Limit: 3,
				Page:  20,
			},
			Err: assert.AnError,
		},
		"Error returned by sort key checking func": {
			FilterKeyCheck: func(_, _ string) error {
				return nil
			},
			SortKeyCheck: func(_ string) error {
				return assert.AnError
			},
			Query: Query{
				Limit: 3,
				Page:  20,
			},
			Err: assert.AnError,
		},
		"Invalid count value": {
			FilterKeyCheck: func(_, _ string) error {
				return nil
			},
			SortKeyCheck: func(_ string) error {
				return nil
			},
			Query: Query{
				Limit: 0,
				Page:  20,
			},
			Err: assert.AnError,
		},
		"Invalid page value": {
			FilterKeyCheck: func(_, _ string) error {
				return nil
			},
			SortKeyCheck: func(_ string) error {
				return nil
			},
			Query: Query{
				Limit: 3,
				Page:  0,
			},
			Err: assert.AnError,
		},
		"Successful validation": {
			FilterKeyCheck: func(_, _ string) error {
				return nil
			},
			SortKeyCheck: func(_ string) error {
				return nil
			},
			Query: Query{
				Limit: 3,
				Page:  20,
			},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			err := c.Query.Validate(c.FilterKeyCheck, c.SortKeyCheck)
			if c.Err != nil {
				if c.Err == assert.AnError { //nolint:goerr113 // direct check is needed
					assert.Error(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}

				return
			}

			assert.NoError(t, err)
		})
	}
}
