package timeutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_Now(t *testing.T) {
	n := Now()
	assert.NotZero(t, n)
	assert.Equal(t, time.UTC, n.Location())
}
