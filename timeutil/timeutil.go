// Package timeutil implements helper functions for time-related logic
// which extends the functionality of the standard time package.
package timeutil

import (
	"time"
)

// Now returns the current time with the location set to UTC.
func Now() time.Time {
	return time.Now().UTC()
}
