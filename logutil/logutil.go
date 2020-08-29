// Package logutil provides helper functions for more convenient logging
// and error tracking.
package logutil

import (
	"errors"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog"
)

// Critical creates an error level log event and sends the error to the
// remote error tracking service.
func Critical(log zerolog.Logger, err error) *zerolog.Event {
	st := sentry.NewStacktrace()
	st.Frames = st.Frames[:len(st.Frames)-1]

	e := sentry.NewEvent()
	e.Level = sentry.LevelError
	e.Exception = []sentry.Exception{{
		Type:       err.Error(),
		Stacktrace: st,
	}}
	sentry.CaptureEvent(e)

	// since critical errors might expose some of the internal logic,
	// they shouldn't be logged locally
	return log.Error().Err(errors.New("internal error"))
}

// Recover handles recoveries from panics, sends their info to the
// remote error tracking service and logs them locally.
// If no panic occurs, nothing will be logged / sent.
// Map parameter provides additional key-value pairs to include in the
// log entry (not the remote error tracking event). It can be nil.
// Function type parameter is called right before message printing. It can
// be nil.
// Example:
// `defer logutil.Recover(log, "cannot continue", map[string]interface{"request_id": "id123"}, cleanupFn)`.
// or
// `defer logutil.Recover(log, "cannot continue", nil, nil)`.
func Recover(log zerolog.Logger, msg string, extra map[string]interface{}, fn func()) {
	if r := recover(); r != nil {
		var rerr error

		switch v := r.(type) {
		case string:
			rerr = errors.New(v)
		case error:
			rerr = v
		default:
			rerr = errors.New("panic of unknown type")
		}

		if fn != nil {
			fn()
		}

		Critical(log, rerr).Fields(extra).Msg(msg)
	}
}
