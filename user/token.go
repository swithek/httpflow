package user

import (
	"net/http"
	"time"

	"github.com/dchest/uniuri"
	"github.com/rs/xid"
	"github.com/swithek/httpflow"
	"github.com/swithek/httpflow/timeutil"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v3"
)

var (
	// ErrTooManyTokens is returned when too many requests for new tokens
	// have been received.
	ErrTooManyTokens = httpflow.NewError(nil, http.StatusTooManyRequests, "too many requests")

	// ErrInvalidToken is returned when the provided token is incorrect or
	// already expired.
	ErrInvalidToken = httpflow.NewError(nil, http.StatusBadRequest, "invalid token")
)

var (
	// _tokenChars is an array of characters used by token string
	// generator.
	_tokenChars = []byte("abcdefghijklmnopqrstuvwxyz0123456789")
)

// TokenLifetime holds data related to token expiration and next generation times.
type TokenLifetime struct {
	// Interval is used for token expiration time calculation.
	Interval time.Duration

	// Cooldown is used for token next allowed generation time calculation.
	Cooldown time.Duration
}

// Token is a temporary password-type data structure used for account
// verification and recovery.
type Token struct {
	// ExpiresAt specifies the exact time when the token becomes invalid.
	ExpiresAt null.Time `json:"-" db:"expires_at"`

	// NextAt specifies the exact time when the next token will be allowed
	// to be generated.
	NextAt null.Time `json:"-" db:"next_at"`

	// Hash is the hashed token value version. Treat it as a temporary
	// password.
	Hash []byte `json:"-" db:"hash"`
}

// IsEmpty checks whether the token is active or not.
func (t *Token) IsEmpty() bool {
	return t.ExpiresAt.Time.IsZero() && t.NextAt.Time.IsZero() && len(t.Hash) == 0
}

// gen generates a new token. Provided values determine the expiration time
// and the time when another token will be allowed to be generated.
func (t *Token) gen(tl TokenLifetime) (string, error) {
	if timeutil.Now().Before(t.NextAt.Time) {
		return "", ErrTooManyTokens
	}

	v := uniuri.NewLenChars(uniuri.StdLen, _tokenChars)

	h, err := bcrypt.GenerateFromPassword([]byte(v), bcrypt.DefaultCost)
	if err != nil {
		// unlikely to happen
		return "", err
	}

	t.ExpiresAt = null.TimeFrom(timeutil.Now().Add(tl.Interval))
	t.NextAt = null.TimeFrom(timeutil.Now().Add(tl.Cooldown))
	t.Hash = h

	return v, nil
}

// Check determines whether the provided token is correct and non-expired
// or not.
func (t *Token) Check(v string) error {
	if timeutil.Now().After(t.ExpiresAt.Time) {
		return ErrInvalidToken
	}

	if len(t.Hash) == 0 {
		return ErrInvalidToken
	}

	if bcrypt.CompareHashAndPassword(t.Hash, []byte(v)) != nil {
		return ErrInvalidToken
	}

	return nil
}

// Clear resets all token data.
func (t *Token) Clear() {
	t.ExpiresAt = null.TimeFrom(time.Time{})
	t.NextAt = null.TimeFrom(time.Time{})
	t.Hash = nil
}

// toFullToken combines token value and user's ID.
func toFullToken(t string, id xid.ID) string {
	return t + id.String()
}

// FromFullToken extracts token value and user's ID from the combined token
// form.
func FromFullToken(t string) (string, xid.ID, error) {
	if len(t) < uniuri.StdLen+1 {
		return "", xid.ID{}, ErrInvalidToken
	}

	raw := t[:uniuri.StdLen]

	id, err := xid.FromString(t[uniuri.StdLen:])
	if id.IsNil() || err != nil {
		return "", xid.ID{}, ErrInvalidToken
	}

	return raw, id, nil
}
