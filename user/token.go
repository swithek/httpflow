package user

import (
	"net/http"
	"time"

	"github.com/dchest/uniuri"
	"github.com/rs/xid"
	"github.com/swithek/httputil"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrTooManyTokens is returned when too many requests for new tokens
	// have been received.
	ErrTooManyTokens = httputil.NewError(nil, http.StatusTooManyRequests,
		"too many requests")

	// ErrInvalidToken is returned when the provided token is incorrect or
	// already expired.
	ErrInvalidToken = httputil.NewError(nil, http.StatusBadRequest,
		"invalid token")
)

// token is a temporary password-type data structure used for account
// verification and recovery.
type token struct {
	// ExpiresAt specifies the exact time when the token becomes invalid.
	ExpiresAt time.Time

	// NextAt specifies the exact time when the next token will be allowed
	// to be generated.
	NextAt time.Time

	// Hash is the hashed token value version. Treat it as a temporary
	// password.
	Hash []byte
}

// IsEmpty checks whether the token is active or not.
func (t *token) IsEmpty() bool {
	return t.ExpiresAt.IsZero() && t.NextAt.IsZero() && len(t.Hash) == 0
}

// init generates a new token. Provided values determine the expiration time
// and the time when another token will be allowed to be generated.
func (t *token) init(exp, nxt time.Duration) (string, error) {
	if time.Now().Before(t.NextAt) {
		return "", ErrTooManyTokens
	}

	v := uniuri.New()
	h, err := bcrypt.GenerateFromPassword([]byte(v), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	t.ExpiresAt = time.Now().Add(exp)
	t.NextAt = time.Now().Add(nxt)
	t.Hash = h
	return v, nil
}

// Check determines whether the provided token is correct and non-expired.
func (t *token) Check(v string) error {
	if time.Now().After(t.ExpiresAt) {
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
