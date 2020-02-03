package user

import (
	"testing"
	"time"

	"github.com/dchest/uniuri"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestTokenIsEmpty(t *testing.T) {
	tok := token{}
	assert.Equal(t, true, tok.IsEmpty())

	tok = token{Hash: []byte("123")}
	assert.Equal(t, false, tok.IsEmpty())
}

func TestTokenInit(t *testing.T) {
	cc := map[string]struct {
		Token token
		Err   error
	}{
		"Too many requests": {
			Token: token{
				NextAt: time.Now().Add(time.Hour),
			},
			Err: ErrTooManyTokens,
		},
		"Successful token init": {
			Token: token{},
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(st *testing.T) {
			st.Parallel()
			tok, err := c.Token.init(TokenTimes{time.Minute,
				time.Minute})

			if c.Err != nil {
				assert.Equal(t, c.Err, err)
				return
			}

			assert.Equal(t, uniuri.StdLen, len(tok))
			assert.Equal(t, false, c.Token.ExpiresAt.IsZero())
			assert.Equal(t, false, c.Token.NextAt.IsZero())
			assert.NotZero(t, c.Token.Hash)
		})
	}
}

func TestTokenCheck(t *testing.T) {
	inp := token{
		ExpiresAt: time.Now().Add(time.Hour),
		Hash: func() []byte {
			hash, _ := bcrypt.GenerateFromPassword([]byte("token"), bcrypt.DefaultCost)
			return hash
		}(),
	}

	cc := map[string]struct {
		Token token
		Err   error
		Input string
	}{
		"Expired token": {
			Token: func() token {
				tok := inp
				tok.ExpiresAt = time.Time{}
				return tok
			}(),
			Err:   ErrInvalidToken,
			Input: "token",
		},
		"Token hash is empty": {
			Token: func() token {
				tok := inp
				tok.Hash = nil
				return tok
			}(),
			Err:   ErrInvalidToken,
			Input: "token",
		},
		"Tokens do not match": {
			Token: inp,
			Err:   ErrInvalidToken,
			Input: "token1",
		},
		"Successful check": {
			Token: inp,
			Input: "token",
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(st *testing.T) {
			st.Parallel()
			err := c.Token.Check(c.Input)
			assert.Equal(t, c.Err, err)
		})
	}
}

func TestTokenClear(t *testing.T) {
	tok := token{
		ExpiresAt: time.Now(),
		NextAt:    time.Now(),
		Hash:      []byte("10"),
	}

	tok.Clear()
	assert.Equal(t, token{}, tok)
}

func TestToFullToken(t *testing.T) {
	tok := uniuri.New()
	id := xid.New()
	assert.Equal(t, tok+id.String(), toFullToken(tok, id))
}

func TestFromFullToken(t *testing.T) {
	inpID := xid.New()
	inpTok := uniuri.New()

	cc := map[string]struct {
		Token string
		ID    xid.ID
		Err   error
		Input string
	}{
		"Invalid token length": {
			Err:   ErrInvalidToken,
			Input: "123",
		},
		"Invalid embedded ID": {
			Err: ErrInvalidToken,
			Input: func() string {
				var id xid.ID
				return inpTok + id.String()
			}(),
		},
		"Successful extraction": {
			Token: inpTok,
			ID:    inpID,
			Input: inpTok + inpID.String(),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(st *testing.T) {
			st.Parallel()
			tok, id, err := FromFullToken(c.Input)
			assert.Equal(t, c.Token, tok)
			assert.Equal(t, c.ID, id)
			assert.Equal(t, c.Err, err)
		})
	}
}
