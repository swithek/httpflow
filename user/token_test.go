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
	tok := Token{}
	assert.True(t, tok.IsEmpty())

	tok = Token{Hash: []byte("123")}
	assert.False(t, tok.IsEmpty())
}

func TestTokenInit(t *testing.T) {
	cc := map[string]struct {
		Token Token
		Err   error
	}{
		"Too many requests": {
			Token: Token{
				NextAt: time.Now().Add(time.Hour),
			},
			Err: ErrTooManyTokens,
		},
		"Successful Token init": {
			Token: Token{},
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
			assert.False(t, c.Token.ExpiresAt.IsZero())
			assert.False(t, c.Token.NextAt.IsZero())
			assert.NotZero(t, c.Token.Hash)
		})
	}
}

func TestTokenCheck(t *testing.T) {
	inp := Token{
		ExpiresAt: time.Now().Add(time.Hour),
		Hash: func() []byte {
			hash, _ := bcrypt.GenerateFromPassword([]byte("Token"), bcrypt.DefaultCost)
			return hash
		}(),
	}

	cc := map[string]struct {
		Token Token
		Err   error
		Input string
	}{
		"Expired Token": {
			Token: func() Token {
				tok := inp
				tok.ExpiresAt = time.Time{}
				return tok
			}(),
			Err:   ErrInvalidToken,
			Input: "Token",
		},
		"Token hash is empty": {
			Token: func() Token {
				tok := inp
				tok.Hash = nil
				return tok
			}(),
			Err:   ErrInvalidToken,
			Input: "Token",
		},
		"Tokens do not match": {
			Token: inp,
			Err:   ErrInvalidToken,
			Input: "Token1",
		},
		"Successful check": {
			Token: inp,
			Input: "Token",
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
	tok := Token{
		ExpiresAt: time.Now(),
		NextAt:    time.Now(),
		Hash:      []byte("10"),
	}

	tok.Clear()
	assert.Equal(t, Token{}, tok)
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
		"Invalid Token length": {
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
