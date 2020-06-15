package user

import (
	"testing"
	"time"

	"github.com/dchest/uniuri"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v3"
)

func Test_Token_IsEmpty(t *testing.T) {
	tok := Token{}
	assert.True(t, tok.IsEmpty())

	tok = Token{Hash: []byte("123")}
	assert.False(t, tok.IsEmpty())
}

func Test_Token_Init(t *testing.T) {
	cc := map[string]struct {
		Token Token
		Err   error
	}{
		"Too many requests": {
			Token: Token{
				NextAt: null.TimeFrom(time.Now().Add(time.Hour)),
			},
			Err: ErrTooManyTokens,
		},
		"Successful Token init": {
			Token: Token{},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

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

func Test_Token_Check(t *testing.T) {
	inp := Token{
		ExpiresAt: null.TimeFrom(time.Now().Add(time.Hour)),
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
				tok.ExpiresAt = null.TimeFrom(time.Time{})
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

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			err := c.Token.Check(c.Input)
			assert.Equal(t, c.Err, err)
		})
	}
}

func Test_Token_Clear(t *testing.T) {
	tok := Token{
		ExpiresAt: null.TimeFrom(time.Now()),
		NextAt:    null.TimeFrom(time.Now()),
		Hash:      []byte("10"),
	}

	tok.Clear()
	assert.True(t, tok.IsEmpty())
}

func Test_ToFullToken(t *testing.T) {
	tok := uniuri.New()
	id := xid.New()
	assert.Equal(t, tok+id.String(), toFullToken(tok, id))
}

func Test_FromFullToken(t *testing.T) {
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

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			tok, id, err := FromFullToken(c.Input)
			assert.Equal(t, c.Token, tok)
			assert.Equal(t, c.ID, id)
			assert.Equal(t, c.Err, err)
		})
	}
}
