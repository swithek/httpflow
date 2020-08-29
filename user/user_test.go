package user

import (
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/swithek/httpflow/testutil"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v3"
	"gopkg.in/guregu/null.v3/zero"
)

func Test_NewCore(t *testing.T) {
	cr, err := NewCore(CoreInput{})
	assert.Nil(t, cr)
	assert.Error(t, err)

	cr, err = NewCore(CoreInput{Email: _email, Password: "password"})
	assert.NoError(t, err)
	assert.NotZero(t, cr.ID)
	assert.Equal(t, _email, cr.Email)
	assert.NotZero(t, cr.PasswordHash)
}

func Test_Core_ApplyInput(t *testing.T) {
	cc := map[string]struct {
		Err   error
		Input CoreInput
	}{
		"Invalid email": {
			Err: assert.AnError,
			Input: CoreInput{
				Email:    "useremail.com",
				Password: "password",
			},
		},
		"Invalid password": {
			Err: assert.AnError,
			Input: CoreInput{
				Email:    _email,
				Password: "pass",
			},
		},
		"Successfully applied input": {
			Input: CoreInput{
				Email:    _email,
				Password: "password",
			},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			cr := Core{}
			res, err := cr.ApplyInput(c.Input)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			if c.Input.Email != "" {
				assert.True(t, res.ExposeCore().Email)
				assert.Equal(t, c.Input.Email, cr.Email)
			} else {
				assert.False(t, res.ExposeCore().Email)
				assert.Zero(t, cr.Email)
			}

			if c.Input.Password != "" {
				assert.True(t, res.ExposeCore().Password)
				assert.NotZero(t, cr.PasswordHash)
			} else {
				assert.False(t, res.ExposeCore().Password)
				assert.Zero(t, cr.PasswordHash)
			}
		})
	}
}

func Test_Core_ExposeCore(t *testing.T) {
	cr := Core{Email: _email}
	assert.Equal(t, &cr, cr.ExposeCore())
}

func Test_Core_IsActivated(t *testing.T) {
	cr := Core{}
	assert.False(t, cr.IsActivated())

	cr.ActivatedAt = zero.TimeFrom(time.Now())
	assert.True(t, cr.IsActivated())
}

func Test_Core_SetEmail(t *testing.T) {
	cc := map[string]struct {
		Err        error
		Current    string
		New        string
		Applied    bool
		Unverified bool
	}{
		"Empty new and current emails": {
			Err:     ErrInvalidEmail,
			Current: "",
			New:     "",
		},
		"Empty new email": {
			Current: _email,
			New:     "",
		},
		"Matching emails": {
			Current: _email,
			New:     _email,
		},
		"Invalid new email": {
			Err:     assert.AnError,
			Current: _email,
			New:     "useremail.com",
		},
		"Successful unverified email set": {
			Current:    _email,
			New:        "user123@email.com",
			Applied:    true,
			Unverified: true,
		},
		"Successful email set": {
			Current: "",
			New:     _email,
			Applied: true,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			cr := Core{}
			cr.Email = c.Current

			res, err := cr.SetEmail(c.New)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.Applied, res)

			if c.Applied {
				if c.Unverified {
					assert.Equal(t, c.New, cr.UnverifiedEmail.String)
				} else {
					assert.Equal(t, c.New, cr.Email)
				}
				return
			}
			assert.Equal(t, c.Current, cr.Email)
		})
	}
}

func Test_Core_SetUnverifiedEmail(t *testing.T) {
	cc := map[string]struct {
		Err     error
		Current string // current unverified email
		New     string
		Applied bool
	}{
		"Empty email": {
			Current: "",
			New:     "",
		},
		"Matching email": {
			Current: _email,
			New:     _email,
		},
		"Invalid email": {
			Err:     assert.AnError,
			Current: "",
			New:     "useremail.com",
		},
		"Successfully set unverified email": {
			Current: "",
			New:     _email,
			Applied: true,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			cr := Core{}
			cr.UnverifiedEmail = zero.StringFrom(c.Current)

			res, err := cr.SetUnverifiedEmail(c.New)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.Applied, res)

			if c.Applied {
				assert.Equal(t, c.New, cr.UnverifiedEmail.String)
				return
			}
			assert.Equal(t, c.Current, cr.UnverifiedEmail.String)
		})
	}
}

func Test_Core_SetPassword(t *testing.T) {
	cc := map[string]struct {
		Err      error
		Password string
		Hash     []byte
		Applied  bool
	}{
		"Empty new and current passwords": {
			Err:      ErrInvalidPassword,
			Password: "",
			Hash:     nil,
		},
		"Empty new password": {
			Password: "",
			Hash:     []byte("password"),
		},
		"Invalid password": {
			Err:      assert.AnError,
			Password: "pass",
			Hash:     []byte("password"),
		},
		"Successful password set": {
			Password: "password1",
			Hash:     []byte("password"),
			Applied:  true,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			cr := Core{PasswordHash: c.Hash}

			res, err := cr.SetPassword(c.Password)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.Applied, res)

			if c.Applied {
				assert.NoError(t, bcrypt.CompareHashAndPassword(
					cr.PasswordHash, []byte(c.Password)))
				return
			}
			assert.Error(t, bcrypt.CompareHashAndPassword(
				cr.PasswordHash, []byte(c.Password)))
		})
	}
}

func Test_Core_IsPasswordCorrect(t *testing.T) {
	cr := Core{}
	cr.PasswordHash, _ = bcrypt.GenerateFromPassword([]byte("password"),
		bcrypt.DefaultCost)
	assert.True(t, true, cr.IsPasswordCorrect("password"))
	assert.False(t, false, cr.IsPasswordCorrect("password1"))
}

func Test_Core_InitVerification(t *testing.T) {
	cc := map[string]struct {
		Err   error
		Token Token
	}{
		"Too many requests": {
			Err:   assert.AnError,
			Token: Token{NextAt: null.TimeFrom(time.Now().Add(time.Minute))},
		},
		"Successful init": {
			Token: Token{},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			cr := Core{ID: xid.New(), Verification: c.Token}
			tok, err := cr.InitVerification(TokenLifetime{time.Minute,
				time.Minute})
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.NotZero(t, tok)
			assert.NotZero(t, cr.Verification)
		})
	}
}

func Test_Core_Verify(t *testing.T) {
	inp := Token{}
	str, _ := inp.gen(TokenLifetime{time.Hour, time.Hour})
	cc := map[string]struct {
		Err             error
		Core            Core
		Token           string
		UnverifiedEmail bool
	}{
		"Unsuccessful Token check": {
			Err: assert.AnError,
			Core: Core{
				Verification: func() Token {
					tok := inp
					tok.ExpiresAt = null.TimeFrom(time.Time{})
					return tok
				}(),
			},
			Token: str,
		},
		"Unverified email matches active email": {
			Core: func() Core {
				cr := Core{
					ActivatedAt:  zero.TimeFrom(time.Now()),
					Verification: inp,
				}
				cr.Email = _email
				cr.UnverifiedEmail = zero.StringFrom(_email)
				return cr
			}(),
			Token:           str,
			UnverifiedEmail: true,
		},
		"Successful activation": {
			Core: Core{
				Verification: inp,
			},
			Token: str,
		},
		"Successful verification and activation": {
			Core: func() Core {
				cr := Core{
					ActivatedAt:  zero.TimeFrom(time.Time{}),
					Verification: inp,
				}
				cr.UnverifiedEmail = zero.StringFrom(_email)
				return cr
			}(),
			Token:           str,
			UnverifiedEmail: true,
		},
		"Successful email verification": {
			Core: func() Core {
				cr := Core{
					ActivatedAt:  zero.TimeFrom(time.Now()),
					Verification: inp,
				}
				cr.UnverifiedEmail = zero.StringFrom(_email)
				return cr
			}(),
			Token:           str,
			UnverifiedEmail: true,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			err := c.Core.Verify(c.Token)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.True(t, c.Core.Verification.IsEmpty())
			if c.UnverifiedEmail {
				assert.Zero(t, c.Core.UnverifiedEmail)
				assert.NotZero(t, c.Core.Email)
				return
			}

			assert.NotZero(t, c.Core.ActivatedAt)
		})
	}
}

func Test_Core_CancelVerification(t *testing.T) {
	inp := Token{}
	str, _ := inp.gen(TokenLifetime{time.Hour, time.Hour})
	cc := map[string]struct {
		Err   error
		Core  Core
		Token string
	}{
		"Unsuccessful Token check": {
			Err: assert.AnError,
			Core: Core{
				Verification: func() Token {
					tok := inp
					tok.ExpiresAt = null.TimeFrom(time.Time{})
					return tok
				}(),
			},
			Token: str,
		},
		"Successful verification cancellation": {
			Core: Core{
				Verification: inp,
			},
			Token: str,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			err := c.Core.CancelVerification(c.Token)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.True(t, c.Core.Verification.IsEmpty())
		})
	}
}

func Test_Core_InitRecovery(t *testing.T) {
	cc := map[string]struct {
		Err   error
		Token Token
	}{
		"Too many requests": {
			Err:   assert.AnError,
			Token: Token{NextAt: null.TimeFrom(time.Now().Add(time.Minute))},
		},
		"Successful init": {
			Token: Token{},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			cr := Core{ID: xid.New(), Recovery: c.Token}
			tok, err := cr.InitRecovery(TokenLifetime{time.Minute,
				time.Minute})
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.NotZero(t, tok)
			assert.NotZero(t, cr.Recovery)
		})
	}
}

func Test_Core_Recover(t *testing.T) {
	inp := Token{}
	str, _ := inp.gen(TokenLifetime{time.Hour, time.Hour})
	cc := map[string]struct {
		Err      error
		Core     Core
		Token    string
		Password string
	}{
		"Unsuccessful Token check": {
			Err: assert.AnError,
			Core: Core{
				Recovery: func() Token {
					tok := inp
					tok.ExpiresAt = null.TimeFrom(time.Time{})
					return tok
				}(),
			},
			Token:    str,
			Password: "password",
		},
		"Invalid password": {
			Err: assert.AnError,
			Core: Core{
				Recovery: inp,
			},
			Token:    str,
			Password: "pass",
		},
		"Empty password": {
			Err: ErrInvalidPassword,
			Core: Core{
				PasswordHash: []byte("password"),
				Recovery:     inp,
			},
			Token:    str,
			Password: "",
		},
		"Successful recovery": {
			Core: Core{
				Recovery: inp,
			},
			Token:    str,
			Password: "password",
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			err := c.Core.Recover(c.Token, c.Password)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.True(t, c.Core.Recovery.IsEmpty())
			assert.NoError(t, bcrypt.CompareHashAndPassword(
				c.Core.PasswordHash, []byte(c.Password)))
		})
	}
}

func Test_Core_CancelRecovery(t *testing.T) {
	inp := Token{}
	str, _ := inp.gen(TokenLifetime{time.Hour, time.Hour})
	cc := map[string]struct {
		Err   error
		Core  Core
		Token string
	}{
		"Unsuccessful Token check": {
			Err: assert.AnError,
			Core: Core{
				Recovery: func() Token {
					tok := inp
					tok.ExpiresAt = null.TimeFrom(time.Time{})
					return tok
				}(),
			},
			Token: str,
		},
		"Successful recovery cancellation": {
			Core: Core{
				Recovery: inp,
			},
			Token: str,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			err := c.Core.CancelRecovery(c.Token)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.True(t, c.Core.Recovery.IsEmpty())
		})
	}
}

func Test_CheckEmail(t *testing.T) {
	cc := map[string]struct {
		Email string
		Err   error
	}{
		"Without @": {
			Email: "useremail.com",
			Err:   ErrInvalidEmail,
		},
		"No symbols before @": {
			Email: "@email.com",
			Err:   ErrInvalidEmail,
		},
		"Multiple words": {
			Email: "user@email.com user",
			Err:   ErrInvalidEmail,
		},
		"No symbols after @": {
			Email: "user@",
			Err:   ErrInvalidEmail,
		},
		"Unsupported symbols before @": {
			Email: "user<>@email.com",
			Err:   ErrInvalidEmail,
		},
		"Unsupported symbols after @": {
			Email: "user@email%$.com",
			Err:   ErrInvalidEmail,
		},
		"Empty string": {
			Email: "",
			Err:   ErrInvalidEmail,
		},
		"Correct format": {
			Email: "user3000@email.com",
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			err := CheckEmail(c.Email)
			testutil.AssertEqualError(t, c.Err, err)
		})
	}
}

func Test_CheckPassword(t *testing.T) {
	err := CheckPassword("1234567")
	assert.Equal(t, ErrInvalidPassword, err)

	err = CheckPassword("12345678")
	assert.NoError(t, err)
}

func Test_CoreInput_ExposeCore(t *testing.T) {
	cInp := CoreInput{Email: _email}
	assert.Equal(t, cInp, cInp.ExposeCore())
}

func Test_CoreSummary_ExposeCore(t *testing.T) {
	cSum := CoreSummary{Email: true}
	assert.Equal(t, cSum, cSum.ExposeCore())
}

func Test_CoreStats_ExposeCore(t *testing.T) {
	cStats := CoreStats{TotalCount: 10}
	assert.Equal(t, cStats, cStats.ExposeCore())
}

func Test_CheckFilterKey(t *testing.T) {
	assert.NoError(t, CheckFilterKey("email"))
	assert.Error(t, CheckFilterKey("email1"))
}

func Test_CheckSortKey(t *testing.T) {
	assert.NoError(t, CheckSortKey("created_at"))
	assert.NoError(t, CheckSortKey("updated_at"))
	assert.NoError(t, CheckSortKey("activated_at"))
	assert.NoError(t, CheckSortKey("email"))
	assert.Error(t, CheckSortKey("email1"))
}
