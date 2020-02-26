package user

import (
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v3"
	"gopkg.in/guregu/null.v3/zero"
)

func TestNewCore(t *testing.T) {
	cr, err := NewCore(CoreInput{})
	assert.NotNil(t, err)

	cr, err = NewCore(CoreInput{Email: "user@email.com", Password: "password"})
	assert.Nil(t, err)
	assert.NotZero(t, cr.ID)
	assert.Equal(t, "user@email.com", cr.Email)
	assert.NotZero(t, cr.PasswordHash)
}

func TestCoreApplyInput(t *testing.T) {
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
				Email:    "user@email.com",
				Password: "pass",
			},
		},
		"Successfully applied input": {
			Input: CoreInput{
				Email:    "user@email.com",
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

			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
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

func TestCoreExposeCore(t *testing.T) {
	cr := Core{Email: "user@email.com"}
	assert.Equal(t, &cr, cr.ExposeCore())
}

func TestCoreIsActivated(t *testing.T) {
	cr := Core{}
	assert.False(t, cr.IsActivated())

	cr.ActivatedAt = zero.TimeFrom(time.Now())
	assert.True(t, cr.IsActivated())
}

func TestCoreSetEmail(t *testing.T) {
	current := "user@email.com"

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
			Current: current,
			New:     "",
		},
		"Matching emails": {
			Current: current,
			New:     current,
		},
		"Invalid new email": {
			Err:     assert.AnError,
			Current: current,
			New:     "useremail.com",
		},
		"Successful unverified email set": {
			Current:    current,
			New:        "user123@email.com",
			Applied:    true,
			Unverified: true,
		},
		"Successful email set": {
			Current: "",
			New:     current,
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
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
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

func TestCoreSetUnverifiedEmail(t *testing.T) {
	current := "user@email.com"

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
			Current: current,
			New:     current,
		},
		"Invalid email": {
			Err:     assert.AnError,
			Current: "",
			New:     "useremail.com",
		},
		"Successfully set unverified email": {
			Current: "",
			New:     current,
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
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
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

func TestCoreSetPassword(t *testing.T) {
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
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}

			assert.Equal(t, c.Applied, res)

			if c.Applied {
				assert.Nil(t, bcrypt.CompareHashAndPassword(
					cr.PasswordHash, []byte(c.Password)))
				return
			}
			assert.NotNil(t, bcrypt.CompareHashAndPassword(
				cr.PasswordHash, []byte(c.Password)))
		})
	}
}

func TestCoreIsPasswordCorrect(t *testing.T) {
	cr := Core{}
	cr.PasswordHash, _ = bcrypt.GenerateFromPassword([]byte("password"),
		bcrypt.DefaultCost)
	assert.True(t, true, cr.IsPasswordCorrect("password"))
	assert.False(t, false, cr.IsPasswordCorrect("password1"))
}

func TestCoreInitVerification(t *testing.T) {
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
			tok, err := cr.InitVerification(TokenTimes{time.Minute,
				time.Minute})
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}

			assert.NotZero(t, tok)
			assert.NotZero(t, cr.Verification)
		})
	}
}

func TestCoreVerify(t *testing.T) {
	inp := Token{}
	str, _ := inp.init(TokenTimes{time.Hour, time.Hour})
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
				cr.Email = "user@email.com"
				cr.UnverifiedEmail = zero.StringFrom("user@email.com")
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
				cr.UnverifiedEmail = zero.StringFrom("user@email.com")
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
				cr.UnverifiedEmail = zero.StringFrom("user@email.com")
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
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
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

func TestCoreCancelVerification(t *testing.T) {
	inp := Token{}
	str, _ := inp.init(TokenTimes{time.Hour, time.Hour})
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
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}
			assert.True(t, c.Core.Verification.IsEmpty())
		})
	}
}

func TestCoreInitRecovery(t *testing.T) {
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
			tok, err := cr.InitRecovery(TokenTimes{time.Minute,
				time.Minute})
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}

			assert.NotZero(t, tok)
			assert.NotZero(t, cr.Recovery)
		})
	}
}

func TestCoreRecover(t *testing.T) {
	inp := Token{}
	str, _ := inp.init(TokenTimes{time.Hour, time.Hour})
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
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}

			assert.True(t, c.Core.Recovery.IsEmpty())
			assert.Nil(t, bcrypt.CompareHashAndPassword(
				c.Core.PasswordHash, []byte(c.Password)))
		})
	}
}

func TestCoreCancelRecovery(t *testing.T) {
	inp := Token{}
	str, _ := inp.init(TokenTimes{time.Hour, time.Hour})
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
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}
			assert.True(t, c.Core.Recovery.IsEmpty())
		})
	}
}

func TestCheckEmail(t *testing.T) {
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
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}
		})
	}
}

func TestCheckPassword(t *testing.T) {
	err := CheckPassword("1234567")
	assert.Equal(t, ErrInvalidPassword, err)

	err = CheckPassword("12345678")
	assert.Nil(t, err)
}

func TestCoreInputExposeCore(t *testing.T) {
	cInp := CoreInput{Email: "user@email.com"}
	assert.Equal(t, cInp, cInp.ExposeCore())
}

func TestCoreSummaryExposeCore(t *testing.T) {
	cSum := CoreSummary{Email: true}
	assert.Equal(t, cSum, cSum.ExposeCore())
}

func TestCheckFilterKey(t *testing.T) {
	assert.Nil(t, CheckFilterKey("email"))
	assert.NotNil(t, CheckFilterKey("email1"))
}

func TestCheckSortKey(t *testing.T) {
	assert.Nil(t, CheckSortKey("created_at"))
	assert.Nil(t, CheckSortKey("updated_at"))
	assert.Nil(t, CheckSortKey("activated_at"))
	assert.Nil(t, CheckSortKey("email"))
	assert.NotNil(t, CheckSortKey("email1"))
}
