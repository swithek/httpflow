package user

import (
	"net/http"
	"regexp"
	"time"

	"github.com/rs/xid"
	"github.com/swithek/httpflow"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidEmail is returned when email is determined to be invalid.
	ErrInvalidEmail = httpflow.NewError(nil, http.StatusBadRequest,
		"invalid email")

	// ErrInvalidPassword is returned when password is determined to be
	// invalid.
	ErrInvalidPassword = httpflow.NewError(nil, http.StatusBadRequest,
		"invalid password")

	// ErrInvalidCredentials is returned when login credentials are
	// determined to be incorrect.
	ErrInvalidCredentials = httpflow.NewError(nil, http.StatusBadRequest,
		"incorrect credentials")
)

var (
	// emailRe defines a regexp validation instance with a preset
	// allowed email format.
	emailRe = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)

// User is an interface every user data type should implement.
type User interface {
	// Init should initialize default and other values needed for
	// user data type to be inserted into the data store for the first
	// time.
	Init(i Inputer) error

	// ApplyInput should set values from provided data structure.
	ApplyInput(i Inputer) error

	// Core exposes the user's core fields.
	Core() *Core
}

// Core holds core fields needed for user data types.
type Core struct {
	// ID is the primary and unique user identification key.
	ID xid.ID `json:"id"`

	// CreatedAt specifies the exact time when the user was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt specifies the exact time when the user was last updated.
	UpdatedAt time.Time `json:"updated_at"`

	// ActivatedAt specifies the exact time when user's account
	// was activated.
	ActivatedAt time.Time `json:"activated_at"`

	// Email is user's active email address.
	Email string `json:"email"`

	// UnverifiedEmail is a new email address yet to be verified by its
	// owner. When verified this field is empty.
	UnverifiedEmail string `json:"unverified_email"`

	// PasswordHash is already hashed version of user's password.
	PasswordHash []byte `json:"password_hash"`

	// Verification holds data needed for account activation or email
	// update.
	Verification token `json:"-"`

	// Recovery holds data needed for password recovery.
	Recovery token `json:"-"`
}

// Init initializes all the values, user specified and default, needed for
// user's core to be usable.
func (c *Core) Init(inp Inputer) error {
	*c = Core{
		ID:        xid.New(),
		CreatedAt: time.Now(),
	}

	if err := c.ApplyInput(inp); err != nil {
		return err
	}

	return nil
}

// ApplyInput applies modification to user's core fields and sets new update
// time.
func (c *Core) ApplyInput(inp Inputer) error {
	cInp := inp.Core()

	if err := c.SetEmail(cInp.Email); err != nil {
		return err
	}

	if err := c.SetPassword(cInp.Password); err != nil {
		return err
	}

	c.UpdatedAt = time.Now()

	return nil
}

// Core exposes the user's core fields.
func (c *Core) Core() *Core {
	return c
}

// IsActivated checks whether the user's account is activated.
func (c *Core) IsActivated() bool {
	return !c.ActivatedAt.IsZero()
}

// SetEmail checks and updates user's email address.
func (c *Core) SetEmail(e string) error {
	if e == "" {
		if c.Email == "" {
			return ErrInvalidEmail
		}
		return nil
	}

	if c.Email == e {
		return nil
	}

	if c.Email != "" {
		return c.SetUnverifiedEmail(e)
	}

	if err := CheckEmail(e); err != nil {
		return err
	}

	c.Email = e
	return nil
}

// SetUnverifiedEmail checks and updates user's unverified email address.
func (c *Core) SetUnverifiedEmail(e string) error {
	if e == "" {
		return nil
	}

	if c.UnverifiedEmail == e {
		return nil
	}

	if err := CheckEmail(e); err != nil {
		return err
	}

	c.UnverifiedEmail = e
	return nil
}

// SetPassword checks and updates user's password hash.
func (c *Core) SetPassword(p string) error {
	if p == "" {
		if c.PasswordHash == nil {
			return ErrInvalidPassword
		}
		return nil
	}

	if err := CheckPassword(p); err != nil {
		return err
	}

	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	c.PasswordHash = h
	return nil
}

// IsPasswordCorrect checks whether the provided password matches the hash.
func (c *Core) IsPasswordCorrect(p string) bool {
	return bcrypt.CompareHashAndPassword(c.PasswordHash, []byte(p)) == nil
}

// InitVerification initializes account / email verification and returns
// combination of token and user ID in a string format to send in verification
// emails etc.
// First parameter determines how long the verification token should be active.
// Second parameter determines how much time has to pass until another token
// can be generated.
func (c *Core) InitVerification(tt TokenTimes) (string, error) {
	t, err := c.Verification.init(tt)
	if err != nil {
		return "", err
	}
	return toFullToken(t, c.ID), nil
}

// Verify checks whether the provided token is valid and either activates
// the account (if it wasn't already) or, if unverified email address exists,
// confirms it as the main email address.
// NOTE: provided token must in its original / raw form - not combined with
// the user's ID (as InitVerification method returns).
func (c *Core) Verify(t string) error {
	if err := c.Verification.Check(t); err != nil {
		return err
	}

	if !c.IsActivated() {
		c.ActivatedAt = time.Now()
	} else if c.UnverifiedEmail != "" {
		if c.UnverifiedEmail != c.Email {
			c.Email = c.UnverifiedEmail
		}
		c.UnverifiedEmail = ""
	}

	c.Verification.Clear()
	return nil
}

// CancelVerification checks whether the provided token is valid and clears
// the active verification token data.
// NOTE: provided token must in its original / raw form - not combined with
// the user's ID (as InitVerification method returns).
func (c *Core) CancelVerification(t string) error {
	if err := c.Verification.Check(t); err != nil {
		return err
	}
	c.Verification.Clear()
	return nil
}

// InitRecovery initializes password recovery and returns a combination of
// token and user ID in a string format to send in recovery emails etc.
// First parameter determines how long the recovery token should be active.
// Second parameter determines how much time has to pass until another token
// can be generated.
func (c *Core) InitRecovery(tt TokenTimes) (string, error) {
	t, err := c.Recovery.init(tt)
	if err != nil {
		return "", err
	}
	return toFullToken(t, c.ID), nil
}

// Recover checks whether the provided token is valid and sets the provided
// password as the new account password.
// NOTE: provided token must in its original / raw form - not combined with
// the user's ID (as InitRecovery method returns).
func (c *Core) Recover(t, p string) error {
	if err := c.Recovery.Check(t); err != nil {
		return err
	}

	if err := c.SetPassword(p); err != nil {
		return err
	}

	c.Recovery.Clear()
	return nil
}

// CancelRecovery checks whether the provided token is valid and clears all
// active recovery token data.
// NOTE: provided token must in its original / raw form - not combined with
// the user's ID (as InitRecovery method returns).
func (c *Core) CancelRecovery(t string) error {
	if err := c.Recovery.Check(t); err != nil {
		return err
	}
	c.Recovery.Clear()
	return nil
}

// CheckEmail determines whether the provided email address is of correct
// format.
func CheckEmail(e string) error {
	if !emailRe.MatchString(e) {
		return ErrInvalidEmail
	}

	return nil
}

// CheckPassword determines whether the provided password is of correct format.
func CheckPassword(p string) error {
	if len(p) < 8 { // TODO add more extensive checks?
		return ErrInvalidPassword
	}

	return nil
}

// Inputer is an interface every user input data type should implement.
type Inputer interface {
	Core() CoreInput
}

// CoreInput holds core fields needed for every user's Init/ApplyInput calls.
type CoreInput struct {
	// Email is the user's email address submitted for further processing.
	Email string

	// Password is the user's plain-text password version submitted for
	// futher processing.
	Password string
}

func (c CoreInput) Core() CoreInput {
	return c
}
