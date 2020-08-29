// Package user provides user data handling functionality.
package user

import (
	"net/http"
	"regexp"
	"time"

	"github.com/rs/xid"
	"github.com/swithek/httpflow"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v3/zero"
)

var (
	// ErrInvalidEmail is returned when email is determined to be invalid.
	ErrInvalidEmail = httpflow.NewError(nil, http.StatusBadRequest, "invalid email")

	// ErrInvalidPassword is returned when password is determined to be
	// invalid.
	ErrInvalidPassword = httpflow.NewError(nil, http.StatusBadRequest, "invalid password")

	// ErrInvalidCredentials is returned when login credentials are
	// determined to be incorrect.
	ErrInvalidCredentials = httpflow.NewError(nil, http.StatusUnauthorized, "incorrect credentials")
)

var (
	// _emailRe defines a regexp validation instance with a preset
	// allowed email format.
	_emailRe = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)

var (
	// VerifLifetime is the default / recommended verification token
	// lifetime value.
	VerifLifetime = TokenLifetime{ //nolint:gochecknoglobals // used as a constant
		Interval: time.Hour * 24 * 7,
		Cooldown: time.Minute,
	}

	// RecovLifetime is the default / recommended recovery token lifetime
	// value.
	RecovLifetime = TokenLifetime{ //nolint:gochecknoglobals // used as a constant
		Interval: time.Hour * 3,
		Cooldown: time.Minute,
	}
)

// User is an interface every user data type should implement.
type User interface {
	// ApplyInput should set values from provided data structure.
	// If certain input fields are empty, their destination fields
	// in the underlying user's structure should not be modified.
	ApplyInput(i Inputer) (Summary, error)

	// ExposeCore should return user's core fields.
	ExposeCore() *Core
}

// Core holds core fields needed for user data types.
type Core struct {
	// ID is the primary and unique user identification key.
	ID xid.ID `json:"id" db:"id"`

	// CreatedAt specifies the exact time when the user was created.
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt specifies the exact time when the user was last updated.
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// ActivatedAt specifies the exact time when user's account
	// was activated.
	ActivatedAt zero.Time `json:"activated_at" db:"activated_at"`

	// Email is user's active email address.
	Email string `json:"email" db:"email"`

	// UnverifiedEmail is a new email address yet to be verified by its
	// owner. When verified this field is empty.
	UnverifiedEmail zero.String `json:"unverified_email" db:"unverified_email"`

	// PasswordHash is already hashed version of user's password.
	PasswordHash []byte `json:"-" db:"password_hash"`

	// Verification holds data needed for account activation or email
	// update.
	Verification Token `json:"-" db:"verification"`

	// Recovery holds data needed for account recovery.
	Recovery Token `json:"-" db:"recovery"`
}

// NewCore initializes all the values, user specified and default, needed for
// user's core to be usable and returns it.
func NewCore(inp Inputer) (*Core, error) {
	c := &Core{
		ID:        xid.New(),
		CreatedAt: time.Now(),
	}

	if _, err := c.ApplyInput(inp); err != nil {
		return nil, err
	}

	return c, nil
}

// ApplyInput applies modification to user's core fields and sets new update
// time.
func (c *Core) ApplyInput(inp Inputer) (Summary, error) {
	cInp := inp.ExposeCore()

	eml, err := c.SetEmail(cInp.Email)
	if err != nil {
		return nil, err
	}

	pass, err := c.SetPassword(cInp.Password)
	if err != nil {
		return nil, err
	}

	c.UpdatedAt = time.Now()

	return CoreSummary{
		Email:    eml,
		Password: pass,
	}, nil
}

// ExposeCore returns user's core fields.
func (c *Core) ExposeCore() *Core {
	return c
}

// IsActivated checks whether user's account is activated or not.
func (c *Core) IsActivated() bool {
	return !c.ActivatedAt.IsZero()
}

// SetEmail checks and updates user's email address.
// First return value determines whether the email was set or not.
func (c *Core) SetEmail(e string) (bool, error) {
	if e == "" {
		if c.Email == "" {
			return false, ErrInvalidEmail
		}

		return false, nil
	}

	if c.Email == e {
		return false, nil
	}

	if c.Email != "" {
		return c.SetUnverifiedEmail(e)
	}

	if err := CheckEmail(e); err != nil {
		return false, err
	}

	c.Email = e

	return true, nil
}

// SetUnverifiedEmail checks and updates user's unverified email address.
// First return value determines whether the email was set or not.
func (c *Core) SetUnverifiedEmail(e string) (bool, error) {
	if e == "" {
		return false, nil
	}

	if c.UnverifiedEmail.String == e {
		return false, nil
	}

	if err := CheckEmail(e); err != nil {
		return false, err
	}

	c.UnverifiedEmail = zero.StringFrom(e)

	return true, nil
}

// SetPassword checks and updates user's password hash.
// First return value determines whether the password was set or not.
func (c *Core) SetPassword(p string) (bool, error) {
	if p == "" {
		if c.PasswordHash == nil {
			return false, ErrInvalidPassword
		}

		return false, nil
	}

	if err := CheckPassword(p); err != nil {
		return false, err
	}

	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		// unlikely to happen
		return false, err
	}

	c.PasswordHash = h

	return true, nil
}

// IsPasswordCorrect checks whether the provided password matches the hash
// or not.
func (c *Core) IsPasswordCorrect(p string) bool {
	return bcrypt.CompareHashAndPassword(c.PasswordHash, []byte(p)) == nil
}

// InitVerification initializes account / email verification and returns
// combination of token and user ID in a string format to send in verification
// emails etc.
// First parameter determines how long the verification Token should be active.
// Second parameter determines how much time has to pass until another Token
// can be generated.
func (c *Core) InitVerification(tl TokenLifetime) (string, error) {
	t, err := c.Verification.gen(tl)
	if err != nil {
		return "", err
	}

	return toFullToken(t, c.ID), nil
}

// Verify checks whether the provided token is valid and activates
// the account (if it wasn't already) and/or, if unverified email address
// exists, confirms it as the main email address.
// NOTE: provided Token must in its original / raw form - not combined with
// user's ID (as InitVerification method returns).
func (c *Core) Verify(t string) error {
	if err := c.Verification.Check(t); err != nil {
		return err
	}

	// New email verification and account activation is allowed at the
	// same time to allow the user to change their email when the account
	// is not activated. Account will be activated even during email
	// verification.

	if !c.IsActivated() {
		c.ActivatedAt = zero.TimeFrom(time.Now())
	}

	if c.UnverifiedEmail.String != "" {
		if c.UnverifiedEmail.String != c.Email {
			c.Email = c.UnverifiedEmail.String
		}

		c.UnverifiedEmail = zero.StringFrom("")
	}

	c.Verification.Clear()

	return nil
}

// CancelVerification checks whether the provided Token is valid and clears
// the active verification Token data.
// NOTE: provided Token must be in its original / raw form - not combined
// with user's ID (as InitVerification method returns).
func (c *Core) CancelVerification(t string) error {
	if err := c.Verification.Check(t); err != nil {
		return err
	}

	c.Verification.Clear()

	return nil
}

// InitRecovery initializes account recovery and returns a combination of
// Token and user ID in a string format to send in recovery emails etc.
// First parameter determines how long the recovery Token should be active.
// Second parameter determines how much time has to pass until another Token
// can be generated.
func (c *Core) InitRecovery(tl TokenLifetime) (string, error) {
	t, err := c.Recovery.gen(tl)
	if err != nil {
		return "", err
	}

	return toFullToken(t, c.ID), nil
}

// Recover checks whether the provided Token is valid and sets the provided
// password as the new account password.
// NOTE: provided Token must be in its original / raw form - not combined
// with user's ID (as InitRecovery method returns).
func (c *Core) Recover(t, p string) error {
	if err := c.Recovery.Check(t); err != nil {
		return err
	}

	res, err := c.SetPassword(p)
	if err != nil {
		return err
	}

	if !res {
		return ErrInvalidPassword
	}

	c.Recovery.Clear()

	return nil
}

// CancelRecovery checks whether the provided Token is valid and clears all
// active recovery Token data.
// NOTE: provided Token must in its original / raw form - not combined with
// user's ID (as InitRecovery method returns).
func (c *Core) CancelRecovery(t string) error {
	if err := c.Recovery.Check(t); err != nil {
		return err
	}

	c.Recovery.Clear()

	return nil
}

// CheckEmail determines whether the provided email address is of correct
// format or not.
func CheckEmail(e string) error {
	if !_emailRe.MatchString(e) {
		return ErrInvalidEmail
	}

	return nil
}

// CheckPassword determines whether the provided password is of correct
// format or not.
func CheckPassword(p string) error {
	if len(p) < 8 { // TODO add more extensive checks?
		return ErrInvalidPassword
	}

	return nil
}

// Inputer is an interface which should be implemented by every user
// input data type.
type Inputer interface {
	// ExposeCore should return user's core input fields.
	ExposeCore() CoreInput
}

// CoreInput holds core fields needed for every user's ApplyInput call.
type CoreInput struct {
	// Email is user's email address submitted for further processing.
	Email string `json:"email"`

	// Password is user's plain-text password version submitted for
	// further processing.
	Password string `json:"password"`

	// RememberMe specifies whether a persistent session should be
	// created on registration / log in or not.
	RememberMe bool `json:"remember_me"`
}

// ExposeCore returns user's core input fields.
func (c CoreInput) ExposeCore() CoreInput {
	return c
}

// Summary is an interface which should be implemented by every user
// data type describing modifications during updates.
type Summary interface {
	// ExposeCore should return user's core fields' modification status.
	ExposeCore() CoreSummary
}

// CoreSummary holds core fields' information which determines whether they
// were modified or not.
type CoreSummary struct {
	// Email specifies whether the email was modified during
	// input application or not.
	Email bool

	// Password specifies whether the password was modified
	// during input application or not.
	Password bool
}

// ExposeCore returns user's core input fields' modification status.
func (c CoreSummary) ExposeCore() CoreSummary {
	return c
}

// Stats is an interface which should be implemented by every user statistics
// data type.
type Stats interface {
	// ExposeCore should return users' core statistics.
	ExposeCore() CoreStats
}

// CoreStats holds core user statistics.
type CoreStats struct {
	// TotalCount specifies the total number of users in the data store.
	TotalCount int `json:"total_count" db:"total_count"`
}

// ExposeCore returns users' core statistics.
func (c CoreStats) ExposeCore() CoreStats {
	return c
}

// CheckFilterKey determines whether the filter key is valid or not.
func CheckFilterKey(fk string) error {
	if fk == "email" { // more options might be added
		return nil
	}

	return httpflow.NewError(nil, http.StatusBadRequest, "invalid filter key")
}

// CheckSortKey determines whether the sort key is valid or not.
func CheckSortKey(sk string) error {
	switch sk {
	case "created_at", "updated_at", "activated_at", "email":
		return nil
	}

	return httpflow.NewError(nil, http.StatusBadRequest, "invalid sort key")
}
