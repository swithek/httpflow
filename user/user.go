package user

import (
	"net/http"
	"regexp"
	"time"

	"github.com/rs/xid"
	"github.com/swithek/httputil"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidEmail is returned when email is determined to be invalid.
	ErrInvalidEmail = httputil.NewError(nil, http.StatusBadRequest,
		"invalid email")

	// ErrInvalidPassword is returned when password is determined to be
	// invalid.
	ErrInvalidPassword = httputil.NewError(nil, http.StatusBadRequest,
		"invalid password")

	// ErrInvalidCredentials is returned when login credentials are
	// determined to be incorrect.
	ErrInvalidCredentials = httputil.NewError(nil, http.StatusBadRequest,
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

	// Update should update all modified / non-empty fields.
	Update(i Inputer) error

	// Core exposes the user's core fields.
	Core() *Core
}

// Core holds core fields needed for user data types.
type Core struct {
	// ID is the primary and unique user identification key.
	ID xid.ID

	// CreatedAt specifies the exact time when the user was created.
	CreatedAt time.Time

	// UpdatedAt specifies the exact time when the user was last updated.
	UpdatedAt time.Time

	// ActivatedAt specifies the exact time when user's account
	// was activated.
	ActivatedAt time.Time

	// Email is user's active email address.
	Email string

	// UnverifiedEmail is a new email address yet to be verified by its
	// owner. When verified this field is empty.
	UnverifiedEmail string

	// PasswordHash is already hashed version of user's password.
	PasswordHash []byte
}

// Init initializes all the values, user specified and default, needed for
// user's core to be usable.
func (c *Core) Init(i Inputer) error {
	ci := i.Core()

	c := Core{
		ID:        xid.New(),
		CreatedAt: time.Now(),
	}

	if err := c.Update(ci); err != nil {
		return err
	}

	return nil
}

// Update applies modification to user's core fields and sets new update
// time.
func (c *Core) Update(i Inputer) error {
	ci := i.Core()

	if err := c.SetEmail(ci.Email); err != nil {
		return err
	}

	if err := c.SetPassword(ci.Password); err != nil {
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

	if c.Email != "" && c.IsActivated() {
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
		if u.PasswordHash == nil {
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
	if len(p) < 8 { // TODO add more extensive checks
		return ErrInvalidPassword
	}

	return nil
}

// Inputer is an interface every user input data type should implement.
type Inputer interface {
	Core() CoreInput
}

// CoreInput holds core fields needed for every user's Init/Update.
type CoreInput struct {
	// Email is the user's email address submitted for further processing.
	Email string

	// Password is the user's plain-text password version submitted for
	// futher processing.
	Password string
}
