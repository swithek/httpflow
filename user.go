package httpuser

import (
	"errors"
	"regexp"
	"time"

	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidEmail    = errors.New("invalid email")
	ErrInvalidPassword = errors.New("invalid password")
)

var (
	// emailRe defines a regexp validation instance with a preset
	// allowed email format.
	emailRe = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)

type User interface {
	Init(i Inputer) error
	Update(i Inputer) error
}

type Core struct {
	ID           xid.ID
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Email        string
	PasswordHash []byte
}

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

func (c *Core) SetEmail(e string) error {
	if e == "" {
		if c.Email == "" {
			return ErrInvalidEmail
		}
		return nil
	}

	if err := CheckEmail(e); err != nil {
		return err
	}

	c.Email = e
	return nil
}

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

func (c *Core) IsPasswordCorrect(p string) bool {
	return bcrypt.CompareHashAndPassword(c.PasswordHash, []byte(p)) == nil
}

func CheckEmail(e string) error {
	if !emailRe.MatchString(e) {
		return ErrInvalidEmail
	}

	return nil
}

func CheckPassword(p string) error {
	if len(p) < 8 { // TODO add more extensive checks
		return ErrInvalidPassword
	}

	return nil
}

type Inputer interface {
	Core() CoreInput
}

type CoreInput struct {
	Email    string
	Password string
}
