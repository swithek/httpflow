package email

import (
	"context"
	"net/smtp"

	"github.com/jordan-wright/email"
	"github.com/swithek/httpflow"
)

// Manager holds data needed to send emails to the users.
type Manager struct {
	host     string
	username string
	password string
	from     string
	onError  httpflow.ErrorExec
}

// NewManager creates a fresh instance of email manager.
func NewManager(host, username, password, from string, onError httpflow.ErrorExec) *Manager {
	return &Manager{
		host:     host,
		username: username,
		password: password,
		from:     from,
		onError:  onError,
	}
}

// send authenticates against the smtp server, builds an email and sends it
// to the address provided.
func (m *Manager) send(eml, subj, data string) {
	e := email.NewEmail()
	e.From = m.from
	e.To = []string{eml}
	e.Subject = subj
	e.HTML = []byte(data)
	err := e.Send(m.host, smtp.PlainAuth("", m.username, m.password, m.host))
	if err != nil {
		m.onError(err)
	}
}

// SendAccountActivation sends an email regarding account
// activation with the token, embedded into a full URL, to the
// specified email address.
func (m *Manager) SendAccountActivation(ctx context.Context, eml string, tok string) {
	panic("not implemented")
}

// SendEmailVerification sends an email regarding new email verification with
// the token, embedded into a full URL, to the specified email address.
func (m *Manager) SendEmailVerification(ctx context.Context, eml string, tok string) {
	panic("not implemented")
}

// SendEmailChanged sends an email to the old email address (first parameter)
// about a new email address being set (second parameter).
func (m *Manager) SendEmailChanged(ctx context.Context, oEml string, nEml string) {
	panic("not implemented")
}

// SendRecovery sends an email regarding password recovery with
// the token, embedded into a full URL, to the specified email address.
func (m *Manager) SendRecovery(ctx context.Context, eml string, tok string) {
	panic("not implemented")
}

// SendAccountDeleted sends an email regarding successful account deletion to
// the specified email address.
func (m *Manager) SendAccountDeleted(ctx context.Context, eml string) {
	panic("not implemented")
}

// SendPasswordChanged sends an email notifying about a successful
// password change to the specified email address.
// Last parameter specifies whether the password was changed during
// the recovery process or not.
func (m *Manager) SendPasswordChanged(ctx context.Context, eml string, recov bool) {
	panic("not implemented")
}
