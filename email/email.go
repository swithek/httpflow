package email

import (
	"context"
	"errors"
	"fmt"
	"net/smtp"

	"github.com/jordan-wright/email"
	"github.com/matcornic/hermes/v2"
	"github.com/swithek/httpflow"
)

// Manager holds data needed to send emails to the users.
type Manager struct {
	host     string
	username string
	password string
	from     string
	herm     hermes.Hermes
	links    httpflow.Links
	onError  httpflow.ErrorExec
}

// NewManager creates a fresh instance of email manager.
func NewManager(host, username, password, from string, herm hermes.Hermes,
	l httpflow.Links, onError httpflow.ErrorExec) (*Manager, error) {

	if !l.Exist(httpflow.LinkVerification, httpflow.LinkVerificationCancel,
		httpflow.LinkActivation, httpflow.LinkActivationCancel,
		httpflow.LinkRecovery, httpflow.LinkRecoveryCancel) {

		return nil, errors.New("not all links are set up")
	}

	return &Manager{
		host:     host,
		username: username,
		password: password,
		from:     from,
		herm:     herm,
		links:    l,
		onError:  onError,
	}, nil
}

// send authenticates against the smtp server, builds an email and sends it
// to the address provided.
func (m *Manager) send(_ context.Context, eml, subj, data string) {
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
func (m *Manager) SendAccountActivation(ctx context.Context, eml, tok string) {
	e := hermes.Email{
		Body: hermes.Body{
			Title: "Welcome!",
			Intros: []string{
				"We're very excited to have you on board.",
			},
			Actions: []hermes.Action{
				{
					Instructions: "To activatate your account, please click here:",
					Button: hermes.Button{
						Text: "Activate",
						Link: m.links.Prep(
							httpflow.LinkActivation, tok),
					},
				},
				{
					Instructions: "Wrong email address? Please click here:",
					Button: hermes.Button{
						Text: "Cancel",
						Link: m.links.Prep(
							httpflow.LinkActivationCancel, tok),
					},
				},
			},
		},
	}

	eBody, err := m.herm.GenerateHTML(e)
	if err != nil {
		m.onError(err)
	}

	subj := fmt.Sprintf("Welcome to %s", m.herm.Product.Name)

	m.send(ctx, eml, subj, eBody)
}

// SendEmailVerification sends an email regarding new email verification with
// the token, embedded into a full URL, to the specified email address.
func (m *Manager) SendEmailVerification(ctx context.Context, eml, tok string) {
	e := hermes.Email{
		Body: hermes.Body{
			Title: "Just one more step...",
			Actions: []hermes.Action{
				{
					Instructions: "To verify your new email address, please click here:",
					Button: hermes.Button{
						Text: "Verify",
						Link: m.links.Prep(
							httpflow.LinkVerification, tok),
					},
				},
				{
					Instructions: "Wrong email address? Please click here:",
					Button: hermes.Button{
						Text: "Cancel",
						Link: m.links.Prep(
							httpflow.LinkVerificationCancel, tok),
					},
				},
			},
		},
	}

	eBody, err := m.herm.GenerateHTML(e)
	if err != nil {
		m.onError(err)
	}

	m.send(ctx, eml, "Email address verification", eBody)
}

// SendEmailChanged sends an email to the old email address (first parameter)
// about a new email address being set (second parameter).
func (m *Manager) SendEmailChanged(ctx context.Context, oEml, nEml string) {
	e := hermes.Email{
		Body: hermes.Body{
			Title: "Your email address was successfully changed.",
			Intros: []string{
				fmt.Sprintf("From now on the main email address will be: %s", nEml), // TODO obfuscate email?
			},
		},
	}

	eBody, err := m.herm.GenerateHTML(e)
	if err != nil {
		m.onError(err)
	}

	m.send(ctx, oEml, "Email address changed", eBody)
}

// SendRecovery sends an email regarding account recovery with
// the token, embedded into a full URL, to the specified email address.
func (m *Manager) SendRecovery(ctx context.Context, eml, tok string) {
	e := hermes.Email{
		Body: hermes.Body{
			Title: "Trying to recover access your account?",
			Actions: []hermes.Action{
				{
					Instructions: "To recover access to your account, please click here:",
					Button: hermes.Button{
						Text: "Recover",
						Link: m.links.Prep(
							httpflow.LinkRecovery, tok),
					},
				},
				{
					Instructions: "Wrong email address? Please click here:",
					Button: hermes.Button{
						Text: "Cancel",
						Link: m.links.Prep(
							httpflow.LinkRecoveryCancel, tok),
					},
				},
			},
		},
	}

	eBody, err := m.herm.GenerateHTML(e)
	if err != nil {
		m.onError(err)
	}

	m.send(ctx, eml, "Password reset", eBody)
}

// SendAccountDeleted sends an email regarding successful account deletion to
// the specified email address.
func (m *Manager) SendAccountDeleted(ctx context.Context, eml string) {
	e := hermes.Email{
		Body: hermes.Body{
			Title: "Your account was successfully deleted.",
			Intros: []string{
				"We're sad to see you go, but you are welcome any time!",
			},
		},
	}

	eBody, err := m.herm.GenerateHTML(e)
	if err != nil {
		m.onError(err)
	}

	m.send(ctx, eml, "Account deleted", eBody)
}

// SendPasswordChanged sends an email notifying about a successful
// password change to the specified email address.
// Last parameter specifies whether the password was changed during
// the recovery process or not.
func (m *Manager) SendPasswordChanged(ctx context.Context, eml string, recov bool) {
	var (
		e    hermes.Email
		subj string
	)

	if recov {
		subj = "Password successfully reset"
		e = hermes.Email{
			Body: hermes.Body{
				Title: "Password was successfully reset.",
				Intros: []string{
					"You can log in to your account any time with your new password.",
				},
			},
		}
	} else {
		subj = "Password changed"
		e = hermes.Email{
			Body: hermes.Body{
				Title: "Password changed.",
				Intros: []string{
					"You can log in to your account any time with your new password.",
				},
			},
		}
	}

	eBody, err := m.herm.GenerateHTML(e)
	if err != nil {
		m.onError(err)
	}

	m.send(ctx, eml, subj, eBody)
}
