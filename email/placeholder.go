package email

import (
	"context"
	"log"

	"github.com/swithek/httpflow"
)

// Placeholder is a drop-in no-op replacement of a working email sender.
type Placeholder struct {
	log   *log.Logger
	links httpflow.Links
}

// NewPlaceholder creates a new email service placeholder instance.
func NewPlaceholder(l *log.Logger, ll httpflow.Links) Placeholder {
	return Placeholder{
		log:   l,
		links: ll,
	}
}

// SendAccountActivation should send an email regarding account
// activation with the token, embedded into a full URL, to the
// specified email address.
func (p Placeholder) SendAccountActivation(_ context.Context, eml, tok string) {
	if p.log != nil && p.links.Exist(httpflow.LinkActivation) {
		p.log.Printf("Activate account: %s\n", p.links.Prep(httpflow.LinkActivation, tok))
	}
}

// SendEmailVerification should send an email regarding new email
// verification with the token, embedded into a full URL, to the
// specified email address.
func (p Placeholder) SendEmailVerification(_ context.Context, eml, tok string) {
	if p.log != nil && p.links.Exist(httpflow.LinkVerification) {
		p.log.Printf("Verify new email: %s\n", p.links.Prep(httpflow.LinkVerification, tok))
	}
}

// SendEmailChanged should send an email to the old email
// address (first parameter) about a new email address
// being set (second parameter).
func (p Placeholder) SendEmailChanged(_ context.Context, oEml, nEml string) {
	if p.log != nil {
		p.log.Printf("Email was changed from \"%s\" to \"%s\"\n", oEml, nEml)
	}
}

// SendRecovery should send an email regarding account recovery with
// the token, embedded into a full URL, to the specified email address.
func (p Placeholder) SendRecovery(_ context.Context, eml, tok string) {
	if p.log != nil && p.links.Exist(httpflow.LinkRecovery) {
		p.log.Printf("Recover access to your account: %s\n", p.links.Prep(httpflow.LinkRecovery, tok))
	}
}

// SendAccountDeleted should send an email regarding successful account
// deletion to the specified email address.
func (p Placeholder) SendAccountDeleted(ctx context.Context, eml string) {
	if p.log != nil {
		p.log.Printf("\"%s\" account was deleted\n", eml)
	}
}

// SendPasswordChanged should send an email notifying about a successful
// password change to the specified email address.
// Last parameter specifies whether the password was changed during
// the recovery process or not.
func (p Placeholder) SendPasswordChanged(ctx context.Context, eml string, recov bool) {
	if p.log != nil {
		p.log.Printf("\"%s\" account password was changed\n", eml)
	}
}
