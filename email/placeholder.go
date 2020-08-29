package email

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/swithek/httpflow"
)

// Placeholder is a drop-in no-op replacement of a working email sender.
type Placeholder struct {
	log   zerolog.Logger
	links httpflow.Links
}

// NewPlaceholder creates a new email service placeholder instance.
func NewPlaceholder(log zerolog.Logger, ll httpflow.Links) Placeholder {
	return Placeholder{
		log:   log,
		links: ll,
	}
}

// SendAccountActivation should send an email regarding account
// activation with the token, embedded into a full URL, to the
// specified email address.
func (p Placeholder) SendAccountActivation(_ context.Context, eml, tok string) {
	if p.links.Exist(httpflow.LinkActivation) {
		p.log.Info().Msgf("Activate account: %s\n", p.links.Prep(httpflow.LinkActivation, tok))
	}
}

// SendEmailVerification should send an email regarding new email
// verification with the token, embedded into a full URL, to the
// specified email address.
func (p Placeholder) SendEmailVerification(_ context.Context, eml, tok string) {
	if p.links.Exist(httpflow.LinkVerification) {
		p.log.Info().Msgf("Verify new email: %s\n", p.links.Prep(httpflow.LinkVerification, tok))
	}
}

// SendEmailChanged should send an email to the old email
// address (first parameter) about a new email address
// being set (second parameter).
func (p Placeholder) SendEmailChanged(_ context.Context, oEml, nEml string) {
	p.log.Info().Msgf("Email was changed from \"%s\" to \"%s\"\n", oEml, nEml)
}

// SendRecovery should send an email regarding account recovery with
// the token, embedded into a full URL, to the specified email address.
func (p Placeholder) SendRecovery(_ context.Context, eml, tok string) {
	if p.links.Exist(httpflow.LinkRecovery) {
		p.log.Info().Msgf("Recover access to your account: %s\n", p.links.Prep(httpflow.LinkRecovery, tok))
	}
}

// SendAccountDeleted should send an email regarding successful account
// deletion to the specified email address.
func (p Placeholder) SendAccountDeleted(ctx context.Context, eml string) {
	p.log.Info().Msgf("\"%s\" account was deleted\n", eml)
}

// SendPasswordChanged should send an email notifying about a successful
// password change to the specified email address.
// Last parameter specifies whether the password was changed during
// the recovery process or not.
func (p Placeholder) SendPasswordChanged(ctx context.Context, eml string, recov bool) {
	p.log.Info().Msgf("\"%s\" account password was changed\n", eml)
}
