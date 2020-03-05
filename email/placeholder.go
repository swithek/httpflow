package email

import "context"

// Placeholder is a drop-in no-op replacement of a working email sender.
type Placeholder struct {
}

// SendAccountActivation should send an email regarding account
// activation with the token, embedded into a full URL, to the
// specified email address.
func (p Placeholder) SendAccountActivation(ctx context.Context, eml string, tok string) {
	return
}

// SendEmailVerification should send an email regarding new email
// verification with the token, embedded into a full URL, to the
// specified email address.
func (p Placeholder) SendEmailVerification(ctx context.Context, eml string, tok string) {
	return
}

// SendEmailChanged should send an email to the old email
// address (first parameter) about a new email address
// being set (second parameter).
func (p Placeholder) SendEmailChanged(ctx context.Context, oEml string, nEml string) {
	return
}

// SendRecovery should send an email regarding account recovery with
// the token, embedded into a full URL, to the specified email address.
func (p Placeholder) SendRecovery(ctx context.Context, eml string, tok string) {
	return
}

// SendAccountDeleted should send an email regarding successful account
// deletion to the specified email address.
func (p Placeholder) SendAccountDeleted(ctx context.Context, eml string) {
	return
}

// SendPasswordChanged should send an email notifying about a successful
// password change to the specified email address.
// Last parameter specifies whether the password was changed during
// the recovery process or not.
func (p Placeholder) SendPasswordChanged(ctx context.Context, eml string, recov bool) {
	return
}
