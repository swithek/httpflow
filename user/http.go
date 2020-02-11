package user

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/swithek/httpflow"
	"github.com/swithek/sessionup"
)

var (
	// ErrUnauthorized is returned when request's context contains invalid
	// session.
	ErrUnauthorized = httpflow.NewError(nil, http.StatusUnauthorized,
		"unauthorized")
)

// Handler holds dependencies required for user management.
//go:generate moq -out ./http_mock_test.go . Database EmailSender
type Handler struct {
	sessions *sessionup.Manager
	sesDur   time.Duration
	db       Database
	email    EmailSender

	onError httpflow.ErrorExec
	parse   Parser
	create  Creator

	verif TokenTimes
	recov TokenTimes
}

// Parser is a function that should be used for custom input parsing.
// Used only during user update process and registration.
type Parser func(r *http.Request) (Inputer, error)

// DefaultParser marshals incoming request's body into a core input
// data structure.
func DefaultParser(r *http.Request) (Inputer, error) {
	var cInp CoreInput
	if err := httpflow.DecodeJSON(r, &cInp); err != nil {
		return nil, err
	}

	return cInp, nil
}

// Creator is a function that should be used for custom user creation.
// Used only during registration.
type Creator func(inp Inputer) (User, error)

// DefaultCreator creates a new user with only core data fields from the
// provided input.
func DefaultCreator(inp Inputer) (User, error) {
	usr := &Core{}
	usr.Init(inp)
	return usr, nil
}

// NewHandler creates a new user http handler.
func NewHandler(sm *sessionup.Manager, sd time.Duration, db Database,
	email EmailSender, onError httpflow.ErrorExec, parse Parser,
	create Creator, verif TokenTimes, recov TokenTimes) *Handler {
	return &Handler{
		sessions: sm,
		sesDur:   sd,
		db:       db,
		email:    email,
		onError:  onError,
		parse:    parse,
		create:   create,
		verif:    verif,
		recov:    recov,
	}
}

// ServeHTTP returns a handler with all core user routes.
func (h *Handler) ServeHTTP() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.AllowContentType("application/json"))

	r.Post("/new", h.Register)
	r.Route("/auth", func(sr chi.Router) {
		sr.Post("/", h.LogIn)
		sr.With(h.sessions.Auth).Delete("/", h.LogOut)
	})

	r.Group(func(sr chi.Router) {
		sr.Use(h.sessions.Auth)
		sr.Get("/", h.Fetch)
		sr.Patch("/", h.Update)
		sr.Delete("/", h.Delete)
	})

	r.Route("/sessions", func(sr chi.Router) {
		sr.Use(h.sessions.Auth)
		sr.Get("/", h.FetchSessions)
		sr.Delete("/{id}", h.RevokeSession)
		sr.Delete("/", h.RevokeOtherSessions)
	})

	r.Route("/verif", func(sr chi.Router) {
		sr.With(h.sessions.Auth).Put("/", h.ResendVerification)
		sr.Post("/{token}", h.Verify)
		sr.Get("/{token}/cancel", h.CancelVerification)
	})

	r.Route("/recov", func(sr chi.Router) {
		sr.Put("/", h.InitRecovery)
		sr.Post("/{token}", h.Recover)
		sr.Get("/{token}", h.PingRecovery)
		sr.Get("/{token}/cancel", h.CancelRecovery)
	})

	return r
}

// SetupLinks creates a link string map that should be used for email
// sending etc.
// The parameter specifies the root of the link, example:
// "http://yoursite.com/user"
func SetupLinks(r string) map[httpflow.LinkKey]string {
	return map[httpflow.LinkKey]string{
		httpflow.LinkActivation:         r + "/activ?token=%s",
		httpflow.LinkActivationCancel:   r + "/activ/cancel?token=%s",
		httpflow.LinkVerification:       r + "/verif?token=%s",
		httpflow.LinkVerificationCancel: r + "/verif/cancel?token=%s",
		httpflow.LinkRecovery:           r + "/recov?token=%s",
		httpflow.LinkRecoveryCancel:     r + "/recov/cancel?token=%s",
	}
}

// Register handles new user's creation and insertion into the data store.
// On successful execution, a session will be created and account activation
// email will sent.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	inp, err := h.parse(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usr, err := h.create(inp)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.Core()

	tok, err := usrC.InitVerification(h.verif)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	ctx := r.Context()

	if err = h.db.Create(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	sessions := h.sessions
	if inp.Core().RememberMe {
		sessions = sessions.Clone(sessionup.ExpiresIn(h.sesDur))
	}

	if err = sessions.Init(w, r, usrC.ID.String()); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	go h.email.SendAccountActivation(ctx, usrC.Email, tok)

	httpflow.Respond(w, r, nil, http.StatusCreated, h.onError)
}

// LogIn handles user's credentials checking and new session creation.
// On successful execution, a session will be created.
func (h *Handler) LogIn(w http.ResponseWriter, r *http.Request) {
	var cInp CoreInput
	if err := httpflow.DecodeJSON(r, &cInp); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err := CheckEmail(cInp.Email); err != nil {
		httpflow.RespondError(w, r, ErrInvalidCredentials, h.onError)
		return
	}

	ctx := r.Context()

	usr, err := h.db.FetchByEmail(ctx, cInp.Email)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.Core()

	if !usrC.IsPasswordCorrect(cInp.Password) {
		httpflow.RespondError(w, r, ErrInvalidCredentials, h.onError)
		return
	}

	usrC.Recovery.Clear()

	if err = h.db.Update(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	sessions := h.sessions
	if cInp.RememberMe {
		sessions = sessions.Clone(sessionup.ExpiresIn(h.sesDur))
	}

	if err = sessions.Init(w, r, usrC.ID.String()); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// LogOut handles user's active session revokation.
func (h *Handler) LogOut(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.Revoke(r.Context(), w); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// Fetch handles user's data retrieval.
func (h *Handler) Fetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ses, ok := sessionup.FromContext(ctx)
	if !ok {
		httpflow.RespondError(w, r, ErrUnauthorized, h.onError)
		return
	}

	usr, err := h.db.FetchByID(ctx, ses.UserKey)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	httpflow.Respond(w, r, usr, http.StatusOK, h.onError)
}

// Update handles user's data update in the data store.
// On email address change, a verification email will be sent to the new
// address.
// On password change, all other sessions will be destroyed and email sent.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ses, ok := sessionup.FromContext(ctx)
	if !ok {
		httpflow.RespondError(w, r, ErrUnauthorized, h.onError)
		return
	}

	inp, err := h.parse(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usr, err := h.db.FetchByID(ctx, ses.UserKey)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	upd, err := usr.ApplyInput(inp)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.Core()
	updC := upd.Core()

	var tok string

	if updC.Email {
		tok, err = usrC.InitVerification(h.verif)
		if err != nil {
			httpflow.RespondError(w, r, err, h.onError)
			return
		}
	}

	if err = h.db.Update(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if updC.Password {
		if err := h.sessions.RevokeOther(r.Context()); err != nil {
			httpflow.RespondError(w, r, err, h.onError)
			return
		}

		go h.email.SendPasswordChanged(ctx, usrC.Email, false)
	}

	if tok != "" {
		go h.email.SendEmailVerification(ctx, usrC.UnverifiedEmail, tok)
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// Delete handles user's data removal from the data store.
// On successful deletion, an email will be sent.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ses, ok := sessionup.FromContext(ctx)
	if !ok {
		httpflow.RespondError(w, r, ErrUnauthorized, h.onError)
		return
	}

	var cInp CoreInput
	if err := httpflow.DecodeJSON(r, &cInp); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usr, err := h.db.FetchByID(ctx, ses.UserKey)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.Core()

	if !usrC.IsPasswordCorrect(cInp.Password) {
		httpflow.RespondError(w, r, ErrInvalidCredentials, h.onError)
		return
	}

	if err = h.db.DeleteByID(ctx, ses.UserKey); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.sessions.RevokeAll(ctx, w); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	go h.email.SendAccountDeleted(ctx, usrC.Email)

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// FetchSessions retrieves all sessions of the same user.
func (h *Handler) FetchSessions(w http.ResponseWriter, r *http.Request) {
	ss, err := h.sessions.FetchAll(r.Context())
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if len(ss) == 0 {
		httpflow.RespondError(w, r, httpflow.NewError(nil,
			http.StatusNotFound, "not found"), h.onError)
		return
	}

	httpflow.Respond(w, r, ss, http.StatusOK, h.onError)
}

// RevokeSession revokes one specific session of the user with the
// active session in the request's context.
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if ses, ok := sessionup.FromContext(ctx); !ok || ses.ID == id {
		httpflow.RespondError(w, r, httpflow.NewError(nil,
			http.StatusBadRequest,
			"current session cannot be revoked"), h.onError)
		return
	}

	if err := h.sessions.RevokeByID(ctx, id); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// RevokeOtherSessions revokes all sessions of the same user besides the
// current one.
func (h *Handler) RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.RevokeOther(r.Context()); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}
	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// ResendVerification attempts to send and generate the verification token
// once more.
// On successful execution, either account activation or new email verification
// will be sent.
func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ses, ok := sessionup.FromContext(ctx)
	if !ok {
		httpflow.RespondError(w, r, ErrUnauthorized, h.onError)
		return
	}

	usr, err := h.db.FetchByID(ctx, ses.UserKey)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.Core()

	if usrC.Verification.IsEmpty() {
		httpflow.RespondError(w, r, httpflow.NewError(nil,
			http.StatusBadRequest,
			"verification has not been initiated"), h.onError)
		return
	}

	tok, err := usrC.InitVerification(h.verif)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.Update(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if usrC.IsActivated() {
		go h.email.SendEmailVerification(ctx, usrC.UnverifiedEmail, tok)
	} else {
		go h.email.SendAccountActivation(ctx, usrC.Email, tok)
	}

	httpflow.Respond(w, r, nil, http.StatusAccepted, h.onError)
}

// Verify checks whether the token in the URL is valid and activates either
// user's account or their new email address.
// If new email was changed and verified, an email will be sent to the old
// address about the change.
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.Core()
	oEml := usrC.Email

	if err = usrC.Verify(tok); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	ctx := r.Context()

	if err = h.db.Update(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if oEml != usrC.Email { // email was changed
		go h.email.SendEmailChanged(ctx, oEml, usrC.Email)
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// CancelVerification checks whether the token in the URL is valid and stops
// active verification token from further processing.
func (h *Handler) CancelVerification(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = usr.Core().CancelVerification(tok); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.Update(r.Context(), usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// InitRecovery initializes recovery token for the user associated with the
// provided email address and sends to the same address.
// On successful execution, a recovery email will be sent to the email
// provided.
func (h *Handler) InitRecovery(w http.ResponseWriter, r *http.Request) {
	var cInp CoreInput
	if err := httpflow.DecodeJSON(r, &cInp); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err := CheckEmail(cInp.Email); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	ctx := r.Context()

	usr, err := h.db.FetchByEmail(ctx, cInp.Email)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.Core()

	tok, err := usrC.InitRecovery(h.recov)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.Update(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	go h.email.SendRecovery(ctx, usrC.Email, tok)

	httpflow.Respond(w, r, nil, http.StatusAccepted, h.onError)
}

// Recover checks the token in the URL and applies the provided password
// to the user account data structure.
// On successful execution, an email will be sent notifying about password
// change.
func (h *Handler) Recover(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	var cInp CoreInput
	if err = httpflow.DecodeJSON(r, &cInp); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	ctx := r.Context()
	usrC := usr.Core()

	if err = usrC.Recover(tok, cInp.Password); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.Update(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.sessions.RevokeByUserKey(ctx, usrC.ID.String()); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	go h.email.SendPasswordChanged(ctx, usrC.Email, true)

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// PingRecovery only checks whether the token in the URL is valid, no
// writable modifications are being done.
func (h *Handler) PingRecovery(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = usr.Core().Recovery.Check(tok); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// CancelRecovery checks whether the token in the URL is valid and stops
// active verification token from further processing.
func (h *Handler) CancelRecovery(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = usr.Core().CancelRecovery(tok); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.Update(r.Context(), usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// fetchByToken extracts the token from request's URL, retrieves a user by ID
// embedded in the token and returns user's account instance, raw token and
// optionally an error.
func (h *Handler) fetchByToken(r *http.Request) (User, string, error) {
	tok := chi.URLParam(r, "token")
	if tok == "" {
		return nil, "", httpflow.NewError(nil, http.StatusBadRequest,
			"token not found")
	}

	tok, id, err := FromFullToken(tok)
	if err != nil {
		return nil, "", err
	}

	usr, err := h.db.FetchByID(r.Context(), id.String())
	if err != nil {
		return nil, "", err
	}

	return usr, tok, nil
}

// Database is an interface which should be implemented by the user data
// store layer.
type Database interface {
	// Create should insert the freshly created user into the underlying
	// data store.
	Create(ctx context.Context, usr User) error

	// FetchByID should retrieve the user from the underlying data store
	// by their ID.
	FetchByID(ctx context.Context, id string) (User, error)

	// FetchByEmail should retrieve the user from the underlying data store
	// by their email address.
	FetchByEmail(ctx context.Context, eml string) (User, error)

	// Update should update user's data in the underlying data store.
	Update(ctx context.Context, usr User) error

	// DeleteByID should delete the user from the underlying data store
	// by their ID.
	DeleteByID(ctx context.Context, id string) error
}

// EmailSender is an interface which should be implemented by email
// sending service.
type EmailSender interface {
	// SendAccountActivation should send an email regarding account
	// activation with the token, embedded into a full URL, to the
	// specified email address.
	SendAccountActivation(ctx context.Context, eml, tok string)

	// SendEmailVerification should send an email regarding new email
	// verification with the token, embedded into a full URL, to the
	// specified email address.
	SendEmailVerification(ctx context.Context, eml, tok string)

	// SendEmailChanged should send an email to the old email
	// address (first parameter) about a new email address
	// being set (second parameter).
	SendEmailChanged(ctx context.Context, oEml, nEml string)

	// SendRecovery should send an email regarding account recovery with
	// the token, embedded into a full URL, to the specified email address.
	SendRecovery(ctx context.Context, eml, tok string)

	// SendAccountDeleted should send an email regarding successful account
	// deletion to the specified email address.
	SendAccountDeleted(ctx context.Context, eml string)

	// SendPasswordChanged should send an email notifying about a successful
	// password change to the specified email address.
	// Last parameter specifies whether the password was changed during
	// the recovery process or not.
	SendPasswordChanged(ctx context.Context, eml string, recov bool)
}
