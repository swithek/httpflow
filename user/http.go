package user

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/swithek/httpflow"
	"github.com/swithek/sessionup"
)

var (
	// ErrNotActivated is returned when an action which is allowed only
	// by activated users is performed.
	ErrNotActivated = httpflow.NewError(nil, http.StatusForbidden, "not activated")
)

var (
	// SessionDuration is the default / recommended session duration
	// value.
	SessionDuration = time.Hour * 24 * 30 //nolint:gochecknoglobals // used as a constant
)

// Handler holds dependencies required for user management.
//go:generate moq -out ./mock_test.go . DB EmailSender
type Handler struct {
	log     zerolog.Logger
	db      DB
	email   EmailSender
	session struct {
		manager  *sessionup.Manager
		duration time.Duration
	}
	token struct {
		verif TokenLifetime
		recov TokenLifetime
	}
	ext struct { // behaviour extensions, useful for custom logic
		parse       Parser
		create      Creator
		loginCheck  LoginCheck
		deleteCheck DeleteCheck
	}
}

// setter is used to set Handler configuration options.
type setter func(*Handler)

// SetSessionDuration sets the duration of persistent sessions.
func SetSessionDuration(sd time.Duration) setter { //nolint:golint // setter must remain private
	return func(h *Handler) {
		h.session.duration = sd
	}
}

// SetVerificationLifetime sets token time values for verification process.
func SetVerificationLifetime(t TokenLifetime) setter { //nolint:golint // setter must remain private
	return func(h *Handler) {
		h.token.verif = t
	}
}

// SetRecoveryLifetime sets token time values for recovery process.
func SetRecoveryLifetime(t TokenLifetime) setter { //nolint:golint // setter must remain private
	return func(h *Handler) {
		h.token.recov = t
	}
}

// SetParser sets a function that will be used to parse user's request input.
func SetParser(p Parser) setter { //nolint:golint // setter must remain private
	return func(h *Handler) {
		h.ext.parse = p
	}
}

// SetCreator sets a function that will be used to construct a new user.
func SetCreator(c Creator) setter { //nolint:golint // setter must remain private
	return func(h *Handler) {
		h.ext.create = c
	}
}

// SetLoginCheck sets a function that will be called before user auth.
func SetLoginCheck(c LoginCheck) setter { //nolint:golint // setter must remain private
	return func(h *Handler) {
		h.ext.loginCheck = c
	}
}

// SetDeleteCheck sets a function that will be called before user deletion.
func SetDeleteCheck(c DeleteCheck) setter { //nolint:golint // setter must remain private
	return func(h *Handler) {
		h.ext.deleteCheck = c
	}
}

// NewHandler creates a new handler instance with the options provided.
func NewHandler(log zerolog.Logger, db DB, es EmailSender, sm *sessionup.Manager, ss ...setter) *Handler {
	h := &Handler{
		log:   log,
		db:    db,
		email: es,
	}
	h.session.manager = sm

	h.Defaults()

	for _, s := range ss {
		s(h)
	}

	return h
}

// Defaults sets all optional handler's values to sane defaults.
func (h *Handler) Defaults() {
	h.session.duration = SessionDuration
	h.token.verif = VerifLifetime
	h.token.recov = RecovLifetime
	h.ext.parse = DefaultParser
	h.ext.create = DefaultCreator
	h.ext.loginCheck = DefaultLoginCheck(true)
	h.ext.deleteCheck = DefaultDeleteCheck
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
type Creator func(ctx context.Context, inp Inputer) (User, error)

// DefaultCreator creates a new user with only core data fields from the
// provided input.
func DefaultCreator(_ context.Context, inp Inputer) (User, error) {
	return NewCore(inp)
}

// LoginCheck is a function that should be used for custom user data
// checks before authentication.
// Used before non-registration type authentication (e.g. login).
type LoginCheck func(ctx context.Context, usr User) error

// DefaultLoginCheck checks whether the user has to be activated before
// authentication or not.
func DefaultLoginCheck(open bool) LoginCheck {
	return func(_ context.Context, usr User) error {
		if !open && !usr.ExposeCore().IsActivated() {
			return ErrNotActivated
		}

		return nil
	}
}

// DeleteCheck is function that should be used for custom account checks
// before user deletion (e.g. check whether at least one admin user exists
// or not).
type DeleteCheck func(ctx context.Context, usr User) error

// DefaultDeleteCheck does nothing, just fills the space and
// contemplates life.
func DefaultDeleteCheck(_ context.Context, _ User) error {
	return nil
}

// ServeHTTP handles all core user routes.
// Registration is allowed (use Router method to override this).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Router(true).ServeHTTP(w, r)
}

// Router returns a chi router instance with all core user
// routes. Bool parameter determines whether registration is allowed
// or not (useful for applications where users are invited rather
// than allowed to register themselves).
func (h *Handler) Router(open bool) chi.Router {
	r := h.BasicRouter(open)

	r.Group(func(sr chi.Router) {
		sr.Use(h.session.manager.Auth)
		sr.Get("/", h.Fetch)
		sr.Patch("/", h.Update)
		sr.Delete("/", h.Delete)
	})

	r.Route("/sessions", func(sr chi.Router) {
		sr.Use(h.session.manager.Auth)
		sr.Get("/", h.FetchSessions)
		sr.Delete("/{id}", h.RevokeSession)
		sr.Delete("/", h.RevokeOtherSessions)
	})

	r.Route("/activation", func(sr chi.Router) {
		sr.With(h.session.manager.Auth).Put("/", h.ResendVerification)
		sr.Get("/", h.Verify)
		sr.Get("/cancel", h.CancelVerification)
	})

	r.Route("/verification", func(sr chi.Router) {
		sr.With(h.session.manager.Auth).Put("/", h.ResendVerification)
		sr.Get("/", h.Verify)
		sr.Get("/cancel", h.CancelVerification)
	})

	r.Route("/recovery", func(sr chi.Router) {
		sr.Put("/", h.InitRecovery)
		sr.Post("/", h.Recover)
		sr.Get("/", h.PingRecovery)
		sr.Get("/cancel", h.CancelRecovery)
	})

	r.NotFound(httpflow.NotFound(h.log))
	r.MethodNotAllowed(httpflow.MethodNotAllowed(h.log))

	return r
}

// BasicRouter returns a chi router instance with basic user
// routes. Bool parameter determines whether registration is allowed or
// not (useful for applications where users are invited rather than
// allowed to register themselves).
func (h *Handler) BasicRouter(open bool) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.AllowContentType("application/json"))

	if open {
		r.Post("/", h.Register)
	}

	r.Route("/auth", func(sr chi.Router) {
		sr.Post("/", h.LogIn)
		sr.With(h.session.manager.Auth).Delete("/", h.LogOut)
	})

	r.NotFound(httpflow.NotFound(h.log))
	r.MethodNotAllowed(httpflow.MethodNotAllowed(h.log))

	return r
}

// SetupLinks creates a link string map that should be used for email
// sending, etc.
// The parameter specifies the root of the link, example:
// "http://yoursite.com/user"
func SetupLinks(r string) map[httpflow.LinkKey]string {
	return map[httpflow.LinkKey]string{
		httpflow.LinkActivation:         r + "/activate?token=%s",
		httpflow.LinkActivationCancel:   r + "/activate/cancel?token=%s",
		httpflow.LinkVerification:       r + "/verify?token=%s",
		httpflow.LinkVerificationCancel: r + "/verify/cancel?token=%s",
		httpflow.LinkRecovery:           r + "/recover?token=%s",
		httpflow.LinkRecoveryCancel:     r + "/recover/cancel?token=%s",
	}
}

// Register handles new user's creation and insertion into the data store.
// On successful execution, a session will be created and account activation
// email will sent.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	inp, err := h.ext.parse(r)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	ctx := r.Context()

	usr, err := h.ext.create(ctx, inp)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usrC := usr.ExposeCore()

	tok, err := usrC.InitVerification(h.token.verif)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err = h.db.CreateUser(ctx, usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	sm := h.session.manager
	if inp.ExposeCore().RememberMe {
		sm = sm.Clone(sessionup.ExpiresIn(h.session.duration))
	}

	if err = sm.Init(w, r, usrC.ID.String()); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	go h.email.SendAccountActivation(context.Background(), usrC.Email, tok)

	w.Header().Add("Location", "/") // id will be retrieved from the session
	httpflow.Respond(h.log, w, r, usr, http.StatusCreated)
}

// LogIn handles user's credentials checking and new session creation.
// On successful execution, a session will be created.
func (h *Handler) LogIn(w http.ResponseWriter, r *http.Request) {
	var cInp CoreInput
	if err := httpflow.DecodeJSON(r, &cInp); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err := CheckEmail(cInp.Email); err != nil {
		httpflow.RespondError(h.log, w, r, ErrInvalidCredentials)
		return
	}

	ctx := r.Context()

	usr, err := h.db.FetchUserByEmail(ctx, cInp.Email)
	if err != nil {
		if errors.Is(err, httpflow.ErrNotFound) {
			err = ErrInvalidCredentials
		}

		httpflow.RespondError(h.log, w, r, err)

		return
	}

	if err = h.ext.loginCheck(ctx, usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usrC := usr.ExposeCore()

	if !usrC.IsPasswordCorrect(cInp.Password) {
		httpflow.RespondError(h.log, w, r, ErrInvalidCredentials)
		return
	}

	usrC.Recovery.Clear()

	if err = h.db.UpdateUser(ctx, usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	sm := h.session.manager
	if cInp.RememberMe {
		sm = sm.Clone(sessionup.ExpiresIn(h.session.duration))
	}

	if err = sm.Init(w, r, usrC.ID.String()); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	httpflow.Respond(h.log, w, r, usr, http.StatusOK)
}

// LogOut handles user's active session revokation.
func (h *Handler) LogOut(w http.ResponseWriter, r *http.Request) {
	if err := h.session.manager.Revoke(r.Context(), w); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// Fetch handles user's data retrieval.
func (h *Handler) Fetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, id, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usr, err := h.db.FetchUserByID(ctx, id)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	httpflow.Respond(h.log, w, r, usr, http.StatusOK)
}

// Update handles user's data update in the data store.
// On email address change, a verification email will be sent to the new
// address.
// On password change, all other sessions will be destroyed and email sent.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, id, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	inp, err := h.ext.parse(r)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usr, err := h.db.FetchUserByID(ctx, id)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	upd, err := usr.ApplyInput(inp)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usrC := usr.ExposeCore()
	updC := upd.ExposeCore()

	var tok string

	if updC.Email {
		tok, err = usrC.InitVerification(h.token.verif)
		if err != nil {
			httpflow.RespondError(h.log, w, r, err)
			return
		}
	}

	if updC.Password {
		if err := h.session.manager.RevokeOther(ctx); err != nil {
			httpflow.RespondError(h.log, w, r, err)
			return
		}
	}

	if err = h.db.UpdateUser(ctx, usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if updC.Password {
		go h.email.SendPasswordChanged(context.Background(), usrC.Email, false)
	}

	if tok != "" {
		go h.email.SendEmailVerification(context.Background(),
			usrC.UnverifiedEmail.String, tok)
	}

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// Delete handles user's data removal from the data store.
// On successful deletion, an email will be sent.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, id, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	var cInp CoreInput
	if err = httpflow.DecodeJSON(r, &cInp); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usr, err := h.db.FetchUserByID(ctx, id)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err = h.ext.deleteCheck(ctx, usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usrC := usr.ExposeCore()

	if !usrC.IsPasswordCorrect(cInp.Password) {
		httpflow.RespondError(h.log, w, r, ErrInvalidCredentials)
		return
	}

	if err = h.session.manager.RevokeAll(ctx, w); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err = h.db.DeleteUserByID(ctx, id); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	go h.email.SendAccountDeleted(context.Background(), usrC.Email)

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// FetchSessions retrieves all sessions of the same user.
func (h *Handler) FetchSessions(w http.ResponseWriter, r *http.Request) {
	ss, err := h.session.manager.FetchAll(r.Context())
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if len(ss) == 0 {
		httpflow.RespondError(h.log, w, r, httpflow.ErrNotFound)
		return
	}

	httpflow.Respond(h.log, w, r, ss, http.StatusOK)
}

// RevokeSession revokes one specific session of the user with the
// active session in the request's context.
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ses, _, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	id, err := httpflow.ExtractParam(r, "id")
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if ses.ID == id {
		err = httpflow.NewError(nil, http.StatusBadRequest, "current session cannot be revoked")
		httpflow.RespondError(h.log, w, r, err)

		return
	}

	if err = h.session.manager.RevokeByIDExt(ctx, id); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// RevokeOtherSessions revokes all sessions of the same user besides the
// current one.
func (h *Handler) RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	if err := h.session.manager.RevokeOther(r.Context()); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// ResendVerification attempts to send and generate the verification token
// once more.
// On successful execution, either account activation or new email verification
// will be sent.
func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, id, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usr, err := h.db.FetchUserByID(ctx, id)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usrC := usr.ExposeCore()

	if usrC.Verification.IsEmpty() {
		err = httpflow.NewError(nil, http.StatusBadRequest, "verification has not been initiated")
		httpflow.RespondError(h.log, w, r, err)

		return
	}

	tok, err := usrC.InitVerification(h.token.verif)
	if err != nil {
		if errors.Is(err, ErrTooManyTokens) {
			secs := int(time.Until(usrC.Verification.NextAt.Time).Seconds())
			w.Header().Add("Retry-After", strconv.Itoa(secs))
		}

		httpflow.RespondError(h.log, w, r, err)

		return
	}

	if err = h.db.UpdateUser(ctx, usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if usrC.IsActivated() {
		go h.email.SendEmailVerification(context.Background(), usrC.UnverifiedEmail.String, tok)
	} else {
		go h.email.SendAccountActivation(context.Background(), usrC.Email, tok)
	}

	httpflow.Respond(h.log, w, r, nil, http.StatusAccepted)
}

// Verify checks whether the token in the URL is valid and activates either
// user's account or their new email address.
// If new email was changed and verified, an email will be sent to the old
// address about the change.
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	usrC := usr.ExposeCore()
	oEml := usrC.Email

	if err = usrC.Verify(tok); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	ctx := r.Context()

	if err = h.db.UpdateUser(ctx, usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if oEml != usrC.Email { // email was changed
		go h.email.SendEmailChanged(context.Background(), oEml, usrC.Email)
	}

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// CancelVerification checks whether the token in the URL is valid and stops
// active verification token from further processing.
func (h *Handler) CancelVerification(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err = usr.ExposeCore().CancelVerification(tok); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err = h.db.UpdateUser(r.Context(), usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// InitRecovery initializes recovery token for the user associated with the
// provided email address and sends to the same address.
// On successful execution, a recovery email will be sent to the email
// provided.
func (h *Handler) InitRecovery(w http.ResponseWriter, r *http.Request) {
	var cInp CoreInput
	if err := httpflow.DecodeJSON(r, &cInp); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err := CheckEmail(cInp.Email); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	// if email is not found, etc. we don't want the user or attacker
	// to know this.
	respErr := func(err error) {
		if httpflow.ErrorCode(err) < 500 {
			httpflow.Respond(h.log, w, r, nil, http.StatusAccepted)
			return
		}

		httpflow.RespondError(h.log, w, r, err)
	}

	ctx := r.Context()

	usr, err := h.db.FetchUserByEmail(ctx, cInp.Email)
	if err != nil {
		respErr(err)
		return
	}

	usrC := usr.ExposeCore()

	tok, err := usrC.InitRecovery(h.token.recov)
	if err != nil {
		if errors.Is(err, ErrTooManyTokens) {
			secs := int(time.Until(usrC.Recovery.NextAt.Time).Seconds())
			w.Header().Add("Retry-After", strconv.Itoa(secs))
		}

		httpflow.RespondError(h.log, w, r, err)

		return
	}

	if err = h.db.UpdateUser(ctx, usr); err != nil {
		respErr(err)
		return
	}

	go h.email.SendAccountRecovery(context.Background(), usrC.Email, tok)

	httpflow.Respond(h.log, w, r, nil, http.StatusAccepted)
}

// Recover checks the token in the URL and applies the provided password
// to the user account data structure.
// On successful execution, an email will be sent notifying about password
// change.
func (h *Handler) Recover(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	var cInp CoreInput
	if err = httpflow.DecodeJSON(r, &cInp); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	ctx := r.Context()
	usrC := usr.ExposeCore()

	if err = usrC.Recover(tok, cInp.Password); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	err = h.session.manager.RevokeByUserKey(ctx, usrC.ID.String())
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err = h.db.UpdateUser(ctx, usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	go h.email.SendPasswordChanged(context.Background(), usrC.Email, true)

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// PingRecovery only checks whether the token in the URL is valid or not; no
// writable modifications are being done.
func (h *Handler) PingRecovery(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err = usr.ExposeCore().Recovery.Check(tok); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// CancelRecovery checks whether the token in the URL is valid and stops
// active verification token from further processing.
func (h *Handler) CancelRecovery(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
	if err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err = usr.ExposeCore().CancelRecovery(tok); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	if err = h.db.UpdateUser(r.Context(), usr); err != nil {
		httpflow.RespondError(h.log, w, r, err)
		return
	}

	httpflow.Respond(h.log, w, r, nil, http.StatusNoContent)
}

// FetchByToken extracts the token from request's URL, retrieves a user by ID
// embedded in the token and returns user's account instance, raw token and
// optionally an error.
func (h *Handler) FetchByToken(r *http.Request) (User, string, error) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		return nil, "", httpflow.NewError(nil, http.StatusBadRequest, "token not found")
	}

	tok, id, err := FromFullToken(tok)
	if err != nil {
		return nil, "", err
	}

	usr, err := h.db.FetchUserByID(r.Context(), id)
	if err != nil {
		return nil, "", err
	}

	return usr, tok, nil
}

// DB is an interface which should be implemented by the user data
// store layer.
type DB interface {
	// UserStats should return users' data statistics from the underlying
	// data store.
	UserStats(ctx context.Context) (Stats, error)

	// CreateUser should insert the freshly created user into the underlying
	// data store.
	CreateUser(ctx context.Context, usr User) error

	// FetchManyUsers should retrieve multiple users from the underlying data
	// store by the provided query.
	FetchManyUsers(ctx context.Context, qr httpflow.Query) ([]User, error)

	// FetchUserByID should retrieve a user from the underlying data store
	// by their ID.
	FetchUserByID(ctx context.Context, id xid.ID) (User, error)

	// FetchUserByEmail should retrieve a user from the underlying data store
	// by their email address.
	FetchUserByEmail(ctx context.Context, eml string) (User, error)

	// UpdateUser should update user's data in the underlying data store.
	UpdateUser(ctx context.Context, usr User) error

	// DeleteUserByID should delete a user from the underlying data store
	// by their ID.
	DeleteUserByID(ctx context.Context, id xid.ID) error
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

	// SendAccountRecovery should send an email regarding account recovery with
	// the token, embedded into a full URL, to the specified email address.
	SendAccountRecovery(ctx context.Context, eml, tok string)

	// SendAccountDeleted should send an email regarding successful account
	// deletion to the specified email address.
	SendAccountDeleted(ctx context.Context, eml string)

	// SendPasswordChanged should send an email notifying about a successful
	// password change to the specified email address.
	// Last parameter specifies whether the password was changed during
	// the recovery process or not.
	SendPasswordChanged(ctx context.Context, eml string, recov bool)
}
