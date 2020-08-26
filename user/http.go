package user

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/rs/xid"
	"github.com/swithek/httpflow"
	"github.com/swithek/sessionup"
)

var (
	// ErrNotActivated is returned when an action which is allowed only
	// by activated users is performed.
	ErrNotActivated = httpflow.NewError(nil, http.StatusForbidden, "not activated")
)

var (
	// SessionDuration is the default / recommended session duration value.
	SessionDuration = time.Hour * 24 * 30 //nolint:gochecknoglobals // used as a constant
)

// Handler holds dependencies required for user management.
//go:generate moq -out ./mock_test.go . DB EmailSender
type Handler struct {
	sessions *sessionup.Manager
	sesDur   time.Duration
	db       DB
	email    EmailSender

	onError httpflow.ErrorExec
	parse   Parser
	create  Creator
	gKeep   GateKeeper
	pDel    PreDeleter

	verif TokenTimes
	recov TokenTimes
}

// Setter is used to set Handler configuration options.
type Setter func(*Handler)

// SetSessionDuration sets the duration of permanent sessions.
func SetSessionDuration(sd time.Duration) Setter {
	return func(h *Handler) {
		h.sesDur = sd
	}
}

// SetErrorExec sets a function that will be used during critical errors
// detection.
func SetErrorExec(ex httpflow.ErrorExec) Setter {
	return func(h *Handler) {
		h.onError = ex
	}
}

// SetParser sets a function that will be used to parse user's request input.
func SetParser(p Parser) Setter {
	return func(h *Handler) {
		h.parse = p
	}
}

// SetCreator sets a function that will be used to construct a new user.
func SetCreator(c Creator) Setter {
	return func(h *Handler) {
		h.create = c
	}
}

// SetGateKeeper sets a function that will be called before user auth.
func SetGateKeeper(gk GateKeeper) Setter {
	return func(h *Handler) {
		h.gKeep = gk
	}
}

// SetPreDeleter sets a function that will be called before user deletion.
func SetPreDeleter(pd PreDeleter) Setter {
	return func(h *Handler) {
		h.pDel = pd
	}
}

// SetVerificationTimes sets token time values for verification process.
func SetVerificationTimes(t TokenTimes) Setter {
	return func(h *Handler) {
		h.verif = t
	}
}

// SetRecoveryTimes sets token time values for recovery process.
func SetRecoveryTimes(t TokenTimes) Setter {
	return func(h *Handler) {
		h.recov = t
	}
}

// NewHandler creates a new handler instance with the options provided.
func NewHandler(sm *sessionup.Manager, db DB, es EmailSender, ss ...Setter) *Handler {
	h := &Handler{
		sessions: sm,
		db:       db,
		email:    es,
	}

	h.Defaults()

	for _, s := range ss {
		s(h)
	}

	return h
}

// Defaults sets all optional handler's values to sane defaults.
func (h *Handler) Defaults() {
	h.sesDur = SessionDuration
	h.onError = httpflow.DefaultErrorExec
	h.parse = DefaultParser
	h.create = DefaultCreator
	h.gKeep = DefaultGateKeeper(true)
	h.pDel = DefaultPreDeleter
	h.verif = VerifTimes
	h.recov = RecovTimes
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

// GateKeeper is a function that should be used for custom user data
// checks before authentication.
// Used before non-registration type authentication (e.g. login).
type GateKeeper func(usr User) error

// DefaultGateKeeper checks whether the user has to be activated before
// authentication or not.
func DefaultGateKeeper(open bool) GateKeeper {
	return func(usr User) error {
		if !open && !usr.ExposeCore().IsActivated() {
			return ErrNotActivated
		}

		return nil
	}
}

// PreDeleter is function that should be used for custom account checks
// before user deletion (e.g. check whether at least one admin user exists
// or not).
type PreDeleter func(ctx context.Context, usr User) error

// DefaultPreDeleter does nothing, just fills the space and contemplates life.
func DefaultPreDeleter(_ context.Context, _ User) error {
	return nil
}

// ServeHTTP handles all core user routes.
// Registration is allowed (use Routes method to override this).
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

	r.Route("/activ", func(sr chi.Router) {
		sr.With(h.sessions.Auth).Put("/", h.ResendVerification)
		sr.Get("/", h.Verify)
		sr.Get("/cancel", h.CancelVerification)
	})

	r.Route("/verif", func(sr chi.Router) {
		sr.With(h.sessions.Auth).Put("/", h.ResendVerification)
		sr.Get("/", h.Verify)
		sr.Get("/cancel", h.CancelVerification)
	})

	r.Route("/recov", func(sr chi.Router) {
		sr.Put("/", h.InitRecovery)
		sr.Post("/", h.Recover)
		sr.Get("/", h.PingRecovery)
		sr.Get("/cancel", h.CancelRecovery)
	})

	r.NotFound(httpflow.NotFound(h.onError))
	r.MethodNotAllowed(httpflow.MethodNotAllowed(h.onError))

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
		sr.With(h.sessions.Auth).Delete("/", h.LogOut)
	})

	r.NotFound(httpflow.NotFound(h.onError))
	r.MethodNotAllowed(httpflow.MethodNotAllowed(h.onError))

	return r
}

// SetupLinks creates a link string map that should be used for email
// sending, etc.
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

	ctx := r.Context()

	usr, err := h.create(ctx, inp)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.ExposeCore()

	tok, err := usrC.InitVerification(h.verif)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.Create(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	sessions := h.sessions
	if inp.ExposeCore().RememberMe {
		sessions = sessions.Clone(sessionup.ExpiresIn(h.sesDur))
	}

	if err = sessions.Init(w, r, usrC.ID.String()); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	go h.email.SendAccountActivation(context.Background(), usrC.Email, tok)

	httpflow.Respond(w, r, nil, http.StatusCreated, h.onError)
}

// LogIn handles user's credentials checking and new session creation.
// On successful execution, a session will be created.
// Boolean parameters determines whether inactive users can log in or not.
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
		if errors.Is(err, httpflow.ErrNotFound) {
			err = ErrInvalidCredentials
		}

		httpflow.RespondError(w, r, err, h.onError)

		return
	}

	if err = h.gKeep(usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.ExposeCore()

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

	_, id, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usr, err := h.db.FetchByID(ctx, id)
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

	_, id, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	inp, err := h.parse(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usr, err := h.db.FetchByID(ctx, id)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	upd, err := usr.ApplyInput(inp)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.ExposeCore()
	updC := upd.ExposeCore()

	var tok string

	if updC.Email {
		tok, err = usrC.InitVerification(h.verif)
		if err != nil {
			httpflow.RespondError(w, r, err, h.onError)
			return
		}
	}

	if updC.Password {
		if err := h.sessions.RevokeOther(ctx); err != nil {
			httpflow.RespondError(w, r, err, h.onError)
			return
		}
	}

	if err = h.db.Update(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if updC.Password {
		go h.email.SendPasswordChanged(context.Background(), usrC.Email, false)
	}

	if tok != "" {
		go h.email.SendEmailVerification(context.Background(),
			usrC.UnverifiedEmail.String, tok)
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// Delete handles user's data removal from the data store.
// On successful deletion, an email will be sent.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, id, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	var cInp CoreInput
	if err = httpflow.DecodeJSON(r, &cInp); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usr, err := h.db.FetchByID(ctx, id)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.pDel(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.ExposeCore()

	if !usrC.IsPasswordCorrect(cInp.Password) {
		httpflow.RespondError(w, r, ErrInvalidCredentials, h.onError)
		return
	}

	if err = h.sessions.RevokeAll(ctx, w); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.DeleteByID(ctx, id); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	go h.email.SendAccountDeleted(context.Background(), usrC.Email)

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

	ses, _, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	id, err := httpflow.ExtractParam(r, "id")
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if ses.ID == id {
		httpflow.RespondError(w, r, httpflow.NewError(nil,
			http.StatusBadRequest,
			"current session cannot be revoked"), h.onError)

		return
	}

	if err = h.sessions.RevokeByIDExt(ctx, id); err != nil {
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

	_, id, err := httpflow.ExtractSession(ctx)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usr, err := h.db.FetchByID(ctx, id)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.ExposeCore()

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
		go h.email.SendEmailVerification(context.Background(),
			usrC.UnverifiedEmail.String, tok)
	} else {
		go h.email.SendAccountActivation(context.Background(), usrC.Email, tok)
	}

	httpflow.Respond(w, r, nil, http.StatusAccepted, h.onError)
}

// Verify checks whether the token in the URL is valid and activates either
// user's account or their new email address.
// If new email was changed and verified, an email will be sent to the old
// address about the change.
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	usrC := usr.ExposeCore()
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
		go h.email.SendEmailChanged(context.Background(), oEml, usrC.Email)
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// CancelVerification checks whether the token in the URL is valid and stops
// active verification token from further processing.
func (h *Handler) CancelVerification(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = usr.ExposeCore().CancelVerification(tok); err != nil {
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

	// if email is not found, etc. we don't want the user or attacker
	// know this.
	respErr := func(err error) {
		if httpflow.ErrorCode(err) < 500 {
			httpflow.Respond(w, r, nil, http.StatusAccepted,
				h.onError)
			return
		}

		httpflow.RespondError(w, r, err, h.onError)
	}

	ctx := r.Context()

	usr, err := h.db.FetchByEmail(ctx, cInp.Email)
	if err != nil {
		respErr(err)
		return
	}

	usrC := usr.ExposeCore()

	tok, err := usrC.InitRecovery(h.recov)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.Update(ctx, usr); err != nil {
		respErr(err)
		return
	}

	go h.email.SendRecovery(context.Background(), usrC.Email, tok)

	httpflow.Respond(w, r, nil, http.StatusAccepted, h.onError)
}

// Recover checks the token in the URL and applies the provided password
// to the user account data structure.
// On successful execution, an email will be sent notifying about password
// change.
func (h *Handler) Recover(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
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
	usrC := usr.ExposeCore()

	if err = usrC.Recover(tok, cInp.Password); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.sessions.RevokeByUserKey(ctx, usrC.ID.String()); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.Update(ctx, usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	go h.email.SendPasswordChanged(context.Background(), usrC.Email, true)

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// PingRecovery only checks whether the token in the URL is valid or not; no
// writable modifications are being done.
func (h *Handler) PingRecovery(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = usr.ExposeCore().Recovery.Check(tok); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// CancelRecovery checks whether the token in the URL is valid and stops
// active verification token from further processing.
func (h *Handler) CancelRecovery(w http.ResponseWriter, r *http.Request) {
	usr, tok, err := h.FetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = usr.ExposeCore().CancelRecovery(tok); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	if err = h.db.Update(r.Context(), usr); err != nil {
		httpflow.RespondError(w, r, err, h.onError)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.onError)
}

// FetchByToken extracts the token from request's URL, retrieves a user by ID
// embedded in the token and returns user's account instance, raw token and
// optionally an error.
func (h *Handler) FetchByToken(r *http.Request) (User, string, error) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		return nil, "", httpflow.NewError(nil, http.StatusBadRequest,
			"token not found")
	}

	tok, id, err := FromFullToken(tok)
	if err != nil {
		return nil, "", err
	}

	usr, err := h.db.FetchByID(r.Context(), id)
	if err != nil {
		return nil, "", err
	}

	return usr, tok, nil
}

// DB is an interface which should be implemented by the user data
// store layer.
type DB interface {
	// Stats should return users' data statistics from the underlying
	// data store.
	Stats(ctx context.Context) (Stats, error)

	// Create should insert the freshly created user into the underlying
	// data store.
	Create(ctx context.Context, usr User) error

	// FetchMany should retrieve multiple users from the underlying data
	// store by the provided query.
	FetchMany(ctx context.Context, qr httpflow.Query) ([]User, error)

	// FetchByID should retrieve a user from the underlying data store
	// by their ID.
	FetchByID(ctx context.Context, id xid.ID) (User, error)

	// FetchByEmail should retrieve a user from the underlying data store
	// by their email address.
	FetchByEmail(ctx context.Context, eml string) (User, error)

	// Update should update user's data in the underlying data store.
	Update(ctx context.Context, usr User) error

	// DeleteByID should delete a user from the underlying data store
	// by their ID.
	DeleteByID(ctx context.Context, id xid.ID) error
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
