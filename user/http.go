package user

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/swithek/httpflow"
	"github.com/swithek/sessionup"
)

var (
	// ErrUnauthorized is returned when request's context contains invalid
	// session.
	ErrUnauthorized = httpflow.NewError(nil, http.StatusUnauthorized,
		"unauthorized")

	// ErrInvalidJSON is returned when request body contains invalid JSON
	// data.
	ErrInvalidJSON = httpflow.NewError(nil, http.StatusBadRequest,
		"invalid JSON body")
)

// Handler holds dependencies required for user management.
type Handler struct {
	sessions      sessionup.Manager
	db            Database
	email         EmailSender
	fatal         func(error)
	input         func(*http.Request) (Inputer, error)
	create        func(Inputer) (User, error)
	verifInterval time.Duration
	verifCooldown time.Duration
	recovInterval time.Duration
	recovCooldown time.Duration
}

// ServeHTTP returns a handler with all core user routes.
func (h *Handler) ServeHTTP() http.Handler {
	r := chi.NewRouter()
	r.Post("/new", h.Register)
	r.Route("/auth", func(sr chi.Router) {
		sr.Post("/", h.Login)
		sr.With(h.sessions.Auth).Delete("/", h.Logout)
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

// Register handles new user's creation and insertion into the data store.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	i, err := h.input(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	u, err := h.create(i)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	uc := u.Core()

	t, err := uc.InitVerification(h.verifInterval, h.verifCooldown)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	ctx := r.Context()

	if err = h.db.Create(ctx, u); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.sessions.Init(w, r, u.Core().ID.String()); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	go h.email.SendAccountActivation(ctx, u.Core().Email, t)

	httpflow.Respond(w, r, nil, http.StatusCreated, h.fatal)
}

// Login handles user's credentials checking and new session creation.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(&ci); err != nil {
		httpflow.RespondError(w, r, ErrInvalidJSON, h.fatal)
		return
	}

	if err := CheckEmail(ci.Email); err != nil {
		httpflow.RespondError(w, r, ErrInvalidCredentials, h.fatal)
		return
	}

	ctx := r.Context()

	u, err := h.db.FetchByEmail(ctx, ci.Email)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	uc := u.Core()

	if !uc.IsPasswordCorrect(ci.Password) {
		httpflow.RespondError(w, r, ErrInvalidCredentials, h.fatal)
		return
	}

	uc.Recovery.Clear()

	if err = h.db.Update(ctx, u); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.sessions.Init(w, r, uc.ID.String()); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
}

// Logout handles user's active session revokation.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.Revoke(r.Context(), w); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
}

// Fetch handles user's data retrieval.
func (h *Handler) Fetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		httpflow.RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	u, err := h.db.FetchByID(ctx, s.UserKey)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	httpflow.Respond(w, r, u, http.StatusOK, h.fatal)
}

// Update handles user's data update in the data store.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		httpflow.RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	i, err := h.input(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	u, err := h.db.FetchByID(ctx, s.UserKey)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	uc := u.Core()
	unver := uc.UnverifiedEmail != ""

	if err = u.Update(i); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if !unver && uc.UnverifiedEmail != "" {
		t, err := uc.InitVerification(h.verifInterval, h.verifCooldown)
		if err != nil {
			httpflow.RespondError(w, r, err, h.fatal)
			return
		}

		go h.email.SendEmailVerification(ctx, uc.UnverifiedEmail, t)
	}

	if err = h.db.Update(ctx, u); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if i.Core().Password != "" {
		go h.email.SendPasswordChanged(ctx, uc.Email, false)
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
}

// Delete handles user's data removal from the data store.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		httpflow.RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(&ci); err != nil {
		httpflow.RespondError(w, r, ErrInvalidJSON, h.fatal)
		return
	}

	u, err := h.db.FetchByID(r.Context(), s.UserKey)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	uc := u.Core()

	if !uc.IsPasswordCorrect(ci.Password) {
		httpflow.RespondError(w, r, ErrInvalidCredentials, h.fatal)
		return
	}

	if err = h.db.DeleteByID(ctx, s.UserKey); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.sessions.RevokeAll(ctx, w); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	go h.email.SendAccountDeleted(ctx, uc.Email)

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
}

// FetchSessions retrieves all sessions of the same user.
func (h *Handler) FetchSessions(w http.ResponseWriter, r *http.Request) {
	ss, err := h.sessions.FetchAll(r.Context())
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if len(ss) == 0 {
		httpflow.RespondError(w, r, httpflow.NewError(nil,
			http.StatusNotFound, "not found"), h.fatal)
		return
	}

	httpflow.Respond(w, r, ss, http.StatusOK, h.fatal)
}

// RevokeSession revokes one specific session of the user with the
// active session in the request's context.
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s, ok := sessionup.FromContext(r.Context()); ok && s.ID == id {
		httpflow.RespondError(w, r, httpflow.NewError(nil,
			http.StatusBadRequest,
			"current session cannot be revoked"), h.fatal)
		return
	}

	if err := h.sessions.RevokeByID(r.Context(), id); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
}

// RevokeOtherSessions revokes all sessions of the same user besides the
// current one.
func (h *Handler) RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.RevokeOther(r.Context()); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}
	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
}

// ResendVerification attempts to send and generate the verification token
// once more.
func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		httpflow.RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	u, err := h.db.FetchByID(r.Context(), s.UserKey)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	uc := u.Core()

	if uc.Verification.IsEmpty() {
		httpflow.RespondError(w, r, httpflow.NewError(nil,
			http.StatusBadRequest,
			"verification has not been initiated"), h.fatal)
		return
	}

	t, err := uc.InitVerification(h.verifInterval, h.verifCooldown)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Update(ctx, u); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if uc.IsActivated() {
		go h.email.SendEmailVerification(ctx, uc.UnverifiedEmail, t)
	} else {
		go h.email.SendAccountActivation(ctx, uc.Email, t)
	}

	httpflow.Respond(w, r, nil, http.StatusAccepted, h.fatal)
}

// Verify checks whether the token in the URL is valid and activates either
// user's account or their new email address.
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	u, t, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = u.Core().Verify(t); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Update(r.Context(), u); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
	return
}

// CancelVerification checks whether the token in the URL is valid and stops
// active verification token from further processing.
func (h *Handler) CancelVerification(w http.ResponseWriter, r *http.Request) {
	u, t, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = u.Core().CancelVerification(t); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Update(r.Context(), u); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
	return
}

// InitRecovery initializes recovery token for the user associated with the
// provided email address and sends to the same address.
func (h *Handler) InitRecovery(w http.ResponseWriter, r *http.Request) {
	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(&ci); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err := CheckEmail(ci.Email); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	ctx := r.Context()

	u, err := h.db.FetchByEmail(ctx, ci.Email)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	uc := u.Core()

	t, err := uc.InitRecovery(h.recovInterval, h.recovCooldown)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Update(ctx, u); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	go h.email.SendRecovery(ctx, uc.Email, t)

	httpflow.Respond(w, r, nil, http.StatusAccepted, h.fatal)
}

// Recover checks the token in the URL and applies the provided password
// to the user account data structure.
func (h *Handler) Recover(w http.ResponseWriter, r *http.Request) {
	u, t, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(&ci); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	ctx := r.Context()
	uc := u.Core()

	if err = uc.Recover(t, ci.Password); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Update(ctx, u); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	go h.email.SendPasswordChanged(ctx, uc.Email, true)

	if err = h.sessions.RevokeByUserKey(ctx, uc.ID.String()); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
}

// PingRecovery only checks whether the token in the URL is valid, no
// writable modifications are being done.
func (h *Handler) PingRecovery(w http.ResponseWriter, r *http.Request) {
	u, t, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = u.Core().Recovery.Check(t); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
}

// CancelRecovery checks whether the token in the URL is valid and stops
// active verification token from further processing.
func (h *Handler) CancelRecovery(w http.ResponseWriter, r *http.Request) {
	u, t, err := h.fetchByToken(r)
	if err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = u.Core().CancelVerification(t); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Update(r.Context(), u); err != nil {
		httpflow.RespondError(w, r, err, h.fatal)
		return
	}

	httpflow.Respond(w, r, nil, http.StatusNoContent, h.fatal)
}

// fetchByToken extracts the token from request's URL, retrieves a user by ID
// embedded in the token and returns user's account instance, raw token and
// optionally an error.
func (h *Handler) fetchByToken(r *http.Request) (User, string, error) {
	t := chi.URLParam(r, "token")
	if t == "" {
		return nil, "", httpflow.NewError(nil, http.StatusBadRequest,
			"token not found")
	}

	t, id, err := FromFullToken(t)
	if err != nil {
		return nil, "", err
	}

	u, err := h.db.FetchByID(r.Context(), id.String())
	if err != nil {
		return nil, "", err
	}

	return u, t, nil
}

// Database is an interface user's data store layer should implement.
type Database interface {
	// Create should insert the freshly created user into the underlying
	// data store.
	Create(ctx context.Context, u User) error

	// FetchByID should retrieve the user from the underlying data store
	// by their ID.
	FetchByID(ctx context.Context, id string) (User, error)

	// FetchByEmail should retrieve the user from the underlying data store
	// by their email address.
	FetchByEmail(ctx context.Context, e string) (User, error)

	// Update should update user's data in the underlying data store.
	Update(ctx context.Context, u User) error

	// DeleteByID should delete the user from the underlying data store
	// by their ID.
	DeleteByID(ctx context.Context, id string) error
}

// EmailSender is an interface email sending service should implement.
type EmailSender interface {
	// SendAccountActivation should send an email regarding account
	// activation with the token, embedded into a full URL, to the
	// specified email address.
	SendAccountActivation(ctx context.Context, eml, tok string)

	// EmailVerification should send an email regarding new email
	// verification with the token, embedded into a full URL, to the
	// specified email address.
	SendEmailVerification(ctx context.Context, eml, tok string)

	// Recovery should send an email regarding password recovery with
	// the token, embedded into a full URL, to the specified email address.
	SendRecovery(ctx context.Context, eml, tok string)

	// AccountDeleted should send an email regarding successful account
	// deletion to the specified email address.
	SendAccountDeleted(ctx context.Context, eml string)

	// PasswordChanged should send an email notifying about a successful
	// password change to the specified email address.
	// Last parameter specifies whether the password was changed during
	// the recovery process or not.
	SendPasswordChanged(ctx context.Context, eml string, recov bool)
}
