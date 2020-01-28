package user

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/swithek/httputil"
	"github.com/swithek/sessionup"
)

var (
	// ErrUnauthorized is returned when request's context contains invalid
	// session.
	ErrUnauthorized = httputil.NewError(nil, http.StatusUnauthorized,
		"unauthorized")

	// ErrInvalidJSON is returned when request body contains invalid JSON
	// data.
	ErrInvalidJSON = httputil.NewError(nil, http.StatusBadRequest,
		"invalid JSON body")
)

// Handler holds dependencies required for user management.
type Handler struct {
	sessions sessionup.Manager
	db       UserDB
	fatal    func(error)
	input    func(*http.Request) (Inputer, error)
	create   func(Inputer) (User, error)
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

	r.Route("/sessions", func(r chi.Router) {
		r.Use(h.sessions.Auth)
		r.Get("/", h.FetchSessions)
		r.Delete("/{id}", h.RevokeSession)
		r.Delete("/", h.RevokeOtherSessions)
	})

	return r
}

// Register handles new user's creation and insertion into the data store.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	i, err := h.input(r)
	if err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	u, err := h.create(i)
	if err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Create(r.Context(), u); err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.sessions.Init(w, r, u.Core().ID.String()); err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	httputil.Respond(w, r, nil, http.StatusNoContent)
}

// Login handles user's credentials checking and new session creation.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		httputil.RespondError(w, r, ErrInvalidJSON, h.fatal)
		return
	}

	u, err := h.db.FetchByEmail(r.Context(), ci.Email)
	if err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	if !u.Core().IsPasswordCorrect(ci.Password) {
		httputil.RespondError(w, r, ErrInvalidCredentials, h.fatal)
		return
	}

	if err = h.sessions.Init(w, r, id.String()); err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	httputil.Respond(w, r, nil, http.StatusNoContent)
}

// Logout handles user's active session revokation.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.Revoke(r.Context(), w); err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	httputil.Respond(w, r, nil, http.StatusNoContent)
}

// Fetch handles user's data retrieval.
func (h *Handler) Fetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		httputil.RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	u, err := h.db.FetchByID(r.Context(), s.UserKey)
	if err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	httputil.Respond(w, r, u, http.StatusOK)
}

// Update handles user's data update in the data store.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		httputil.RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	i, err := h.input(r)
	if err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	u, err := h.db.FetchByID(ctx, s.UserKey)
	if err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	if err = u.Update(i); err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Update(ctx, u); err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	httputil.Respond(w, r, nil, http.StatusNoContent)
}

// Delete handles user's data removal from the data store.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		httputil.RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		httputil.RespondError(w, r, ErrInvalidJSON, h.fatal)
		return
	}

	u, err := h.db.FetchByID(r.Context(), s.UserKey)
	if err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	if !u.Core().IsPasswordCorrect(ci.Password) {
		httputil.RespondError(w, r, ErrInvalidCredentials, h.fatal)
		return
	}

	if err = h.db.DeleteByID(ctx, s.UserKey); err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.sessions.RevokeAll(ctx, w); err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	httputil.Respond(w, r, nil, http.StatusNoContent)
}

// FetchSessions retrieves all sessions of the same user.
func (h *Handler) FetchSessions(w http.ResponseWriter, r *http.Request) {
	ss, err := h.sessions.FetchAll(r.Context())
	if err != nil {
		httputil.RespondError(w, r, err, h.fatal)
		return
	}

	if len(ss) == 0 {
		httputil.RespondError(w, r, httputil.NewError(nil,
			http.StatusNotFound, "not found"), h.fatal)
		return
	}

	httputil.Respond(w, r, ss, http.StatusOK)
}

// RevokeSession revokes one specific session of the user with the
// active session in the request's context.
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s, ok := sessionup.FromContext(r.Context()); ok && s.ID == id {
		httputil.RespondError(w, r, httputil.NewError(nil,
			http.StatusBadRequest, "current session cannot be revoked"))
		return
	}

	if err := h.sessions.RevokeByID(r.Context(), id); err != nil {
		httputil.RespondError(w, r, err)
		return
	}

	httputil.Respond(w, r, nil, http.StatusNoContent)
}

// RevokeOtherSessions revokes all sessions of the same user besides the
// current one.
func (h *Handler) RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.RevokeOther(r.Context()); err != nil {
		httputil.RespondError(w, r, err)
	}
	httputil.Respond(w, r, nil, http.StatusNoContent)
}

// UserDB is an interface data store layer should implement.
type UserDB interface {
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
