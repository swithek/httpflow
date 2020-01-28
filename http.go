package httpuser

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/swithek/sessionup"
)

var (
	// ErrUnauthorized is returned when request's context contains invalid
	// session.
	ErrUnauthorized = NewError(nil, http.StatusUnauthorized, "unauthorized")

	// ErrInvalidJSON is returned when request body contains invalid JSON
	// data.
	ErrInvalidJSON = NewError(nil, http.StatusBadRequest, "invalid JSON body")
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
		//r.Get("/", h.FetchSessions)
		//r.Delete("/{id}", h.RevokeSession)
		//r.Delete("/", h.RevokeAllSessions)
	})

	return r
}

// Register handles new user's creation and insertion into the data store.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	i, err := h.input(r)
	if err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	u, err := h.create(i)
	if err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Create(r.Context(), u); err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.sessions.Init(w, r, u.Core().ID.String()); err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	Respond(w, r, nil, http.StatusNoContent)
}

// Login handles user's credentials checking and new session creation.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		RespondError(w, r, ErrInvalidJSON, h.fatal)
		return
	}

	u, err := h.db.FetchByEmail(r.Context(), ci.Email)
	if err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	if !u.Core().IsPasswordCorrect(ci.Password) {
		RespondError(w, r, ErrInvalidCredentials, h.fatal)
		return
	}

	if err = h.sessions.Init(w, r, id.String()); err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	Respond(w, r, nil, http.StatusNoContent)
}

// Logout handles user's active session revokation.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.Revoke(r.Context(), w); err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	Respond(w, r, nil, http.StatusNoContent)
}

// Fetch handles user's data retrieval.
func (h *Handler) Fetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	u, err := h.db.FetchByID(r.Context(), s.UserKey)
	if err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	Respond(w, r, u, http.StatusOK)
}

// Update handles user's data update in the data store.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	i, err := h.input(r)
	if err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	u, err := h.db.FetchByID(ctx, s.UserKey)
	if err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	if err = u.Update(i); err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.db.Update(ctx, u); err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	Respond(w, r, nil, http.StatusNoContent)
}

// Delete handles user's data removal from the data store.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s, ok := sessionup.FromContext(ctx)
	if !ok {
		RespondError(w, r, ErrUnauthorized, h.fatal)
		return
	}

	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		RespondError(w, r, ErrInvalidJSON, h.fatal)
		return
	}

	u, err := h.db.FetchByID(r.Context(), s.UserKey)
	if err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	if !u.Core().IsPasswordCorrect(ci.Password) {
		RespondError(w, r, ErrInvalidCredentials, h.fatal)
		return
	}

	if err = h.db.DeleteByID(ctx, s.UserKey); err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	if err = h.sessions.RevokeAll(ctx, w); err != nil {
		RespondError(w, r, err, h.fatal)
		return
	}

	Respond(w, r, nil, http.StatusNoContent)

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

// Respond sends JSON type response to the client.
func Respond(w http.ResponseWriter, r *http.Request, data interface{},
	code int, fatal func(error)) {
	w.WriteHeader(code)
	if data == nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.Header().Del("Content-Type")
		w.WriteHeader(http.StatusInternalServerError)
		fatal(err)
	}
}

// RespondError sends the provided error in a JSON format to the client.
func RespondError(w http.ResponseWriter, r *http.Request, err error,
	fatal func(error)) {
	err = DetectError(err)
	code := ErrorCode(err)
	Respond(w, r, err, code)
	if code >= 500 {
		fatal(err)
	}
}
