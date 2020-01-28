package httpuser

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/swithek/sessionup"
)

var (
	// ErrInvalidJSON is returned when request body contains invalid JSON
	// data.
	ErrInvalidJSON = NewError(err, http.StatusBadRequest, "invalid JSON body")
)

func Routes() http.Handler {
	r := chi.NewRouter()
}

type Handler struct {
	sessions sessionup.Manager
	db       UserDB
	fatal    func(error)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		RespondError(w, r, ErrInvalidJSON, h.fatal)
		return
	}

	u, err := h.db.FetchByID(r.Context(), ci.Email)
	if err != nil {
		RespondError(w, r, DetectError(err), h.fatal)
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

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.sessions.Revoke(r.Context(), w); err != nil {
		RespondError(w, r, err)
		return
	}

	Respond(w, r, nil, http.StatusNoContent)
}

type UserDB interface {
	Create(ctx context.Context, u User) error
	FetchByID(ctx context.Context, id string) (User, error)
	FetchByEmail(ctx context.Context, e string) (User, error)
	Update(ctx context.Context, u User) error
	DeleteByID(ctx context.Context, id string) error
}

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

func RespondError(w http.ResponseWriter, r *http.Request, err error,
	fatal func(error)) {
	code := ErrorCode(err)
	Respond(w, r, err, code)
	if code >= 500 {
		fatal(err)
	}
}
