package httpuser

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/swithek/sessionup"
)

func Routes() http.Handler {
	r := chi.NewRouter()
}

type Handler struct {
	sessions sessionup.Manager
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var ci CoreInput
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		h.Respond(w, r, 
	}
}

func (h *Handler) Respond(w http.ResponseWriter, r *http.Request,
	data interface{}, code int) {
	w.WriteHeader(code)
	if data == nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		w.Header().Del("Content-Type")
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (h *Handler) Error(w http.ResponseWriter, r *http.Request, err error) {
	
}
