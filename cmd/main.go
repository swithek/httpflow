package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"
	"github.com/swithek/httpflow"
	"github.com/swithek/httpflow/email"
	"github.com/swithek/httpflow/user"
	uPg "github.com/swithek/httpflow/user/postgres"
	"github.com/swithek/sessionup"
	sesPg "github.com/swithek/sessionup-pgstore"
)

func main() {
	log := zerolog.New(zerolog.NewConsoleWriter())

	db, err := sqlx.Connect("postgres", "dbname=httpflow user=postgres password=password123 sslmode=disable")
	if err != nil {
		log.Error().Err(err).Msg("cannot connect to db")
		return
	}

	sesStore, err := sesPg.New(db.DB, "sessions", time.Minute*5)
	if err != nil {
		log.Error().Err(err).Msg("cannot init session db")
		return
	}

	ses := sessionup.NewManager(sesStore,
		sessionup.Secure(false),
		sessionup.Reject(httpflow.SessionReject(log)))

	uDB, err := uPg.NewStore(log, db, time.Hour*24)
	if err != nil {
		log.Error().Err(err).Msg("cannot init user db")
		return
	}

	eml := email.NewPlaceholder(
		log,
		httpflow.NewLinks(user.SetupLinks("http://localhost:8080")),
	)

	hdl := user.NewHandler(log, uDB, eml, ses)

	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Use(middleware.Logger)
	router.Mount("/", hdl.Router(true))

	if err := http.ListenAndServe(":8080", router); errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Msg("server terminated")
	}
}
