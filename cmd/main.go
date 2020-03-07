package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/jmoiron/sqlx"
	"github.com/swithek/httpflow"
	"github.com/swithek/httpflow/email"
	"github.com/swithek/httpflow/user"
	uPg "github.com/swithek/httpflow/user/postgres"
	"github.com/swithek/sessionup"
	sesPg "github.com/swithek/sessionup-pgstore"
)

func main() {
	log := log.New(os.Stdout, "", log.LstdFlags)
	db, err := sqlx.Connect("postgres", "dbname=httpflow user=postgres password=password123 sslmode=disable")
	if err != nil {
		handleErr(log)(err)
		return
	}

	sesStore, err := sesPg.New(db.DB, "sessions", time.Minute*5)
	if err != nil {
		handleErr(log)(err)
		return
	}

	ses := sessionup.NewManager(sesStore)

	uDB, err := uPg.New(db, time.Hour*24, handleErr(log))
	if err != nil {
		handleErr(log)(err)
		return
	}

	eml := email.NewPlaceholder(
		log,
		httpflow.NewLinks(user.SetupLinks("http://localhost:8080")),
	)

	hdl := user.NewHandler(ses, uDB, eml, user.SetErrorExec(handleErr(log)))

	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Use(middleware.Logger)
	router.Mount("/", hdl.Routes(true))

	http.ListenAndServe(":8080", router)
}

func handleErr(log *log.Logger) httpflow.ErrorExec {
	return func(err error) {
		log.Println(err)
	}
}
