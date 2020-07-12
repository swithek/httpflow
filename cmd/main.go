package main

import (
	"errors"
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
	l := log.New(os.Stdout, "", log.LstdFlags)

	db, err := sqlx.Connect("postgres", "dbname=httpflow user=postgres password=password123 sslmode=disable")
	if err != nil {
		handleErr(l)(err)
		return
	}

	sesStore, err := sesPg.New(db.DB, "sessions", time.Minute*5)
	if err != nil {
		handleErr(l)(err)
		return
	}

	ses := sessionup.NewManager(sesStore,
		sessionup.Secure(false),
		sessionup.Reject(httpflow.SessionReject(handleErr(l))))

	uDB, err := uPg.New(db, time.Hour*24, handleErr(l))
	if err != nil {
		handleErr(l)(err)
		return
	}

	eml := email.NewPlaceholder(
		l,
		httpflow.NewLinks(user.SetupLinks("http://localhost:8080")),
	)

	hdl := user.NewHandler(ses, uDB, eml, user.SetErrorExec(handleErr(l)))

	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Use(middleware.Logger)
	router.Mount("/", hdl.Router(true))

	if err := http.ListenAndServe(":8080", router); errors.Is(err, http.ErrServerClosed) {
		l.Fatal(err)
	}
}

func handleErr(l *log.Logger) httpflow.ErrorExec {
	return func(err error) {
		l.Println(err)
	}
}
