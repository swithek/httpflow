package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/swithek/httpflow"
	"github.com/swithek/httpflow/email"
	"github.com/swithek/httpflow/user"
	uPg "github.com/swithek/httpflow/user/postgres"
	"github.com/swithek/sessionup"
	sesPg "github.com/swithek/sessionup-pgstore"
)

func main() {
	db, err := sqlx.Connect("postgres", "dbname=httpflow user=postgres password=password123 sslmode=disable")
	if err != nil {
		handleErr(err)
		return
	}

	sesStore, err := sesPg.New(db.DB, "sessions", time.Minute*5)
	if err != nil {
		handleErr(err)
		return
	}

	ses := sessionup.NewManager(sesStore)

	uDB, err := uPg.New(db, time.Hour*24, handleErr)
	if err != nil {
		handleErr(err)
		return
	}

	eml := email.NewPlaceholder(
		log.New(os.Stderr, "", log.LstdFlags),
		httpflow.NewLinks(user.SetupLinks("http://localhost:8080")),
	)

	hdl := user.NewDefaultHandler(ses, uDB, eml)

	http.ListenAndServe(":8080", hdl)
}

func handleErr(err error) {
	log.Println(err)
}
