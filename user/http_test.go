package user

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swithek/httpflow"
	"github.com/swithek/sessionup"
	"github.com/swithek/sessionup/memstore"
)

func TestDefaultParser(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/",
		strings.NewReader("{"))
	inp, err := DefaultParser(req)
	assert.Nil(t, inp)
	assert.NotNil(t, err)

	req = httptest.NewRequest("GET", "http://test.com/",
		toJSON("user@email.com", "password1"))
	inp, err = DefaultParser(req)
	assert.Nil(t, err)
	require.NotNil(t, inp)
	assert.Equal(t, "user@email.com", inp.Core().Email)
	assert.Equal(t, "password1", inp.Core().Password)
}

func TestDefaultCreator(t *testing.T) {
	usr, err := DefaultCreator(CoreInput{Email: "user@email.com",
		Password: "password1"})
	assert.Nil(t, err)
	require.NotNil(t, usr)
	assert.Equal(t, "user@email.com", usr.Core().Email)
	assert.NotZero(t, usr.Core().PasswordHash)
}

func TestNewHandler(t *testing.T) {

}

func TestHandlerRegister(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DatabaseMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasCreateCalled := func(count int, eml string) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.CreateCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, eml, ff[0].Usr.Core().Email)
			assert.NotNil(t, ff[0].Usr.Core().PasswordHash)
			assert.NotNil(t, ff[0].Usr.Core().ID)
		}
	}

	wasSendAccountActivationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendAccountActivationCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
		}
	}

	dbStub := func(err error) *DatabaseMock {
		return &DatabaseMock{
			CreateFunc: func(_ context.Context, _ User) error {
				return err
			},
		}
	}

	emailStub := func() *EmailSenderMock {
		return &EmailSenderMock{
			SendAccountActivationFunc: func(_ context.Context, _, _ string) {},
		}
	}

	inpEml := "user@email.com"

	cc := map[string]struct {
		Sessions *sessionup.Manager
		DB       *DatabaseMock
		Email    *EmailSenderMock
		Creator  Creator
		Body     io.Reader
		Checks   []check
	}{
		"Error returned by Parser": {
			Sessions: sessionup.NewManager(memstore.New(time.Hour)),
			DB:       dbStub(nil),
			Email:    emailStub(),
			Body:     strings.NewReader("{"),
			Creator:  DefaultCreator,
			Checks: checks(
				hasResp(true),
				wasCreateCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Creator": {
			Sessions: sessionup.NewManager(memstore.New(time.Hour)),
			DB:       dbStub(nil),
			Email:    emailStub(),
			Body:     toJSON(inpEml, "password1"),
			Creator: func(inp Inputer) (User, error) {
				return nil, assert.AnError
			},
			Checks: checks(
				hasResp(true),
				wasCreateCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Core.InitVerification": {
			Sessions: sessionup.NewManager(memstore.New(time.Hour)),
			DB:       dbStub(nil),
			Email:    emailStub(),
			Body:     toJSON(inpEml, "password1"),
			Creator: func(inp Inputer) (User, error) {
				usr := &Core{}
				usr.Init(inp)
				usr.Core().InitVerification(
					TokenTimes{time.Hour, time.Hour})
				return usr, nil
			},
			Checks: checks(
				hasResp(true),
				wasCreateCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Database.Create": {
			Sessions: sessionup.NewManager(memstore.New(time.Hour)),
			DB:       dbStub(assert.AnError),
			Email:    emailStub(),
			Body:     toJSON(inpEml, "password1"),
			Creator:  DefaultCreator,
			Checks: checks(
				hasResp(true),
				wasCreateCalled(1, inpEml),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Session init error": {
			Sessions: sessionup.NewManager(func() *memstore.MemStore {
				st := memstore.New(0)
				st.Create(context.Background(), sessionup.Session{
					ID:        "1",
					UserKey:   "user",
					ExpiresAt: time.Now().Add(time.Hour),
				})
				return st
			}(), sessionup.GenID(func() string { return "1" }),
				sessionup.ExpiresIn(time.Hour)),
			DB:      dbStub(nil),
			Email:   emailStub(),
			Body:    toJSON(inpEml, "password1"),
			Creator: DefaultCreator,
			Checks: checks(
				hasResp(true),
				wasCreateCalled(1, inpEml),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Successful user creation": {
			Sessions: sessionup.NewManager(memstore.New(time.Hour)),
			DB:       dbStub(nil),
			Email:    emailStub(),
			Body:     toJSON(inpEml, "password1"),
			Creator:  DefaultCreator,
			Checks: checks(
				hasResp(false),
				wasCreateCalled(1, inpEml),
				wasSendAccountActivationCalled(1, inpEml),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/",
				c.Body)
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.sessions = c.Sessions
			hdl.db = c.DB
			hdl.email = c.Email
			hdl.create = c.Creator
			hdl.Register(rec, req)
			time.Sleep(time.Millisecond) // to record goroutine func call
			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func TestHandlerLogIn(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DatabaseMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasFetchByEmailCalled := func(count int, eml string) check {
		return func(t *testing.T, db *DatabaseMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByEmailCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DatabaseMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Zero(t, ff[0].Usr.Core().Recovery)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DatabaseMock {
		return &DatabaseMock{
			FetchByEmailFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err1
			},
			UpdateFunc: func(_ context.Context, _ User) error {
				return err2
			},
		}
	}

	inpUsr := Core{Email: "user@email.com"}
	inpPass := "password1"
	inpUsr.SetPassword(inpPass)

	cc := map[string]struct {
		Sessions *sessionup.Manager
		DB       *DatabaseMock
		Body     io.Reader
		Checks   []check
	}{
		"Invalid JSON body": {
			Sessions: sessionup.NewManager(memstore.New(0)),
			DB:       dbStub(nil, nil, toPointer(inpUsr)),
			Body:     strings.NewReader("{"),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(0, ""),
				wasUpdateCalled(0),
			),
		},
		"Invalid email": {
			Sessions: sessionup.NewManager(memstore.New(0)),
			DB:       dbStub(nil, nil, toPointer(inpUsr)),
			Body:     toJSON("useremail.com", inpPass),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(0, ""),
				wasUpdateCalled(0),
			),
		},
		"Error returned by Database.FetchByEmail": {
			Sessions: sessionup.NewManager(memstore.New(0)),
			DB:       dbStub(assert.AnError, nil, nil),
			Body:     toJSON(inpUsr.Email, inpPass),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
			),
		},
		"Incorrect password": {
			Sessions: sessionup.NewManager(memstore.New(0)),
			DB:       dbStub(nil, nil, toPointer(inpUsr)),
			Body:     toJSON(inpUsr.Email, "password2"),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
			),
		},
		"Error returned by Database.Update": {
			Sessions: sessionup.NewManager(memstore.New(0)),
			DB:       dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Body:     toJSON(inpUsr.Email, inpPass),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Session init error": {
			Sessions: sessionup.NewManager(func() *memstore.MemStore {
				st := memstore.New(0)
				st.Create(context.Background(), sessionup.Session{
					ID:        "1",
					UserKey:   "user",
					ExpiresAt: time.Now().Add(time.Hour),
				})
				return st
			}(), sessionup.GenID(func() string { return "1" }),
				sessionup.ExpiresIn(time.Hour)),
			DB:   dbStub(nil, nil, toPointer(inpUsr)),
			Body: toJSON(inpUsr.Email, inpPass),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Successful user log in": {
			Sessions: sessionup.NewManager(memstore.New(0)),
			DB:       dbStub(nil, nil, toPointer(inpUsr)),
			Body:     toJSON(inpUsr.Email, inpPass),
			Checks: checks(
				hasResp(false),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/",
				c.Body)
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.sessions = c.Sessions
			hdl.db = c.DB
			hdl.LogIn(rec, req)
			for _, ch := range c.Checks {
				ch(t, c.DB, rec)
			}
		})
	}
}

func TestHandlerFetch(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DatabaseMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.NotZero(t, rec.Body.Len())
		}
	}

	wasFetchByIDCalled := func(count int, id string) check {
		return func(t *testing.T, db *DatabaseMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByIDCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, id, ff[0].ID)
		}
	}

	dbStub := func(err error, usr User) *DatabaseMock {
		return &DatabaseMock{
			FetchByIDFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err
			},
		}
	}

	inpUsr := Core{ID: xid.New()}

	cc := map[string]struct {
		DB      *DatabaseMock
		Session bool
		Checks  []check
	}{
		"No active session": {
			DB: dbStub(nil, toPointer(inpUsr)),
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:      dbStub(assert.AnError, nil),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
			),
		},
		"Successful user fetch": {
			DB:      dbStub(nil, toPointer(inpUsr)),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/",
				nil)
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.db = c.DB
			if c.Session {
				req = req.WithContext(sessionup.NewContext(
					context.Background(),
					sessionup.Session{UserKey: inpUsr.ID.String()}))
			}
			hdl.Fetch(rec, req)
			for _, ch := range c.Checks {
				ch(t, c.DB, rec)
			}
		})
	}
}

func TestHandlerUpdate(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DatabaseMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasFetchByIDCalled := func(count int, id string) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByIDCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasUpdateCalled := func(count int, eml string, verif bool) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, eml, ff[0].Usr.Core().UnverifiedEmail)
			assert.NotZero(t, ff[0].Usr.Core().PasswordHash)

			if verif {
				assert.NotZero(t, ff[0].Usr.Core().Verification)
			}
		}
	}

	wasSendEmailVerificationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendEmailVerificationCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	wasSendPasswordChangedCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendPasswordChangedCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, eml, ff[0].Eml)
			assert.False(t, ff[0].Recov)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DatabaseMock {
		return &DatabaseMock{
			FetchByIDFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err1
			},
			UpdateFunc: func(_ context.Context, _ User) error {
				return err2
			},
		}
	}

	emailStub := func() *EmailSenderMock {
		return &EmailSenderMock{
			SendEmailVerificationFunc: func(_ context.Context, _, _ string) {},
			SendPasswordChangedFunc:   func(_ context.Context, _ string, _ bool) {},
		}
	}

	inpUsr := Core{
		ID:           xid.New(),
		Email:        "user@email.com",
		PasswordHash: []byte("password1"),
	}
	inpNewEml := "user123@email.com"
	inpNewPass := "password@1"

	cc := map[string]struct {
		DB      *DatabaseMock
		Email   *EmailSenderMock
		Body    io.Reader
		Session bool
		Checks  []check
	}{
		"No active session": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON(inpNewEml, inpNewPass),
			Session: false,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
				wasUpdateCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Invalid JSON body": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    strings.NewReader("{"),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
				wasUpdateCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:      dbStub(assert.AnError, nil, nil),
			Email:   emailStub(),
			Body:    toJSON(inpNewEml, inpNewPass),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by User.ApplyInput": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON(inpNewEml, "pass"),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by Core.InitVerification": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Verification.NextAt = time.Now().Add(time.Hour)
				return tmp
			}())),
			Email:   emailStub(),
			Body:    toJSON(inpNewEml, inpNewPass),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by Database.Update": {
			DB:      dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON(inpNewEml, inpNewPass),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1, inpNewEml, true),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Successful user update with only password change": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON("", inpNewPass),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(1, inpUsr.Email),
			),
		},
		"Successful user update with only email change": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON(inpNewEml, ""),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1, inpNewEml, true),
				wasSendEmailVerificationCalled(1, inpNewEml),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Successful user update with email and password changes": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON(inpNewEml, inpNewPass),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1, inpNewEml, true),
				wasSendEmailVerificationCalled(1, inpNewEml),
				wasSendPasswordChangedCalled(1, inpUsr.Email),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/",
				c.Body)
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.db = c.DB
			hdl.email = c.Email
			if c.Session {
				req = req.WithContext(sessionup.NewContext(
					context.Background(),
					sessionup.Session{UserKey: inpUsr.ID.String()}))
			}
			hdl.Update(rec, req)
			time.Sleep(time.Millisecond) // to record goroutine func call
			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func TestHandlerDelete(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DatabaseMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasFetchByIDCalled := func(count int, id string) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByIDCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasDeleteByIDCalled := func(count int, id string) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.DeleteByIDCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasSendAccountDeletedCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendAccountDeletedCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DatabaseMock {
		return &DatabaseMock{
			FetchByIDFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err1
			},
			DeleteByIDFunc: func(_ context.Context, _ string) error {
				return err2
			},
		}
	}

	emailStub := func() *EmailSenderMock {
		return &EmailSenderMock{
			SendAccountDeletedFunc: func(_ context.Context, _ string) {},
		}
	}

	inpUsr := Core{
		ID:    xid.New(),
		Email: "user@email.com",
	}
	inpUsr.SetPassword("password1")

	inpPass := "password1"

	cc := map[string]struct {
		DB      *DatabaseMock
		Email   *EmailSenderMock
		Body    io.Reader
		Session bool
		Checks  []check
	}{
		"No active session": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON("", inpPass),
			Session: false,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
				wasDeleteByIDCalled(0, ""),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Invalid JSON body": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    strings.NewReader("{"),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
				wasDeleteByIDCalled(0, ""),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:      dbStub(assert.AnError, nil, nil),
			Email:   emailStub(),
			Body:    toJSON("", inpPass),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasDeleteByIDCalled(0, ""),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Incorrect password": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON("", "password2"),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasDeleteByIDCalled(0, ""),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by Database.DeleteByID": {
			DB:      dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON("", inpPass),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasDeleteByIDCalled(1, inpUsr.ID.String()),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Successful account deletion": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Body:    toJSON("", inpPass),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasDeleteByIDCalled(1, inpUsr.ID.String()),
				wasSendAccountDeletedCalled(1, inpUsr.Email),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/",
				c.Body)
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.sessions = sessionup.NewManager(memstore.New(0))
			hdl.db = c.DB
			hdl.email = c.Email
			if c.Session {
				req = req.WithContext(sessionup.NewContext(
					context.Background(),
					sessionup.Session{UserKey: inpUsr.ID.String()}))
			}
			hdl.Delete(rec, req)
			time.Sleep(time.Millisecond) // to record goroutine func call
			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func TestHandlerResendVerification(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DatabaseMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasFetchByIDCalled := func(count int, id string) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByIDCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotZero(t, ff[0].Usr.Core().Verification)
		}
	}

	wasSendEmailVerificationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendEmailVerificationCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	wasSendAccountActivationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendAccountActivationCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DatabaseMock {
		return &DatabaseMock{
			FetchByIDFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err1
			},
			UpdateFunc: func(_ context.Context, _ User) error {
				return err2
			},
		}
	}

	emailStub := func() *EmailSenderMock {
		return &EmailSenderMock{
			SendEmailVerificationFunc: func(_ context.Context, _, _ string) {},
			SendAccountActivationFunc: func(_ context.Context, _, _ string) {},
		}
	}

	inpUsr := Core{
		ID:           xid.New(),
		Email:        "user@email.com",
		PasswordHash: []byte("password1"),
		Verification: Token{
			Hash: []byte("12345"),
		},
	}

	cc := map[string]struct {
		DB      *DatabaseMock
		Email   *EmailSenderMock
		Session bool
		Checks  []check
	}{
		"No active session": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Session: false,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
				wasUpdateCalled(0),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:      dbStub(assert.AnError, nil, nil),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(0),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Verification not active": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Verification = Token{}
				return tmp
			}())),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(0),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Core.InitVerification": {
			DB: dbStub(nil, assert.AnError, toPointer(func() Core {
				tmp := inpUsr
				tmp.Verification.NextAt = time.Now().Add(time.Hour)
				return tmp
			}())),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(0),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Database.Update": {
			DB:      dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Successful email verification resend": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.UnverifiedEmail = tmp.Email
				tmp.ActivatedAt = time.Now()
				return tmp
			}())),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1),
				wasSendEmailVerificationCalled(1, inpUsr.Email),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Successful account activation resend": {
			DB:      dbStub(nil, nil, toPointer(inpUsr)),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(1, inpUsr.Email),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/", nil)
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.db = c.DB
			hdl.email = c.Email
			if c.Session {
				req = req.WithContext(sessionup.NewContext(
					context.Background(),
					sessionup.Session{UserKey: inpUsr.ID.String()}))
			}
			hdl.ResendVerification(rec, req)
			time.Sleep(time.Millisecond) // to record goroutine func call
			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func TestHandlerVerify(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DatabaseMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Zero(t, ff[0].Usr.Core().Verification)
		}
	}

	wasSendEmailChangedCalled := func(count int, oEml, nEml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendEmailChangedCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, oEml, ff[0].OEml)
			assert.Equal(t, nEml, ff[0].NEml)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DatabaseMock {
		return &DatabaseMock{
			FetchByIDFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err1
			},
			UpdateFunc: func(_ context.Context, _ User) error {
				return err2
			},
		}
	}

	emailStub := func() *EmailSenderMock {
		return &EmailSenderMock{
			SendEmailChangedFunc: func(_ context.Context, _, _ string) {},
		}
	}

	inpUsr := Core{
		ActivatedAt:     time.Now(),
		ID:              xid.New(),
		Email:           "user@email.com",
		UnverifiedEmail: "user123@email.com",
	}

	inpTok, _ := inpUsr.InitVerification(TokenTimes{time.Hour, time.Hour})

	cc := map[string]struct {
		DB     *DatabaseMock
		Email  *EmailSenderMock
		Token  string
		Checks []check
	}{
		"Error returned by Handler.fetchByToken": {
			DB:    dbStub(assert.AnError, nil, nil),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(0),
				wasSendEmailChangedCalled(0, "", ""),
			),
		},
		"Error returned by Core.Verify": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Verification.ExpiresAt = time.Time{}
				return tmp
			}())),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(0),
				wasSendEmailChangedCalled(0, "", ""),
			),
		},
		"Error returned by Database.Update": {
			DB:    dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(1),
				wasSendEmailChangedCalled(0, "", ""),
			),
		},
		"Successful account activation": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.ActivatedAt = time.Time{}
				return tmp
			}())),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(false),
				wasUpdateCalled(1),
				wasSendEmailChangedCalled(0, "", ""),
			),
		},
		"Successful email verification": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(false),
				wasUpdateCalled(1),
				wasSendEmailChangedCalled(1, inpUsr.Email, inpUsr.UnverifiedEmail),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/", nil)
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.db = c.DB
			hdl.email = c.Email
			hdl.Verify(rec, req.WithContext(
				addChiCtx(nil, "token", c.Token)))
			time.Sleep(time.Millisecond) // to record goroutine func call
			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func TestHandlerCancelVerification(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DatabaseMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DatabaseMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Zero(t, ff[0].Usr.Core().Verification)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DatabaseMock {
		return &DatabaseMock{
			FetchByIDFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err1
			},
			UpdateFunc: func(_ context.Context, _ User) error {
				return err2
			},
		}
	}

	inpUsr := Core{
		ActivatedAt:     time.Now(),
		ID:              xid.New(),
		Email:           "user@email.com",
		UnverifiedEmail: "user123@email.com",
	}

	inpTok, _ := inpUsr.InitVerification(TokenTimes{time.Hour, time.Hour})

	cc := map[string]struct {
		DB     *DatabaseMock
		Token  string
		Checks []check
	}{
		"Error returned by Handler.fetchByToken": {
			DB:    dbStub(assert.AnError, nil, nil),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(0),
			),
		},
		"Error returned by Core.CancelVerification": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Verification.ExpiresAt = time.Time{}
				return tmp
			}())),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(0),
			),
		},
		"Error returned by Database.Update": {
			DB:    dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(1),
			),
		},
		"Successful verification cancel": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasResp(false),
				wasUpdateCalled(1),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/", nil)
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.db = c.DB
			hdl.CancelVerification(rec, req.WithContext(
				addChiCtx(nil, "token", c.Token)))
			time.Sleep(time.Millisecond) // to record goroutine func call
			for _, ch := range c.Checks {
				ch(t, c.DB, rec)
			}
		})
	}
}

func TestHandlerFetchByToken(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, User, string, error)

	checks := func(cc ...check) []check { return cc }

	hasUser := func(usr User) check {
		return func(t *testing.T, _ *DatabaseMock, res User, _ string, _ error) {
			assert.Equal(t, usr, res)
		}
	}

	hasToken := func(tok string) check {
		return func(t *testing.T, _ *DatabaseMock, _ User, res string, _ error) {
			assert.Equal(t, tok, res)
		}
	}

	hasError := func(err bool) check {
		return func(t *testing.T, _ *DatabaseMock, _ User, _ string, res error) {
			if err {
				assert.NotNil(t, res)
				return
			}
			assert.Nil(t, res)
		}
	}

	wasFetchByIDCalled := func(count int, id string) check {
		return func(t *testing.T, db *DatabaseMock, _ User, _ string, _ error) {
			ff := db.FetchByIDCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.Equal(t, id, ff[0].ID)
		}
	}

	dbStub := func(err error, usr User) *DatabaseMock {
		return &DatabaseMock{
			FetchByIDFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err
			},
		}
	}

	inpUsr := Core{ID: xid.New()}
	inpTok, _ := inpUsr.InitVerification(TokenTimes{time.Hour, time.Hour})
	inpRawTok, _, _ := FromFullToken(inpTok)

	cc := map[string]struct {
		DB     *DatabaseMock
		Token  string
		Checks []check
	}{
		"No token": {
			DB:    dbStub(nil, toPointer(inpUsr)),
			Token: "",
			Checks: checks(
				hasUser(nil),
				hasToken(""),
				hasError(true),
				wasFetchByIDCalled(0, ""),
			),
		},
		"Invalid token": {
			DB:    dbStub(nil, toPointer(inpUsr)),
			Token: "12345asdfgh",
			Checks: checks(
				hasUser(nil),
				hasToken(""),
				hasError(true),
				wasFetchByIDCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:    dbStub(assert.AnError, nil),
			Token: inpTok,
			Checks: checks(
				hasUser(nil),
				hasToken(""),
				hasError(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
			),
		},
		"Successful fetch by token": {
			DB:    dbStub(nil, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasUser(toPointer(inpUsr)),
				hasToken(inpRawTok),
				hasError(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
			),
		},
	}

	for cn, c := range cc {
		c := c
		t.Run(cn, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "http://test.com/", nil)
			hdl := newHandler()
			hdl.db = c.DB
			usr, tok, err := hdl.fetchByToken(req.WithContext(
				addChiCtx(nil, "token", c.Token)))

			for _, ch := range c.Checks {
				ch(t, c.DB, usr, tok, err)
			}
		})
	}
}

func toJSON(eml, pass string) *bytes.Buffer {
	b := &bytes.Buffer{}
	json.NewEncoder(b).Encode(CoreInput{Email: eml, Password: pass})
	return b
}

func toPointer(c Core) *Core {
	return &c
}

func addChiCtx(ctx context.Context, k, v string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(k, v)
	return context.WithValue(ctx, chi.RouteCtxKey, rctx)
}

func newHandler() *Handler {
	return &Handler{
		onError: httpflow.DefaultErrorExec,
		parse:   DefaultParser,
		create:  DefaultCreator,
	}
}
