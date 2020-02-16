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
	"gopkg.in/guregu/null.v3"
	"gopkg.in/guregu/null.v3/zero"
)

func TestDefaultParser(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/",
		strings.NewReader("{"))
	inp, err := DefaultParser(req)
	assert.Nil(t, inp)
	assert.NotNil(t, err)

	req = httptest.NewRequest("GET", "http://test.com/",
		toJSON("user@email.com", "password1", false))
	inp, err = DefaultParser(req)
	assert.Nil(t, err)
	require.NotNil(t, inp)
	assert.Equal(t, "user@email.com", inp.ExposeCore().Email)
	assert.Equal(t, "password1", inp.ExposeCore().Password)
}

func TestDefaultCreator(t *testing.T) {
	usr, err := DefaultCreator(CoreInput{Email: "user@email.com",
		Password: "password1"})
	assert.Nil(t, err)
	require.NotNil(t, usr)
	assert.Equal(t, "user@email.com", usr.ExposeCore().Email)
	assert.NotZero(t, usr.ExposeCore().PasswordHash)
}

func TestNewHandler(t *testing.T) {
	hdl := NewHandler(sessionup.NewManager(&StoreMock{}), time.Hour,
		&DatabaseMock{}, &EmailSenderMock{}, httpflow.DefaultErrorExec,
		DefaultParser, DefaultCreator, TokenTimes{time.Hour, time.Hour},
		TokenTimes{time.Hour, time.Hour})
	assert.NotZero(t, hdl.sessions)
	assert.Equal(t, time.Hour, hdl.sesDur)
	assert.NotZero(t, hdl.db)
	assert.NotZero(t, hdl.email)
	assert.NotZero(t, hdl.onError)
	assert.NotZero(t, hdl.parse)
	assert.NotZero(t, hdl.create)
	assert.NotZero(t, hdl.verif)
	assert.NotZero(t, hdl.recov)

	assert.NotZero(t, hdl.ServeHTTP())
	assert.NotZero(t, hdl.Routes(true))
}

func TestSetupLinks(t *testing.T) {
	ll := SetupLinks("http://yoursite.com/user")
	require.NotNil(t, ll)
	assert.Equal(t, "http://yoursite.com/user/activ?token=%s",
		ll[httpflow.LinkActivation])
	assert.Equal(t, "http://yoursite.com/user/activ/cancel?token=%s",
		ll[httpflow.LinkActivationCancel])
	assert.Equal(t, "http://yoursite.com/user/verif?token=%s",
		ll[httpflow.LinkVerification])
	assert.Equal(t, "http://yoursite.com/user/verif/cancel?token=%s",
		ll[httpflow.LinkVerificationCancel])
	assert.Equal(t, "http://yoursite.com/user/recov?token=%s",
		ll[httpflow.LinkRecovery])
	assert.Equal(t, "http://yoursite.com/user/recov/cancel?token=%s",
		ll[httpflow.LinkRecoveryCancel])
}

func TestHandlerRegister(t *testing.T) {
	type check func(*testing.T, *DatabaseMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err, rem bool) check {
		return func(t *testing.T, _ *DatabaseMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			co := rec.Header().Get("Set-Cookie")
			assert.NotZero(t, co)
			if rem {
				assert.Contains(t, co, "Expires")
			} else {
				assert.NotContains(t, co, "Expires")
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

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Usr.ExposeCore().Email)
			assert.NotNil(t, ff[0].Usr.ExposeCore().PasswordHash)
			assert.NotNil(t, ff[0].Usr.ExposeCore().ID)
		}
	}

	wasSendAccountActivationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendAccountActivationCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
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

	sessionStoreStub := func(err error) *StoreMock {
		return &StoreMock{
			CreateFunc: func(_ context.Context, _ sessionup.Session) error {
				return err
			},
		}
	}

	inpEml := "user@email.com"

	cc := map[string]struct {
		SessionStore *StoreMock
		DB           *DatabaseMock
		Email        *EmailSenderMock
		Creator      Creator
		Body         io.Reader
		Checks       []check
	}{
		"Error returned by Parser": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         strings.NewReader("{"),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(true, false),
				wasCreateCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Creator": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(inpEml, "password1", false),
			Creator: func(inp Inputer) (User, error) {
				return nil, assert.AnError
			},
			Checks: checks(
				hasResp(true, false),
				wasCreateCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Core.InitVerification": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(inpEml, "password1", false),
			Creator: func(inp Inputer) (User, error) {
				usr := &Core{}
				usr.Init(inp)
				usr.ExposeCore().InitVerification(
					TokenTimes{time.Hour, time.Hour})
				return usr, nil
			},
			Checks: checks(
				hasResp(true, false),
				wasCreateCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Database.Create": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(assert.AnError),
			Email:        emailStub(),
			Body:         toJSON(inpEml, "password1", false),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(true, false),
				wasCreateCalled(1, inpEml),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Session init error": {
			SessionStore: sessionStoreStub(assert.AnError),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(inpEml, "password1", true),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(true, false),
				wasCreateCalled(1, inpEml),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Successful user creation with permanent session": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(inpEml, "password1", true),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(false, true),
				wasCreateCalled(1, inpEml),
				wasSendAccountActivationCalled(1, inpEml),
			),
		},
		"Successful user creation with temporary session": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(inpEml, "password1", false),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(false, false),
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
			hdl.sessions = sessionup.NewManager(c.SessionStore)
			hdl.sesDur = time.Hour
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

	hasResp := func(err, rem bool) check {
		return func(t *testing.T, _ *DatabaseMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			co := rec.Header().Get("Set-Cookie")
			assert.NotZero(t, co)
			if rem {
				assert.Contains(t, co, "Expires")
			} else {
				assert.NotContains(t, co, "Expires")
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

			assert.NotNil(t, ff[0].Ctx)
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

			assert.NotNil(t, ff[0].Ctx)
			assert.True(t, ff[0].Usr.ExposeCore().Recovery.IsEmpty())
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

	sessionStoreStub := func(err error) *StoreMock {
		return &StoreMock{
			CreateFunc: func(_ context.Context, _ sessionup.Session) error {
				return err
			},
		}
	}

	inpUsr := Core{Email: "user@email.com"}
	inpPass := "password1"
	inpUsr.SetPassword(inpPass)

	cc := map[string]struct {
		SessionStore *StoreMock
		DB           *DatabaseMock
		Body         io.Reader
		Checks       []check
	}{
		"Invalid JSON body": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Body:         strings.NewReader("{"),
			Checks: checks(
				hasResp(true, false),
				wasFetchByEmailCalled(0, ""),
				wasUpdateCalled(0),
			),
		},
		"Invalid email": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Body:         toJSON("useremail.com", inpPass, false),
			Checks: checks(
				hasResp(true, false),
				wasFetchByEmailCalled(0, ""),
				wasUpdateCalled(0),
			),
		},
		"Error returned by Database.FetchByEmail": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(assert.AnError, nil, nil),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(true, false),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
			),
		},
		"Incorrect password": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Body:         toJSON(inpUsr.Email, "password2", false),
			Checks: checks(
				hasResp(true, false),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
			),
		},
		"Error returned by Database.Update": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(true, false),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Session init error": {
			SessionStore: sessionStoreStub(assert.AnError),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Body:         toJSON(inpUsr.Email, inpPass, true),
			Checks: checks(
				hasResp(true, false),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Successful user log in with permanent session": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Body:         toJSON(inpUsr.Email, inpPass, true),
			Checks: checks(
				hasResp(false, true),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Successful user log in with temporary session": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, false),
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
			hdl.sessions = sessionup.NewManager(c.SessionStore)
			hdl.sesDur = time.Hour
			hdl.db = c.DB
			hdl.LogIn(rec, req)
			for _, ch := range c.Checks {
				ch(t, c.DB, rec)
			}
		})
	}
}

func TestHandlerLogout(t *testing.T) {
	type check func(*testing.T, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	sessionStoreStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByIDFunc: func(_ context.Context, _ string) error {
				return err
			},
		}
	}

	cc := map[string]struct {
		SessionStore *StoreMock
		Checks       []check
	}{
		"Session revokation error": {
			SessionStore: sessionStoreStub(assert.AnError),
			Checks: checks(
				hasResp(true),
			),
		},
		"Successful log out": {
			SessionStore: sessionStoreStub(nil),
			Checks: checks(
				hasResp(false),
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
			hdl.sessions = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
			hdl.LogOut(rec, req.WithContext(sessionup.NewContext(
				context.Background(), sessionup.Session{
					ID: "12345"})))
			for _, ch := range c.Checks {
				ch(t, rec)
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

			assert.NotNil(t, ff[0].Ctx)
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

			assert.NotNil(t, ff[0].Ctx)
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

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Usr.ExposeCore().UnverifiedEmail.String)
			assert.NotZero(t, ff[0].Usr.ExposeCore().PasswordHash)

			if verif {
				assert.NotZero(t, ff[0].Usr.ExposeCore().Verification)
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

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
		}
	}

	wasSendPasswordChangedCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendPasswordChangedCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
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

	sessionStoreStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
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
		DB           *DatabaseMock
		Email        *EmailSenderMock
		SessionStore *StoreMock
		Body         io.Reader
		Session      bool
		Checks       []check
	}{
		"No active session": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Session:      false,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
				wasUpdateCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Invalid JSON body": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         strings.NewReader("{"),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
				wasUpdateCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:           dbStub(assert.AnError, nil, nil),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by User.ApplyInput": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, "pass", false),
			Session:      true,
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
				tmp.Verification.NextAt = null.TimeFrom(time.Now().Add(time.Hour))
				return tmp
			}())),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by Database.Update": {
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1, inpNewEml, true),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Other sessions revokation error": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(assert.AnError),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1, inpNewEml, true),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Successful user update with only password change": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON("", inpNewPass, false),
			Session:      true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(1, inpUsr.Email),
			),
		},
		"Successful user update with only email change": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, "", false),
			Session:      true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasUpdateCalled(1, inpNewEml, true),
				wasSendEmailVerificationCalled(1, inpNewEml),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Successful user update with email and password changes": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Session:      true,
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
			hdl.sessions = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
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

			assert.NotNil(t, ff[0].Ctx)
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

			assert.NotNil(t, ff[0].Ctx)
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

			assert.NotNil(t, ff[0].Ctx)
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

	sessionStoreStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	inpUsr := Core{
		ID:    xid.New(),
		Email: "user@email.com",
	}
	inpUsr.SetPassword("password1")

	inpPass := "password1"

	cc := map[string]struct {
		DB           *DatabaseMock
		Email        *EmailSenderMock
		SessionStore *StoreMock
		Body         io.Reader
		Session      bool
		Checks       []check
	}{
		"No active session": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON("", inpPass, false),
			Session:      false,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
				wasDeleteByIDCalled(0, ""),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Invalid JSON body": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         strings.NewReader("{"),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, ""),
				wasDeleteByIDCalled(0, ""),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:           dbStub(assert.AnError, nil, nil),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasDeleteByIDCalled(0, ""),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Incorrect password": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON("", "password2", false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasDeleteByIDCalled(0, ""),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by Database.DeleteByID": {
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasDeleteByIDCalled(1, inpUsr.ID.String()),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Sessions revokation error": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(assert.AnError),
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID.String()),
				wasDeleteByIDCalled(1, inpUsr.ID.String()),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Successful account deletion": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON("", inpPass, false),
			Session:      true,
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
			hdl.sessions = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
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

func TestHandlerFetchSessions(t *testing.T) {
	type check func(*testing.T, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.NotZero(t, rec.Body.Len())
		}
	}

	sessionStoreStub := func(err error, ss []sessionup.Session) *StoreMock {
		return &StoreMock{
			FetchByUserKeyFunc: func(_ context.Context, _ string) ([]sessionup.Session, error) {
				return ss, err
			},
		}
	}

	inpSS := []sessionup.Session{
		{ID: "12345"},
		{ID: "123456"},
	}

	cc := map[string]struct {
		SessionStore *StoreMock
		Checks       []check
	}{
		"Session fetch error": {
			SessionStore: sessionStoreStub(assert.AnError, nil),
			Checks: checks(
				hasResp(true),
			),
		},
		"No sessions found": {
			SessionStore: sessionStoreStub(nil, nil),
			Checks: checks(
				hasResp(true),
			),
		},
		"Successful fetch": {
			SessionStore: sessionStoreStub(nil, inpSS),
			Checks: checks(
				hasResp(false),
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
			hdl.sessions = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
			hdl.FetchSessions(rec, req.WithContext(sessionup.NewContext(
				context.Background(), sessionup.Session{
					ID: "12345"})))
			for _, ch := range c.Checks {
				ch(t, rec)
			}
		})
	}
}

func TestHandlerRevokeSession(t *testing.T) {
	type check func(*testing.T, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	sessionStoreStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByIDFunc: func(_ context.Context, _ string) error {
				return err
			},
		}
	}

	inpID := "12345"

	cc := map[string]struct {
		SessionStore *StoreMock
		ID           string
		Session      bool
		Checks       []check
	}{
		"No active session": {
			SessionStore: sessionStoreStub(nil),
			ID:           inpID,
			Checks: checks(
				hasResp(true),
			),
		},
		"Matching session ID": {
			SessionStore: sessionStoreStub(nil),
			ID:           "123456",
			Session:      true,
			Checks: checks(
				hasResp(true),
			),
		},
		"Session revokation error": {
			SessionStore: sessionStoreStub(assert.AnError),
			ID:           inpID,
			Session:      true,
			Checks: checks(
				hasResp(true),
			),
		},
		"Successful session revokation": {
			SessionStore: sessionStoreStub(nil),
			ID:           inpID,
			Session:      true,
			Checks: checks(
				hasResp(false),
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
			hdl.sessions = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))

			if c.Session {
				req = req.WithContext(sessionup.NewContext(
					context.Background(), sessionup.Session{
						ID: "123456"}))
			}

			req = req.WithContext(addChiCtx(req.Context(), "id", c.ID))

			hdl.RevokeSession(rec, req)
			for _, ch := range c.Checks {
				ch(t, rec)
			}
		})
	}
}

func TestHandlerRevokeOtherSessions(t *testing.T) {
	type check func(*testing.T, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())
				return
			}
			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	sessionStoreStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	cc := map[string]struct {
		SessionStore *StoreMock
		Checks       []check
	}{
		"Other sessions revokation error": {
			SessionStore: sessionStoreStub(assert.AnError),
			Checks: checks(
				hasResp(true),
			),
		},
		"Successful other sessions revokation": {
			SessionStore: sessionStoreStub(nil),
			Checks: checks(
				hasResp(false),
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
			hdl.sessions = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
			hdl.RevokeOtherSessions(rec, req.WithContext(sessionup.NewContext(
				context.Background(), sessionup.Session{
					ID: "12345"})))
			for _, ch := range c.Checks {
				ch(t, rec)
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

			assert.NotNil(t, ff[0].Ctx)
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

			assert.NotNil(t, ff[0].Ctx)
			assert.NotZero(t, ff[0].Usr.ExposeCore().Verification)
		}
	}

	wasSendEmailVerificationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendEmailVerificationCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
		}
	}

	wasSendAccountActivationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendAccountActivationCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
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
				tmp.Verification.NextAt = null.TimeFrom(time.Now().Add(time.Hour))
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
				tmp.UnverifiedEmail = zero.StringFrom(tmp.Email)
				tmp.ActivatedAt = zero.TimeFrom(time.Now())
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

			assert.NotNil(t, ff[0].Ctx)
			assert.True(t, ff[0].Usr.ExposeCore().Verification.IsEmpty())
		}
	}

	wasSendEmailChangedCalled := func(count int, oEml, nEml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendEmailChangedCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
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
		ActivatedAt:     zero.TimeFrom(time.Now()),
		ID:              xid.New(),
		Email:           "user@email.com",
		UnverifiedEmail: zero.StringFrom("user123@email.com"),
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
				tmp.Verification.ExpiresAt = null.TimeFrom(time.Time{})
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
				tmp.ActivatedAt = zero.TimeFrom(time.Time{})
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
				wasSendEmailChangedCalled(1, inpUsr.Email, inpUsr.UnverifiedEmail.String),
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

			assert.NotNil(t, ff[0].Ctx)
			assert.True(t, ff[0].Usr.ExposeCore().Verification.IsEmpty())
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
		ActivatedAt:     zero.TimeFrom(time.Now()),
		ID:              xid.New(),
		Email:           "user@email.com",
		UnverifiedEmail: zero.StringFrom("user123@email.com"),
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
				tmp.Verification.ExpiresAt = null.TimeFrom(time.Time{})
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

func TestHandlerInitRecovery(t *testing.T) {
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

	wasFetchByEmailCalled := func(count int, eml string) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByEmailCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DatabaseMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.NotZero(t, ff[0].Usr.ExposeCore().Recovery)
		}
	}

	wasSendRecoveryCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendRecoveryCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
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

	emailStub := func() *EmailSenderMock {
		return &EmailSenderMock{
			SendRecoveryFunc: func(_ context.Context, _, _ string) {},
		}
	}

	inpUsr := Core{
		ID:    xid.New(),
		Email: "user@email.com",
	}

	cc := map[string]struct {
		DB     *DatabaseMock
		Email  *EmailSenderMock
		Body   io.Reader
		Checks []check
	}{
		"Invalid JSON body": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Email: emailStub(),
			Body:  strings.NewReader("{"),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(0, ""),
				wasUpdateCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Invalid email": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Email: emailStub(),
			Body:  toJSON("useremail.com", "", false),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(0, ""),
				wasUpdateCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByEmail": {
			DB:    dbStub(assert.AnError, nil, nil),
			Email: emailStub(),
			Body:  toJSON("user@email.com", "", false),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Error returned by Core.InitRecovery": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Recovery.NextAt = null.TimeFrom(time.Now().Add(time.Hour))
				return tmp
			}())),
			Email: emailStub(),
			Body:  toJSON("user@email.com", "", false),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Error returned by Database.Update": {
			DB:    dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email: emailStub(),
			Body:  toJSON("user@email.com", "", false),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Successful recovery init": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Email: emailStub(),
			Body:  toJSON("user@email.com", "", false),
			Checks: checks(
				hasResp(false),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
				wasSendRecoveryCalled(1, inpUsr.Email),
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
			hdl.InitRecovery(rec, req)
			time.Sleep(time.Millisecond) // to record goroutine func call
			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func TestHandlerRecover(t *testing.T) {
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

			assert.NotNil(t, ff[0].Ctx)
			assert.True(t, ff[0].Usr.ExposeCore().Recovery.IsEmpty())
			assert.NotZero(t, ff[0].Usr.ExposeCore().PasswordHash)
		}
	}

	wasSendPasswordChangedCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DatabaseMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendPasswordChangedCalls()
			require.Equal(t, count, len(ff))
			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.True(t, ff[0].Recov)
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
			SendPasswordChangedFunc: func(_ context.Context, _ string, _ bool) {},
		}
	}

	sessionStoreStub := func(err error) *StoreMock {
		return &StoreMock{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	inpUsr := Core{
		ActivatedAt: zero.TimeFrom(time.Now()),
		ID:          xid.New(),
		Email:       "user@email.com",
	}

	inpTok, _ := inpUsr.InitRecovery(TokenTimes{time.Hour, time.Hour})

	cc := map[string]struct {
		DB           *DatabaseMock
		Email        *EmailSenderMock
		SessionStore *StoreMock
		Token        string
		Body         io.Reader
		Checks       []check
	}{
		"Error returned by Handler.fetchByToken": {
			DB:           dbStub(assert.AnError, nil, nil),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Token:        inpTok,
			Body:         toJSON("", "password1", false),
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(0),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Invalid JSON body": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Token:        inpTok,
			Body:         strings.NewReader("{"),
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(0),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by Core.Recover": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Recovery.ExpiresAt = null.TimeFrom(time.Time{})
				return tmp
			}())),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Token:        inpTok,
			Body:         toJSON("", "password1", false),
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(0),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by Database.Update": {
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Token:        inpTok,
			Body:         toJSON("", "password1", false),
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(1),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Sessions revokation error": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(assert.AnError),
			Token:        inpTok,
			Body:         toJSON("", "password1", false),
			Checks: checks(
				hasResp(true),
				wasUpdateCalled(1),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Successful recovery": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Token:        inpTok,
			Body:         toJSON("", "password1", false),
			Checks: checks(
				hasResp(false),
				wasUpdateCalled(1),
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
			hdl.sessions = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
			hdl.db = c.DB
			hdl.email = c.Email
			hdl.Recover(rec, req.WithContext(
				addChiCtx(nil, "token", c.Token)))
			time.Sleep(time.Millisecond) // to record goroutine func call
			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func TestHandlerPingRecovery(t *testing.T) {
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

	dbStub := func(err error, usr User) *DatabaseMock {
		return &DatabaseMock{
			FetchByIDFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err
			},
		}
	}

	inpUsr := Core{
		ActivatedAt: zero.TimeFrom(time.Now()),
		ID:          xid.New(),
		Email:       "user@email.com",
	}

	inpTok, _ := inpUsr.InitRecovery(TokenTimes{time.Hour, time.Hour})

	cc := map[string]struct {
		DB     *DatabaseMock
		Email  *EmailSenderMock
		Token  string
		Checks []check
	}{
		"Error returned by Handler.fetchByToken": {
			DB:    dbStub(assert.AnError, nil),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
			),
		},
		"Error returned by Token.Check": {
			DB: dbStub(nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Recovery.ExpiresAt = null.TimeFrom(time.Time{})
				return tmp
			}())),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
			),
		},
		"Successful recovery ping": {
			DB:    dbStub(nil, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasResp(false),
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
			hdl.PingRecovery(rec, req.WithContext(
				addChiCtx(nil, "token", c.Token)))
			for _, ch := range c.Checks {
				ch(t, c.DB, rec)
			}
		})
	}
}

func TestHandlerCancelRecovery(t *testing.T) {
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

			assert.NotNil(t, ff[0].Ctx)
			assert.True(t, ff[0].Usr.ExposeCore().Recovery.IsEmpty())
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
		ActivatedAt: zero.TimeFrom(time.Now()),
		ID:          xid.New(),
		Email:       "user@email.com",
	}

	inpTok, _ := inpUsr.InitRecovery(TokenTimes{time.Hour, time.Hour})

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
		"Error returned by Core.CancelRecovery": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Recovery.ExpiresAt = null.TimeFrom(time.Time{})
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
		"Successful recovery cancel": {
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
			hdl.CancelRecovery(rec, req.WithContext(
				addChiCtx(nil, "token", c.Token)))
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

			assert.NotNil(t, ff[0].Ctx)
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

func toJSON(eml, pass string, rem bool) *bytes.Buffer {
	b := &bytes.Buffer{}
	json.NewEncoder(b).Encode(CoreInput{Email: eml, Password: pass,
		RememberMe: rem})
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
		onError: func(error) {},
		parse:   DefaultParser,
		create:  DefaultCreator,
	}
}
