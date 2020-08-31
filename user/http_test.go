package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swithek/httpflow"
	depMock "github.com/swithek/httpflow/_mock"
	"github.com/swithek/httpflow/timeutil"
	"github.com/swithek/sessionup"
	"gopkg.in/guregu/null.v3"
	"gopkg.in/guregu/null.v3/zero"
)

const (
	_email = "user@email.com"
)

func Test_SetSessionDuration(t *testing.T) {
	h := &Handler{}
	SetSessionDuration(time.Hour)(h)
	assert.Equal(t, time.Hour, h.session.duration)
}

func Test_SetVerificationLifetime(t *testing.T) {
	h := &Handler{}
	SetVerificationLifetime(VerifLifetime)(h)
	assert.Equal(t, VerifLifetime, h.token.verif)
}

func Test_SetRecoveryLifetime(t *testing.T) {
	h := &Handler{}
	SetRecoveryLifetime(RecovLifetime)(h)
	assert.Equal(t, RecovLifetime, h.token.recov)
}

func Test_SetParser(t *testing.T) {
	h := &Handler{}
	SetParser(DefaultParser)(h)
	assert.NotNil(t, h.ext.parse)
}

func Test_SetCreator(t *testing.T) {
	h := &Handler{}
	SetCreator(DefaultCreator)(h)
	assert.NotNil(t, h.ext.create)
}

func Test_SetLoginCheck(t *testing.T) {
	h := &Handler{}
	SetLoginCheck(DefaultLoginCheck(true))(h)
	assert.NotNil(t, h.ext.loginCheck)
}

func Test_SetDeleteCheck(t *testing.T) {
	h := &Handler{}
	SetDeleteCheck(DefaultDeleteCheck)(h)
	assert.NotNil(t, h.ext.deleteCheck)
}

func Test_NewHandler(t *testing.T) {
	h := NewHandler(
		zerolog.Nop(),
		&DBMock{},
		&EmailSenderMock{},
		sessionup.NewManager(&depMock.SessionStore{}),
		SetSessionDuration(time.Hour),
		SetVerificationLifetime(VerifLifetime),
	)

	assert.NotZero(t, h.log)
	assert.NotNil(t, h.db)
	assert.NotNil(t, h.email)
	assert.NotNil(t, h.session)
	assert.Equal(t, time.Hour, h.session.duration)
	assert.NotNil(t, h.ext.parse)
	assert.NotNil(t, h.ext.create)
	assert.NotNil(t, h.ext.loginCheck)
	assert.NotNil(t, h.ext.deleteCheck)
	assert.Equal(t, VerifLifetime, h.token.verif)
	assert.NotZero(t, h.token.recov)
	assert.NotNil(t, h.Router(true))
}

func Test_Handler_Defaults(t *testing.T) {
	var h Handler

	h.Defaults()
	assert.Equal(t, SessionDuration, h.session.duration)
	assert.Equal(t, VerifLifetime, h.token.verif)
	assert.Equal(t, RecovLifetime, h.token.recov)
	assert.NotNil(t, h.ext.parse)
	assert.NotNil(t, h.ext.create)
	assert.NotNil(t, h.ext.loginCheck)
	assert.NotNil(t, h.ext.deleteCheck)
}

func Test_DefaultParser(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/", strings.NewReader("{"))
	inp, err := DefaultParser(req)
	assert.Nil(t, inp)
	assert.Error(t, err)

	req = httptest.NewRequest("GET", "http://test.com/",
		strings.NewReader(toJSON(_email, "password1", false)))
	inp, err = DefaultParser(req)
	assert.NoError(t, err)
	require.NotNil(t, inp)
	assert.Equal(t, _email, inp.ExposeCore().Email)
	assert.Equal(t, "password1", inp.ExposeCore().Password)
}

func Test_DefaultCreator(t *testing.T) {
	usr, err := DefaultCreator(context.Background(), CoreInput{})
	assert.Error(t, err)
	assert.Nil(t, usr)

	usr, err = DefaultCreator(context.Background(),
		CoreInput{Email: _email, Password: "password1"})
	assert.NoError(t, err)
	require.NotNil(t, usr)
	assert.Equal(t, _email, usr.ExposeCore().Email)
	assert.NotZero(t, usr.ExposeCore().PasswordHash)
}

func Test_DefaultLoginCheck(t *testing.T) {
	cr := &Core{}
	assert.NoError(t, DefaultLoginCheck(true)(context.Background(), cr))
	assert.Equal(t, ErrNotActivated, DefaultLoginCheck(false)(context.Background(), cr))

	cr.ActivatedAt = zero.TimeFrom(timeutil.Now())
	assert.NoError(t, DefaultLoginCheck(false)(context.Background(), cr))
}

func Test_DefaultDeleteCheck(t *testing.T) {
	assert.NoError(t, DefaultDeleteCheck(context.Background(), nil))
}

func Test_SetupLinks(t *testing.T) {
	ll := SetupLinks("http://yoursite.com/user")
	require.NotNil(t, ll)
	assert.Equal(t, "http://yoursite.com/user/activation?token=%s",
		ll[httpflow.LinkActivation])
	assert.Equal(t, "http://yoursite.com/user/activation/cancel?token=%s",
		ll[httpflow.LinkActivationCancel])
	assert.Equal(t, "http://yoursite.com/user/verification?token=%s",
		ll[httpflow.LinkVerification])
	assert.Equal(t, "http://yoursite.com/user/verification/cancel?token=%s",
		ll[httpflow.LinkVerificationCancel])
	assert.Equal(t, "http://yoursite.com/user/recovery?token=%s",
		ll[httpflow.LinkRecovery])
	assert.Equal(t, "http://yoursite.com/user/recovery/cancel?token=%s",
		ll[httpflow.LinkRecoveryCancel])
}

func Test_Handler_Register(t *testing.T) {
	type check func(*testing.T, *DBMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err, rem bool) check {
		return func(t *testing.T, _ *DBMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
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

	wasCreateUserCalled := func(count int, eml string) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.CreateUserCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			require.NotNil(t, ff[0].Usr)
			assert.Equal(t, eml, ff[0].Usr.ExposeCore().Email)
			assert.NotNil(t, ff[0].Usr.ExposeCore().PasswordHash)
			assert.NotNil(t, ff[0].Usr.ExposeCore().ID)
		}
	}

	wasSendAccountActivationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DBMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendAccountActivationCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
		}
	}

	dbStub := func(err error) *DBMock {
		return &DBMock{
			CreateUserFunc: func(_ context.Context, _ User) error {
				return err
			},
		}
	}

	emailStub := func() *EmailSenderMock {
		return &EmailSenderMock{
			SendAccountActivationFunc: func(_ context.Context, _, _ string) {},
		}
	}

	sessionStoreStub := func(err error) *depMock.SessionStore {
		return &depMock.SessionStore{
			CreateFunc: func(_ context.Context, _ sessionup.Session) error {
				return err
			},
		}
	}

	cc := map[string]struct {
		SessionStore *depMock.SessionStore
		DB           *DBMock
		Email        *EmailSenderMock
		Creator      Creator
		Body         string
		Checks       []check
	}{
		"Error returned by Parser": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         "{",
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(true, false),
				wasCreateUserCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Creator": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(_email, "password1", false),
			Creator: func(ctx context.Context, inp Inputer) (User, error) {
				return nil, assert.AnError
			},
			Checks: checks(
				hasResp(true, false),
				wasCreateUserCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Core.InitVerification": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(_email, "password1", false),
			Creator: func(ctx context.Context, inp Inputer) (User, error) {
				usr, _ := NewCore(inp)
				_, err := usr.ExposeCore().InitVerification(
					TokenLifetime{time.Hour, time.Hour})

				require.NoError(t, err)

				return usr, nil
			},
			Checks: checks(
				hasResp(true, false),
				wasCreateUserCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by DB.CreateUser": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(assert.AnError),
			Email:        emailStub(),
			Body:         toJSON(_email, "password1", false),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(true, false),
				wasCreateUserCalled(1, _email),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Session init error": {
			SessionStore: sessionStoreStub(assert.AnError),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(_email, "password1", true),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(true, false),
				wasCreateUserCalled(1, _email),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Successful user creation with persistent session": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(_email, "password1", true),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(false, true),
				wasCreateUserCalled(1, _email),
				wasSendAccountActivationCalled(1, _email),
			),
		},
		"Successful user creation with temporary session": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(_email, "password1", false),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(false, false),
				wasCreateUserCalled(1, _email),
				wasSendAccountActivationCalled(1, _email),
			),
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "http://test.com/",
				strings.NewReader(c.Body))
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.session.manager = sessionup.NewManager(c.SessionStore)
			hdl.session.duration = time.Hour
			hdl.db = c.DB
			hdl.email = c.Email
			hdl.ext.create = c.Creator
			hdl.Register(rec, req)
			time.Sleep(time.Millisecond * 30) // to record goroutine func call

			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func Test_Handler_LogIn(t *testing.T) {
	type check func(*testing.T, *DBMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(rem bool, code int) check {
		return func(t *testing.T, _ *DBMock, rec *httptest.ResponseRecorder) {
			assert.Equal(t, code, rec.Code)

			if code >= 400 {
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

			assert.Zero(t, rec.Body.Len())
		}
	}

	wasFetchUserByEmailCalled := func(count int, eml string) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchUserByEmailCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	wasUpdateUserCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateUserCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			require.NotNil(t, ff[0].Usr)
			assert.True(t, ff[0].Usr.ExposeCore().Recovery.IsEmpty())
		}
	}

	dbStub := func(err1, err2 error, usr User) *DBMock {
		return &DBMock{
			FetchUserByEmailFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err1
			},
			UpdateUserFunc: func(_ context.Context, _ User) error {
				return err2
			},
		}
	}

	sessionStoreStub := func(err error) *depMock.SessionStore {
		return &depMock.SessionStore{
			CreateFunc: func(_ context.Context, _ sessionup.Session) error {
				return err
			},
		}
	}

	inpUsr := Core{Email: _email}
	inpPass := "password1"
	_, err := inpUsr.SetPassword(inpPass)
	require.NoError(t, err)

	cc := map[string]struct {
		Open         bool
		SessionStore *depMock.SessionStore
		DB           *DBMock
		LoginCheck   LoginCheck
		Body         string
		Checks       []check
	}{
		"Invalid JSON body": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			LoginCheck:   DefaultLoginCheck(true),
			Body:         "{",
			Checks: checks(
				hasResp(false, 400),
				wasFetchUserByEmailCalled(0, ""),
				wasUpdateUserCalled(0),
			),
		},
		"Invalid email": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			LoginCheck:   DefaultLoginCheck(true),
			Body:         toJSON("useremail.com", inpPass, false),
			Checks: checks(
				hasResp(false, 401),
				wasFetchUserByEmailCalled(0, ""),
				wasUpdateUserCalled(0),
			),
		},
		"Error returned by DB.FetchUserByEmail": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(assert.AnError, nil, nil),
			LoginCheck:   DefaultLoginCheck(true),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 500),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(0),
			),
		},
		"Not found error returned by DB.FetchUserByEmail": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(httpflow.ErrNotFound, nil, nil),
			LoginCheck:   DefaultLoginCheck(true),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 401),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(0),
			),
		},
		"Account not activated when required": {
			Open:         false,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			LoginCheck:   DefaultLoginCheck(false),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 403),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(0),
			),
		},
		"Incorrect password": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			LoginCheck:   DefaultLoginCheck(true),
			Body:         toJSON(inpUsr.Email, "password2", false),
			Checks: checks(
				hasResp(false, 401),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(0),
			),
		},
		"Error returned by DB.UpdateUser": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			LoginCheck:   DefaultLoginCheck(true),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 500),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(1),
			),
		},
		"Session init error": {
			Open:         true,
			SessionStore: sessionStoreStub(assert.AnError),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			LoginCheck:   DefaultLoginCheck(true),
			Body:         toJSON(inpUsr.Email, inpPass, true),
			Checks: checks(
				hasResp(false, 500),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(1),
			),
		},
		"Successful user log in with persistent session": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			LoginCheck:   DefaultLoginCheck(true),
			Body:         toJSON(inpUsr.Email, inpPass, true),
			Checks: checks(
				hasResp(true, 204),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(1),
			),
		},
		"Successful user log in with temporary session": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			LoginCheck:   DefaultLoginCheck(true),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 204),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(1),
			),
		},
		"Successful user log in with persistent session when activation is required": {
			Open:         false,
			SessionStore: sessionStoreStub(nil),
			DB: dbStub(nil, nil, func() *Core {
				tmp := inpUsr
				tmp.ActivatedAt = zero.TimeFrom(timeutil.Now())
				return &tmp
			}()),
			LoginCheck: DefaultLoginCheck(true),
			Body:       toJSON(inpUsr.Email, inpPass, true),
			Checks: checks(
				hasResp(true, 204),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(1),
			),
		},
		"Successful user log in with temporary session when activation is required": {
			Open:         false,
			SessionStore: sessionStoreStub(nil),
			DB: dbStub(nil, nil, func() *Core {
				tmp := inpUsr
				tmp.ActivatedAt = zero.TimeFrom(timeutil.Now())
				return &tmp
			}()),
			LoginCheck: DefaultLoginCheck(true),
			Body:       toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 204),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(1),
			),
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "http://test.com/",
				strings.NewReader(c.Body))
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.session.manager = sessionup.NewManager(c.SessionStore)
			hdl.session.duration = time.Hour
			hdl.db = c.DB
			hdl.ext.loginCheck = c.LoginCheck
			hdl.LogIn(rec, req)

			for _, ch := range c.Checks {
				ch(t, c.DB, rec)
			}
		})
	}
}

func Test_Handler_Logout(t *testing.T) {
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

	sessionStoreStub := func(err error) *depMock.SessionStore {
		return &depMock.SessionStore{
			DeleteByIDFunc: func(_ context.Context, _ string) error {
				return err
			},
		}
	}

	cc := map[string]struct {
		SessionStore *depMock.SessionStore
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
			hdl.session.manager = sessionup.NewManager(c.SessionStore,
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

func Test_Handler_Fetch(t *testing.T) {
	type check func(*testing.T, *DBMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.NotZero(t, rec.Body.Len())
		}
	}

	wasFetchUserByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchUserByIDCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, id, ff[0].ID)
		}
	}

	dbStub := func(err error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err
			},
		}
	}

	inpUsr := Core{ID: xid.New()}

	cc := map[string]struct {
		DB      *DBMock
		Session bool
		Checks  []check
	}{
		"No active session": {
			DB: dbStub(nil, toPointer(inpUsr)),
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(0, xid.ID{}),
			),
		},
		"Error returned by DB.FetchUserByID": {
			DB:      dbStub(assert.AnError, nil),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
			),
		},
		"Successful user fetch": {
			DB:      dbStub(nil, toPointer(inpUsr)),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchUserByIDCalled(1, inpUsr.ID),
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

//nolint:gocognit // complex testing is required.
func Test_Handler_Update(t *testing.T) {
	type check func(*testing.T, *DBMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasFetchUserByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchUserByIDCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasUpdateUserCalled := func(count int, eml string, verif bool) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateUserCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			require.NotNil(t, ff[0].Usr)
			assert.Equal(t, eml, ff[0].Usr.ExposeCore().UnverifiedEmail.String)
			assert.NotZero(t, ff[0].Usr.ExposeCore().PasswordHash)

			if verif {
				assert.NotZero(t, ff[0].Usr.ExposeCore().Verification)
			}
		}
	}

	wasSendEmailVerificationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DBMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendEmailVerificationCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
		}
	}

	wasSendPasswordChangedCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DBMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendPasswordChangedCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.False(t, ff[0].Recov)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err1
			},
			UpdateUserFunc: func(_ context.Context, _ User) error {
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

	sessionStoreStub := func(err error) *depMock.SessionStore {
		return &depMock.SessionStore{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	inpUsr := Core{
		ID:           xid.New(),
		Email:        _email,
		PasswordHash: []byte("password1"),
	}
	inpNewEml := "user123@email.com"
	inpNewPass := "password@1"

	cc := map[string]struct {
		DB           *DBMock
		Email        *EmailSenderMock
		SessionStore *depMock.SessionStore
		Body         string
		Session      bool
		Checks       []check
	}{
		"No active session": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(0, xid.ID{}),
				wasUpdateUserCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Invalid JSON body": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         "{",
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(0, xid.ID{}),
				wasUpdateUserCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by DB.FetchUserByID": {
			DB:           dbStub(assert.AnError, nil, nil),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(0, "", false),
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
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by Core.InitVerification": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Verification.NextAt = null.TimeFrom(timeutil.Now().Add(time.Hour))
				return tmp
			}())),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(0, "", false),
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
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(0, "", false),
				wasSendEmailVerificationCalled(0, ""),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by DB.UpdateUser": {
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Body:         toJSON(inpNewEml, inpNewPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(1, inpNewEml, true),
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
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(1, "", false),
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
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(1, inpNewEml, true),
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
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(1, inpNewEml, true),
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
				strings.NewReader(c.Body))
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.session.manager = sessionup.NewManager(c.SessionStore,
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

func Test_Handler_Delete(t *testing.T) {
	type check func(*testing.T, *DBMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasFetchUserByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchUserByIDCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasDeleteUserByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.DeleteUserByIDCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasSendAccountDeletedCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DBMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendAccountDeletedCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err1
			},
			DeleteUserByIDFunc: func(_ context.Context, _ xid.ID) error {
				return err2
			},
		}
	}

	emailStub := func() *EmailSenderMock {
		return &EmailSenderMock{
			SendAccountDeletedFunc: func(_ context.Context, _ string) {},
		}
	}

	sessionStoreStub := func(err error) *depMock.SessionStore {
		return &depMock.SessionStore{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	inpUsr := Core{
		ID:    xid.New(),
		Email: _email,
	}
	_, err := inpUsr.SetPassword("password1")
	require.NoError(t, err)

	inpPass := "password1"

	cc := map[string]struct {
		DB           *DBMock
		Email        *EmailSenderMock
		SessionStore *depMock.SessionStore
		DeleteCheck  DeleteCheck
		Body         string
		Session      bool
		Checks       []check
	}{
		"No active session": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			DeleteCheck:  DefaultDeleteCheck,
			Body:         toJSON("", inpPass, false),
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(0, xid.ID{}),
				wasDeleteUserByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Invalid JSON body": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			DeleteCheck:  DefaultDeleteCheck,
			Body:         "{",
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(0, xid.ID{}),
				wasDeleteUserByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by DB.FetchUserByID": {
			DB:           dbStub(assert.AnError, nil, nil),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			DeleteCheck:  DefaultDeleteCheck,
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasDeleteUserByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by delete check": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			DeleteCheck: func(_ context.Context, _ User) error {
				return assert.AnError
			},
			Body:    toJSON("", inpPass, false),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasDeleteUserByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Incorrect password": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			DeleteCheck:  DefaultDeleteCheck,
			Body:         toJSON("", "password2", false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasDeleteUserByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Sessions revokation error": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(assert.AnError),
			DeleteCheck:  DefaultDeleteCheck,
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasDeleteUserByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by DB.DeleteUserByID": {
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			DeleteCheck:  DefaultDeleteCheck,
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasDeleteUserByIDCalled(1, inpUsr.ID),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Successful account deletion": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			DeleteCheck:  DefaultDeleteCheck,
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(false),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasDeleteUserByIDCalled(1, inpUsr.ID),
				wasSendAccountDeletedCalled(1, inpUsr.Email),
			),
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "http://test.com/",
				strings.NewReader(c.Body))
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.session.manager = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
			hdl.db = c.DB
			hdl.email = c.Email
			hdl.ext.deleteCheck = c.DeleteCheck

			if c.Session {
				req = req.WithContext(sessionup.NewContext(
					context.Background(),
					sessionup.Session{UserKey: inpUsr.ID.String()}))
			}

			hdl.Delete(rec, req)
			time.Sleep(time.Millisecond * 30) // to record goroutine func call

			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func Test_Handler_FetchSessions(t *testing.T) {
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

	sessionStoreStub := func(err error, ss []sessionup.Session) *depMock.SessionStore {
		return &depMock.SessionStore{
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
		SessionStore *depMock.SessionStore
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
			hdl.session.manager = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
			hdl.FetchSessions(rec, req.WithContext(sessionup.NewContext(
				context.Background(), sessionup.Session{ID: "12345"})))

			for _, ch := range c.Checks {
				ch(t, rec)
			}
		})
	}
}

func Test_Handler_RevokeSession(t *testing.T) {
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

	sessionStoreStub := func(ses sessionup.Session, isSes bool, err1, err2 error) *depMock.SessionStore {
		return &depMock.SessionStore{
			FetchByIDFunc: func(_ context.Context, _ string) (sessionup.Session, bool, error) {
				return ses, isSes, err1
			},
			DeleteByIDFunc: func(_ context.Context, _ string) error {
				return err2
			},
		}
	}

	inpSes := sessionup.Session{ID: "123456", UserKey: xid.New().String()}

	cc := map[string]struct {
		SessionStore *depMock.SessionStore
		ID           string
		Session      bool
		Checks       []check
	}{
		"No active session": {
			SessionStore: sessionStoreStub(inpSes, true, nil, nil),
			ID:           inpSes.ID,
			Checks: checks(
				hasResp(true),
			),
		},
		"No id provided": {
			SessionStore: sessionStoreStub(inpSes, true, nil, nil),
			ID:           "",
			Session:      true,
			Checks: checks(
				hasResp(true),
			),
		},
		"Matching session ID": {
			SessionStore: sessionStoreStub(inpSes, true, nil, nil),
			ID:           "12345",
			Session:      true,
			Checks: checks(
				hasResp(true),
			),
		},
		"Session revokation error": {
			SessionStore: sessionStoreStub(inpSes, true, nil, assert.AnError),
			ID:           inpSes.ID,
			Session:      true,
			Checks: checks(
				hasResp(true),
			),
		},
		"Successful session revokation": {
			SessionStore: sessionStoreStub(inpSes, true, nil, nil),
			ID:           inpSes.ID,
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
			hdl.session.manager = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))

			if c.Session {
				req = req.WithContext(sessionup.NewContext(
					context.Background(), sessionup.Session{
						ID:      "12345",
						UserKey: inpSes.UserKey,
					}))
			}

			req = req.WithContext(addChiCtx(req.Context(), "id", c.ID))
			hdl.RevokeSession(rec, req)

			for _, ch := range c.Checks {
				ch(t, rec)
			}
		})
	}
}

func Test_Handler_RevokeOtherSessions(t *testing.T) {
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

	sessionStoreStub := func(err error) *depMock.SessionStore {
		return &depMock.SessionStore{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	cc := map[string]struct {
		SessionStore *depMock.SessionStore
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
			hdl.session.manager = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
			hdl.RevokeOtherSessions(rec, req.WithContext(sessionup.NewContext(
				context.Background(), sessionup.Session{ID: "12345"})))

			for _, ch := range c.Checks {
				ch(t, rec)
			}
		})
	}
}

//nolint:gocognit // complex testing is required.
func Test_Handler_ResendVerification(t *testing.T) {
	type check func(*testing.T, *DBMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasFetchUserByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchUserByIDCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasUpdateUserCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateUserCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			require.NotNil(t, ff[0].Usr)
			assert.NotZero(t, ff[0].Usr.ExposeCore().Verification)
		}
	}

	wasSendEmailVerificationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DBMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendEmailVerificationCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
		}
	}

	wasSendAccountActivationCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DBMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendAccountActivationCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err1
			},
			UpdateUserFunc: func(_ context.Context, _ User) error {
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
		Email:        _email,
		PasswordHash: []byte("password1"),
		Verification: Token{
			Hash: []byte("12345"),
		},
	}

	cc := map[string]struct {
		DB      *DBMock
		Email   *EmailSenderMock
		Session bool
		Checks  []check
	}{
		"No active session": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Email: emailStub(),
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(0, xid.ID{}),
				wasUpdateUserCalled(0),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by DB.FetchUserByID": {
			DB:      dbStub(assert.AnError, nil, nil),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(0),
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
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(0),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by Core.InitVerification": {
			DB: dbStub(nil, assert.AnError, toPointer(func() Core {
				tmp := inpUsr
				tmp.Verification.NextAt = null.TimeFrom(timeutil.Now().Add(time.Hour))
				return tmp
			}())),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(0),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Error returned by DB.UpdateUser": {
			DB:      dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(1),
				wasSendEmailVerificationCalled(0, ""),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Successful email verification resend": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.UnverifiedEmail = zero.StringFrom(tmp.Email)
				tmp.ActivatedAt = zero.TimeFrom(timeutil.Now())
				return tmp
			}())),
			Email:   emailStub(),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(1),
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
				wasFetchUserByIDCalled(1, inpUsr.ID),
				wasUpdateUserCalled(1),
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
			time.Sleep(time.Millisecond * 30) // to record goroutine func call

			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func Test_Handler_Verify(t *testing.T) {
	type check func(*testing.T, *DBMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasUpdateUserCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateUserCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			require.NotNil(t, ff[0].Usr)
			assert.NotZero(t, ff[0].Usr.ExposeCore().ActivatedAt)
			assert.True(t, ff[0].Usr.ExposeCore().Verification.IsEmpty())
		}
	}

	wasSendEmailChangedCalled := func(count int, oEml, nEml string) check {
		return func(t *testing.T, _ *DBMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendEmailChangedCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, oEml, ff[0].OEml)
			assert.Equal(t, nEml, ff[0].NEml)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err1
			},
			UpdateUserFunc: func(_ context.Context, _ User) error {
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
		ActivatedAt:     zero.TimeFrom(timeutil.Now()),
		ID:              xid.New(),
		Email:           _email,
		UnverifiedEmail: zero.StringFrom("user123@email.com"),
	}

	inpTok, _ := inpUsr.InitVerification(TokenLifetime{time.Hour, time.Hour})

	cc := map[string]struct {
		DB     *DBMock
		Email  *EmailSenderMock
		Token  string
		Checks []check
	}{
		"Error returned by Handler.FetchByToken": {
			DB:    dbStub(assert.AnError, nil, nil),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateUserCalled(0),
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
				wasUpdateUserCalled(0),
				wasSendEmailChangedCalled(0, "", ""),
			),
		},
		"Error returned by DB.UpdateUser": {
			DB:    dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateUserCalled(1),
				wasSendEmailChangedCalled(0, "", ""),
			),
		},
		"Successful account activation": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.ActivatedAt = zero.TimeFrom(time.Time{})
				tmp.UnverifiedEmail = zero.StringFrom("")
				return tmp
			}())),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(false),
				wasUpdateUserCalled(1),
				wasSendEmailChangedCalled(0, "", ""),
			),
		},
		"Successful email verification and account activation": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.ActivatedAt = zero.TimeFrom(time.Time{})
				return tmp
			}())),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(false),
				wasUpdateUserCalled(1),
				wasSendEmailChangedCalled(1, inpUsr.Email, inpUsr.UnverifiedEmail.String),
			),
		},
		"Successful email verification": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Email: emailStub(),
			Token: inpTok,
			Checks: checks(
				hasResp(false),
				wasUpdateUserCalled(1),
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
			hdl.Verify(rec, addQueryParam(req, "token", c.Token))
			time.Sleep(time.Millisecond * 30) // to record goroutine func call

			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func Test_Handler_CancelVerification(t *testing.T) {
	type check func(*testing.T, *DBMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasUpdateUserCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateUserCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			require.NotNil(t, ff[0].Usr)
			assert.True(t, ff[0].Usr.ExposeCore().Verification.IsEmpty())
		}
	}

	dbStub := func(err1, err2 error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err1
			},
			UpdateUserFunc: func(_ context.Context, _ User) error {
				return err2
			},
		}
	}

	inpUsr := Core{
		ActivatedAt:     zero.TimeFrom(timeutil.Now()),
		ID:              xid.New(),
		Email:           _email,
		UnverifiedEmail: zero.StringFrom("user123@email.com"),
	}

	inpTok, _ := inpUsr.InitVerification(TokenLifetime{time.Hour, time.Hour})

	cc := map[string]struct {
		DB     *DBMock
		Token  string
		Checks []check
	}{
		"Error returned by Handler.FetchByToken": {
			DB:    dbStub(assert.AnError, nil, nil),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateUserCalled(0),
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
				wasUpdateUserCalled(0),
			),
		},
		"Error returned by DB.Update": {
			DB:    dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateUserCalled(1),
			),
		},
		"Successful verification cancel": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasResp(false),
				wasUpdateUserCalled(1),
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
			hdl.CancelVerification(rec, addQueryParam(req, "token", c.Token))
			time.Sleep(time.Millisecond * 30) // to record goroutine func call

			for _, ch := range c.Checks {
				ch(t, c.DB, rec)
			}
		})
	}
}

func Test_Handler_InitRecovery(t *testing.T) {
	type check func(*testing.T, *DBMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasFetchUserByEmailCalled := func(count int, eml string) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchUserByEmailCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	wasUpdateUserCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateUserCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			require.NotNil(t, ff[0].Usr)
			assert.NotZero(t, ff[0].Usr.ExposeCore().Recovery)
		}
	}

	wasSendRecoveryCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DBMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendRecoveryCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.NotZero(t, ff[0].Tok)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DBMock {
		return &DBMock{
			FetchUserByEmailFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err1
			},
			UpdateUserFunc: func(_ context.Context, _ User) error {
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
		Email: _email,
	}

	cc := map[string]struct {
		DB     *DBMock
		Email  *EmailSenderMock
		Body   string
		Checks []check
	}{
		"Invalid JSON body": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Email: emailStub(),
			Body:  "{",
			Checks: checks(
				hasResp(true),
				wasFetchUserByEmailCalled(0, ""),
				wasUpdateUserCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Invalid email": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Email: emailStub(),
			Body:  toJSON("useremail.com", "", false),
			Checks: checks(
				hasResp(true),
				wasFetchUserByEmailCalled(0, ""),
				wasUpdateUserCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"User error returned by DB.FetchUserByEmail": {
			DB:    dbStub(httpflow.NewError(nil, 400, "123"), nil, nil),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
			Checks: checks(
				hasResp(false),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Error returned by DB.FetchUserByEmail": {
			DB:    dbStub(assert.AnError, nil, nil),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
			Checks: checks(
				hasResp(true),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Error returned by Core.InitRecovery": {
			DB: dbStub(nil, nil, toPointer(func() Core {
				tmp := inpUsr
				tmp.Recovery.NextAt = null.TimeFrom(timeutil.Now().Add(time.Hour))
				return tmp
			}())),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
			Checks: checks(
				hasResp(true),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"User error returned by DB.UpdateUser": {
			DB: dbStub(nil, httpflow.NewError(nil, 400, "123"),
				toPointer(inpUsr)),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
			Checks: checks(
				hasResp(false),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(1),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Error returned by DB.UpdateUser": {
			DB:    dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
			Checks: checks(
				hasResp(true),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(1),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Successful recovery init": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
			Checks: checks(
				hasResp(false),
				wasFetchUserByEmailCalled(1, inpUsr.Email),
				wasUpdateUserCalled(1),
				wasSendRecoveryCalled(1, inpUsr.Email),
			),
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "http://test.com/",
				strings.NewReader(c.Body))
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.db = c.DB
			hdl.email = c.Email
			hdl.InitRecovery(rec, req)
			time.Sleep(time.Millisecond * 30) // to record goroutine func call

			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func Test_Handler_Recover(t *testing.T) {
	type check func(*testing.T, *DBMock, *EmailSenderMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, _ *EmailSenderMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasUpdateUserCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateUserCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			require.NotNil(t, ff[0].Usr)
			assert.True(t, ff[0].Usr.ExposeCore().Recovery.IsEmpty())
			assert.NotZero(t, ff[0].Usr.ExposeCore().PasswordHash)
		}
	}

	wasSendPasswordChangedCalled := func(count int, eml string) check {
		return func(t *testing.T, _ *DBMock, es *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := es.SendPasswordChangedCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
			assert.True(t, ff[0].Recov)
		}
	}

	dbStub := func(err1, err2 error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err1
			},
			UpdateUserFunc: func(_ context.Context, _ User) error {
				return err2
			},
		}
	}

	emailStub := func() *EmailSenderMock {
		return &EmailSenderMock{
			SendPasswordChangedFunc: func(_ context.Context, _ string, _ bool) {},
		}
	}

	sessionStoreStub := func(err error) *depMock.SessionStore {
		return &depMock.SessionStore{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	inpUsr := Core{
		ActivatedAt: zero.TimeFrom(timeutil.Now()),
		ID:          xid.New(),
		Email:       _email,
	}

	inpTok, _ := inpUsr.InitRecovery(TokenLifetime{time.Hour, time.Hour})

	cc := map[string]struct {
		DB           *DBMock
		Email        *EmailSenderMock
		SessionStore *depMock.SessionStore
		Token        string
		Body         string
		Checks       []check
	}{
		"Error returned by Handler.FetchByToken": {
			DB:           dbStub(assert.AnError, nil, nil),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Token:        inpTok,
			Body:         toJSON("", "password1", false),
			Checks: checks(
				hasResp(true),
				wasUpdateUserCalled(0),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Invalid JSON body": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Token:        inpTok,
			Body:         "{",
			Checks: checks(
				hasResp(true),
				wasUpdateUserCalled(0),
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
				wasUpdateUserCalled(0),
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
				wasUpdateUserCalled(0),
				wasSendPasswordChangedCalled(0, ""),
			),
		},
		"Error returned by DB.UpdateUser": {
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			Token:        inpTok,
			Body:         toJSON("", "password1", false),
			Checks: checks(
				hasResp(true),
				wasUpdateUserCalled(1),
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
				wasUpdateUserCalled(1),
				wasSendPasswordChangedCalled(1, inpUsr.Email),
			),
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "http://test.com/",
				strings.NewReader(c.Body))
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.session.manager = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
			hdl.db = c.DB
			hdl.email = c.Email
			hdl.Recover(rec, addQueryParam(req, "token", c.Token))
			time.Sleep(time.Millisecond * 30) // to record goroutine func call

			for _, ch := range c.Checks {
				ch(t, c.DB, c.Email, rec)
			}
		})
	}
}

func Test_Handler_PingRecovery(t *testing.T) {
	type check func(*testing.T, *DBMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	dbStub := func(err error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err
			},
		}
	}

	inpUsr := Core{
		ActivatedAt: zero.TimeFrom(timeutil.Now()),
		ID:          xid.New(),
		Email:       _email,
	}

	inpTok, _ := inpUsr.InitRecovery(TokenLifetime{time.Hour, time.Hour})

	cc := map[string]struct {
		DB     *DBMock
		Email  *EmailSenderMock
		Token  string
		Checks []check
	}{
		"Error returned by Handler.FetchByToken": {
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
			hdl.PingRecovery(rec, addQueryParam(req, "token", c.Token))

			for _, ch := range c.Checks {
				ch(t, c.DB, rec)
			}
		})
	}
}

func Test_Handler_CancelRecovery(t *testing.T) {
	type check func(*testing.T, *DBMock, *httptest.ResponseRecorder)

	checks := func(cc ...check) []check { return cc }

	hasResp := func(err bool) check {
		return func(t *testing.T, _ *DBMock, rec *httptest.ResponseRecorder) {
			if err {
				assert.LessOrEqual(t, 400, rec.Code)
				assert.NotZero(t, rec.Body.Len())

				return
			}

			assert.Greater(t, 400, rec.Code)
			assert.Zero(t, rec.Body.Len())
		}
	}

	wasUpdateUserCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateUserCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			require.NotNil(t, ff[0].Usr)
			assert.True(t, ff[0].Usr.ExposeCore().Recovery.IsEmpty())
		}
	}

	dbStub := func(err1, err2 error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err1
			},
			UpdateUserFunc: func(_ context.Context, _ User) error {
				return err2
			},
		}
	}

	inpUsr := Core{
		ActivatedAt: zero.TimeFrom(timeutil.Now()),
		ID:          xid.New(),
		Email:       _email,
	}

	inpTok, _ := inpUsr.InitRecovery(TokenLifetime{time.Hour, time.Hour})

	cc := map[string]struct {
		DB     *DBMock
		Token  string
		Checks []check
	}{
		"Error returned by Handler.FetchByToken": {
			DB:    dbStub(assert.AnError, nil, nil),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateUserCalled(0),
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
				wasUpdateUserCalled(0),
			),
		},
		"Error returned by DB.UpdateUser": {
			DB:    dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasResp(true),
				wasUpdateUserCalled(1),
			),
		},
		"Successful recovery cancel": {
			DB:    dbStub(nil, nil, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasResp(false),
				wasUpdateUserCalled(1),
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
			hdl.CancelRecovery(rec, addQueryParam(req, "token", c.Token))

			for _, ch := range c.Checks {
				ch(t, c.DB, rec)
			}
		})
	}
}

func Test_Handler_FetchByToken(t *testing.T) {
	type check func(*testing.T, *DBMock, User, string, error)

	checks := func(cc ...check) []check { return cc }

	hasUser := func(usr User) check {
		return func(t *testing.T, _ *DBMock, res User, _ string, _ error) {
			assert.Equal(t, usr, res)
		}
	}

	hasToken := func(tok string) check {
		return func(t *testing.T, _ *DBMock, _ User, res string, _ error) {
			assert.Equal(t, tok, res)
		}
	}

	hasError := func(err bool) check {
		return func(t *testing.T, _ *DBMock, _ User, _ string, res error) {
			if err {
				assert.Error(t, res)
				return
			}

			assert.NoError(t, res)
		}
	}

	wasFetchUserByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ User, _ string, _ error) {
			ff := db.FetchUserByIDCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, id, ff[0].ID)
		}
	}

	dbStub := func(err error, usr User) *DBMock {
		return &DBMock{
			FetchUserByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err
			},
		}
	}

	inpUsr := Core{ID: xid.New()}
	inpTok, _ := inpUsr.InitVerification(TokenLifetime{time.Hour, time.Hour})
	inpRawTok, _, _ := FromFullToken(inpTok)

	cc := map[string]struct {
		DB     *DBMock
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
				wasFetchUserByIDCalled(0, xid.ID{}),
			),
		},
		"Invalid token": {
			DB:    dbStub(nil, toPointer(inpUsr)),
			Token: "12345asdfgh",
			Checks: checks(
				hasUser(nil),
				hasToken(""),
				hasError(true),
				wasFetchUserByIDCalled(0, xid.ID{}),
			),
		},
		"Error returned by DB.FetchUserByID": {
			DB:    dbStub(assert.AnError, nil),
			Token: inpTok,
			Checks: checks(
				hasUser(nil),
				hasToken(""),
				hasError(true),
				wasFetchUserByIDCalled(1, inpUsr.ID),
			),
		},
		"Successful fetch by token": {
			DB:    dbStub(nil, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasUser(toPointer(inpUsr)),
				hasToken(inpRawTok),
				hasError(false),
				wasFetchUserByIDCalled(1, inpUsr.ID),
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
			usr, tok, err := hdl.FetchByToken(addQueryParam(req,
				"token", c.Token))

			for _, ch := range c.Checks {
				ch(t, c.DB, usr, tok, err)
			}
		})
	}
}

func toJSON(eml, pass string, rem bool) string {
	b, err := json.Marshal(CoreInput{Email: eml, Password: pass, RememberMe: rem})
	if err != nil {
		panic(err)
	}

	return string(b)
}

func toPointer(c Core) *Core {
	return &c
}

func addQueryParam(r *http.Request, k, v string) *http.Request { //nolint:unparam // might become dynamic in the future
	q := url.Values{}
	q.Add(k, v)
	r.URL.RawQuery = q.Encode()

	return r
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
	h := &Handler{
		log: zerolog.Nop(),
	}
	h.ext.parse = DefaultParser
	h.ext.create = DefaultCreator

	return h
}
