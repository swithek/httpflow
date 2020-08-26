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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swithek/httpflow"
	depMock "github.com/swithek/httpflow/_mock"
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
	assert.Equal(t, time.Hour, h.sesDur)
}

func Test_SetErrorExec(t *testing.T) {
	h := &Handler{}
	SetErrorExec(httpflow.DefaultErrorExec)(h)
	assert.NotNil(t, h.onError)
}

func Test_SetParser(t *testing.T) {
	h := &Handler{}
	SetParser(DefaultParser)(h)
	assert.NotNil(t, h.parse)
}

func Test_SetCreator(t *testing.T) {
	h := &Handler{}
	SetCreator(DefaultCreator)(h)
	assert.NotNil(t, h.create)
}

func Test_SetGateKeeper(t *testing.T) {
	h := &Handler{}
	SetGateKeeper(DefaultGateKeeper(true))(h)
	assert.NotNil(t, h.gKeep)
}

func Test_SetPreDeleter(t *testing.T) {
	h := &Handler{}
	SetPreDeleter(DefaultPreDeleter)(h)
	assert.NotNil(t, h.pDel)
}

func Test_SetVerificationTimes(t *testing.T) {
	h := &Handler{}
	SetVerificationTimes(VerifTimes)(h)
	assert.Equal(t, VerifTimes, h.verif)
}

func Test_SetRecoveryTimes(t *testing.T) {
	h := &Handler{}
	SetRecoveryTimes(RecovTimes)(h)
	assert.Equal(t, RecovTimes, h.recov)
}

func Test_NewHandler(t *testing.T) {
	h := NewHandler(sessionup.NewManager(&depMock.SessionStore{}), &DBMock{},
		&EmailSenderMock{}, SetSessionDuration(time.Hour),
		SetVerificationTimes(VerifTimes))
	assert.NotNil(t, h.sessions)
	assert.NotNil(t, h.db)
	assert.NotNil(t, h.email)
	assert.Equal(t, time.Hour, h.sesDur)
	assert.NotNil(t, h.onError)
	assert.NotNil(t, h.parse)
	assert.NotNil(t, h.create)
	assert.NotNil(t, h.gKeep)
	assert.NotNil(t, h.pDel)
	assert.Equal(t, VerifTimes, h.verif)
	assert.NotZero(t, h.recov)

	assert.NotNil(t, h.Router(true))
}

func Test_Handler_Defaults(t *testing.T) {
	h := Handler{}
	h.Defaults()
	assert.Equal(t, SessionDuration, h.sesDur)
	assert.NotNil(t, h.onError)
	assert.NotNil(t, h.parse)
	assert.NotNil(t, h.create)
	assert.NotNil(t, h.gKeep)
	assert.NotNil(t, h.pDel)
	assert.Equal(t, VerifTimes, h.verif)
	assert.Equal(t, RecovTimes, h.recov)
}

func Test_DefaultParser(t *testing.T) {
	req := httptest.NewRequest("GET", "http://test.com/",
		strings.NewReader("{"))
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
	usr, err := DefaultCreator(context.Background(),
		CoreInput{Email: _email, Password: "password1"})
	assert.NoError(t, err)
	require.NotNil(t, usr)
	assert.Equal(t, _email, usr.ExposeCore().Email)
	assert.NotZero(t, usr.ExposeCore().PasswordHash)
}

func Test_DefaultGateKeeper(t *testing.T) {
	cr := &Core{}
	assert.NoError(t, DefaultGateKeeper(true)(cr))
	assert.Equal(t, ErrNotActivated, DefaultGateKeeper(false)(cr))

	cr.ActivatedAt = zero.TimeFrom(time.Now())
	assert.NoError(t, DefaultGateKeeper(false)(cr))
}

func Test_DefaultPreDeleter(t *testing.T) {
	assert.NoError(t, DefaultPreDeleter(context.Background(), nil))
}

func Test_SetupLinks(t *testing.T) {
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

	wasCreateCalled := func(count int, eml string) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.CreateCalls()
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
				wasCreateCalled(0, ""),
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
				wasCreateCalled(0, ""),
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
					TokenTimes{time.Hour, time.Hour})

				require.NoError(t, err)

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
			Body:         toJSON(_email, "password1", false),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(true, false),
				wasCreateCalled(1, _email),
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
				wasCreateCalled(1, _email),
				wasSendAccountActivationCalled(0, ""),
			),
		},
		"Successful user creation with permanent session": {
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil),
			Email:        emailStub(),
			Body:         toJSON(_email, "password1", true),
			Creator:      DefaultCreator,
			Checks: checks(
				hasResp(false, true),
				wasCreateCalled(1, _email),
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
				wasCreateCalled(1, _email),
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
			hdl.sessions = sessionup.NewManager(c.SessionStore)
			hdl.sesDur = time.Hour
			hdl.db = c.DB
			hdl.email = c.Email
			hdl.create = c.Creator
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

	wasFetchByEmailCalled := func(count int, eml string) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByEmailCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
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
			FetchByEmailFunc: func(_ context.Context, _ string) (User, error) {
				return usr, err1
			},
			UpdateFunc: func(_ context.Context, _ User) error {
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
		GateKeeper   GateKeeper
		Body         string
		Checks       []check
	}{
		"Invalid JSON body": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			GateKeeper:   DefaultGateKeeper(true),
			Body:         "{",
			Checks: checks(
				hasResp(false, 400),
				wasFetchByEmailCalled(0, ""),
				wasUpdateCalled(0),
			),
		},
		"Invalid email": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			GateKeeper:   DefaultGateKeeper(true),
			Body:         toJSON("useremail.com", inpPass, false),
			Checks: checks(
				hasResp(false, 401),
				wasFetchByEmailCalled(0, ""),
				wasUpdateCalled(0),
			),
		},
		"Error returned by Database.FetchByEmail": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(assert.AnError, nil, nil),
			GateKeeper:   DefaultGateKeeper(true),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 500),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
			),
		},
		"Not found error returned by Database.FetchByEmail": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(httpflow.ErrNotFound, nil, nil),
			GateKeeper:   DefaultGateKeeper(true),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 401),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
			),
		},
		"Account not activated when required": {
			Open:         false,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			GateKeeper:   DefaultGateKeeper(false),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 403),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
			),
		},
		"Incorrect password": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			GateKeeper:   DefaultGateKeeper(true),
			Body:         toJSON(inpUsr.Email, "password2", false),
			Checks: checks(
				hasResp(false, 401),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
			),
		},
		"Error returned by Database.Update": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			GateKeeper:   DefaultGateKeeper(true),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 500),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Session init error": {
			Open:         true,
			SessionStore: sessionStoreStub(assert.AnError),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			GateKeeper:   DefaultGateKeeper(true),
			Body:         toJSON(inpUsr.Email, inpPass, true),
			Checks: checks(
				hasResp(false, 500),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Successful user log in with permanent session": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			GateKeeper:   DefaultGateKeeper(true),
			Body:         toJSON(inpUsr.Email, inpPass, true),
			Checks: checks(
				hasResp(true, 204),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Successful user log in with temporary session": {
			Open:         true,
			SessionStore: sessionStoreStub(nil),
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			GateKeeper:   DefaultGateKeeper(true),
			Body:         toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 204),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Successful user log in with permanent session when activation is required": {
			Open:         false,
			SessionStore: sessionStoreStub(nil),
			DB: dbStub(nil, nil, func() *Core {
				tmp := inpUsr
				tmp.ActivatedAt = zero.TimeFrom(time.Now())
				return &tmp
			}()),
			GateKeeper: DefaultGateKeeper(true),
			Body:       toJSON(inpUsr.Email, inpPass, true),
			Checks: checks(
				hasResp(true, 204),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
			),
		},
		"Successful user log in with temporary session when activation is required": {
			Open:         false,
			SessionStore: sessionStoreStub(nil),
			DB: dbStub(nil, nil, func() *Core {
				tmp := inpUsr
				tmp.ActivatedAt = zero.TimeFrom(time.Now())
				return &tmp
			}()),
			GateKeeper: DefaultGateKeeper(true),
			Body:       toJSON(inpUsr.Email, inpPass, false),
			Checks: checks(
				hasResp(false, 204),
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
				strings.NewReader(c.Body))
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.sessions = sessionup.NewManager(c.SessionStore)
			hdl.sesDur = time.Hour
			hdl.db = c.DB
			hdl.gKeep = c.GateKeeper
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

	wasFetchByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByIDCalls()
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
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
				wasFetchByIDCalled(0, xid.ID{}),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:      dbStub(assert.AnError, nil),
			Session: true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID),
			),
		},
		"Successful user fetch": {
			DB:      dbStub(nil, toPointer(inpUsr)),
			Session: true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID),
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

	wasFetchByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByIDCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasUpdateCalled := func(count int, eml string, verif bool) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
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
				wasFetchByIDCalled(0, xid.ID{}),
				wasUpdateCalled(0, "", false),
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
				wasFetchByIDCalled(0, xid.ID{}),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
				wasUpdateCalled(0, "", false),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				strings.NewReader(c.Body))
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

	wasFetchByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByIDCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasDeleteByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.DeleteByIDCalls()
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err1
			},
			DeleteByIDFunc: func(_ context.Context, _ xid.ID) error {
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
		PreDeleter   PreDeleter
		Body         string
		Session      bool
		Checks       []check
	}{
		"No active session": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			PreDeleter:   DefaultPreDeleter,
			Body:         toJSON("", inpPass, false),
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, xid.ID{}),
				wasDeleteByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Invalid JSON body": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			PreDeleter:   DefaultPreDeleter,
			Body:         "{",
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(0, xid.ID{}),
				wasDeleteByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:           dbStub(assert.AnError, nil, nil),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			PreDeleter:   DefaultPreDeleter,
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID),
				wasDeleteByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by pre-deleter": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			PreDeleter:   func(_ context.Context, _ User) error { return assert.AnError },
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID),
				wasDeleteByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Incorrect password": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			PreDeleter:   DefaultPreDeleter,
			Body:         toJSON("", "password2", false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID),
				wasDeleteByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Sessions revokation error": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(assert.AnError),
			PreDeleter:   DefaultPreDeleter,
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID),
				wasDeleteByIDCalled(0, xid.ID{}),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Error returned by Database.DeleteByID": {
			DB:           dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			PreDeleter:   DefaultPreDeleter,
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(true),
				wasFetchByIDCalled(1, inpUsr.ID),
				wasDeleteByIDCalled(1, inpUsr.ID),
				wasSendAccountDeletedCalled(0, ""),
			),
		},
		"Successful account deletion": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(nil),
			PreDeleter:   DefaultPreDeleter,
			Body:         toJSON("", inpPass, false),
			Session:      true,
			Checks: checks(
				hasResp(false),
				wasFetchByIDCalled(1, inpUsr.ID),
				wasDeleteByIDCalled(1, inpUsr.ID),
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
			hdl.sessions = sessionup.NewManager(c.SessionStore,
				sessionup.ExpiresIn(time.Hour))
			hdl.db = c.DB
			hdl.email = c.Email
			hdl.pDel = c.PreDeleter
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
			hdl.sessions = sessionup.NewManager(c.SessionStore,
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

	wasFetchByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByIDCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, id, ff[0].ID)
		}
	}

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
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
				wasFetchByIDCalled(0, xid.ID{}),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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
				wasFetchByIDCalled(1, inpUsr.ID),
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

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
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
		Email:           _email,
		UnverifiedEmail: zero.StringFrom("user123@email.com"),
	}

	inpTok, _ := inpUsr.InitVerification(TokenTimes{time.Hour, time.Hour})

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
				tmp.UnverifiedEmail = zero.StringFrom("")
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
				wasUpdateCalled(1),
				wasSendEmailChangedCalled(1, inpUsr.Email, inpUsr.UnverifiedEmail.String),
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

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
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
		Email:           _email,
		UnverifiedEmail: zero.StringFrom("user123@email.com"),
	}

	inpTok, _ := inpUsr.InitVerification(TokenTimes{time.Hour, time.Hour})

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

	wasFetchByEmailCalled := func(count int, eml string) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.FetchByEmailCalls()
			require.Len(t, ff, count)

			if count == 0 {
				return
			}

			assert.NotNil(t, ff[0].Ctx)
			assert.Equal(t, eml, ff[0].Eml)
		}
	}

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
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
		"User error returned by Database.FetchByEmail": {
			DB:    dbStub(httpflow.NewError(nil, 400, "123"), nil, nil),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
			Checks: checks(
				hasResp(false),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Error returned by Database.FetchByEmail": {
			DB:    dbStub(assert.AnError, nil, nil),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
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
			Body:  toJSON(_email, "", false),
			Checks: checks(
				hasResp(true),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(0),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"User error returned by Database.Update": {
			DB: dbStub(nil, httpflow.NewError(nil, 400, "123"),
				toPointer(inpUsr)),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
			Checks: checks(
				hasResp(false),
				wasFetchByEmailCalled(1, inpUsr.Email),
				wasUpdateCalled(1),
				wasSendRecoveryCalled(0, ""),
			),
		},
		"Error returned by Database.Update": {
			DB:    dbStub(nil, assert.AnError, toPointer(inpUsr)),
			Email: emailStub(),
			Body:  toJSON(_email, "", false),
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
			Body:  toJSON(_email, "", false),
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

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *EmailSenderMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
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

	sessionStoreStub := func(err error) *depMock.SessionStore {
		return &depMock.SessionStore{
			DeleteByUserKeyFunc: func(_ context.Context, _ string, _ ...string) error {
				return err
			},
		}
	}

	inpUsr := Core{
		ActivatedAt: zero.TimeFrom(time.Now()),
		ID:          xid.New(),
		Email:       _email,
	}

	inpTok, _ := inpUsr.InitRecovery(TokenTimes{time.Hour, time.Hour})

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
				wasUpdateCalled(0),
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
		"Sessions revokation error": {
			DB:           dbStub(nil, nil, toPointer(inpUsr)),
			Email:        emailStub(),
			SessionStore: sessionStoreStub(assert.AnError),
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
				strings.NewReader(c.Body))
			rec := httptest.NewRecorder()
			hdl := newHandler()
			hdl.sessions = sessionup.NewManager(c.SessionStore,
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err
			},
		}
	}

	inpUsr := Core{
		ActivatedAt: zero.TimeFrom(time.Now()),
		ID:          xid.New(),
		Email:       _email,
	}

	inpTok, _ := inpUsr.InitRecovery(TokenTimes{time.Hour, time.Hour})

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

	wasUpdateCalled := func(count int) check {
		return func(t *testing.T, db *DBMock, _ *httptest.ResponseRecorder) {
			ff := db.UpdateCalls()
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
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
		Email:       _email,
	}

	inpTok, _ := inpUsr.InitRecovery(TokenTimes{time.Hour, time.Hour})

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

	wasFetchByIDCalled := func(count int, id xid.ID) check {
		return func(t *testing.T, db *DBMock, _ User, _ string, _ error) {
			ff := db.FetchByIDCalls()
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
			FetchByIDFunc: func(_ context.Context, _ xid.ID) (User, error) {
				return usr, err
			},
		}
	}

	inpUsr := Core{ID: xid.New()}
	inpTok, _ := inpUsr.InitVerification(TokenTimes{time.Hour, time.Hour})
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
				wasFetchByIDCalled(0, xid.ID{}),
			),
		},
		"Invalid token": {
			DB:    dbStub(nil, toPointer(inpUsr)),
			Token: "12345asdfgh",
			Checks: checks(
				hasUser(nil),
				hasToken(""),
				hasError(true),
				wasFetchByIDCalled(0, xid.ID{}),
			),
		},
		"Error returned by Database.FetchByID": {
			DB:    dbStub(assert.AnError, nil),
			Token: inpTok,
			Checks: checks(
				hasUser(nil),
				hasToken(""),
				hasError(true),
				wasFetchByIDCalled(1, inpUsr.ID),
			),
		},
		"Successful fetch by token": {
			DB:    dbStub(nil, toPointer(inpUsr)),
			Token: inpTok,
			Checks: checks(
				hasUser(toPointer(inpUsr)),
				hasToken(inpRawTok),
				hasError(false),
				wasFetchByIDCalled(1, inpUsr.ID),
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
	return &Handler{
		onError: func(error) {},
		parse:   DefaultParser,
		create:  DefaultCreator,
	}
}
