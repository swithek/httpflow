package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gchaincl/dotsql"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swithek/httpflow"
	"github.com/swithek/httpflow/testutil"
	"github.com/swithek/httpflow/timeutil"
	"github.com/swithek/httpflow/user"
	"gopkg.in/guregu/null.v3"
	"gopkg.in/guregu/null.v3/zero"
)

var (
	_queries *dotsql.DotSql
)

func init() {
	var err error

	_queries, err = dotsql.LoadFromString(_escFSMustString(false, "/queries.sql"))
	if err != nil {
		panic(err)
	}
}

func rawQuery(name string) string {
	q, err := _queries.Raw(name)
	if err != nil {
		panic(err)
	}

	return q
}

func Test_NewStore(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")

	cc := map[string]struct {
		Expect func()
		Err    error
	}{
		"Error returned during users table creation": {
			Expect: func() {
				mock.ExpectExec(rawQuery("create_users_table")).
					WillReturnError(assert.AnError)
			},
			Err: assert.AnError,
		},
		"Successful store init and users table creation": {
			Expect: func() {
				mock.ExpectExec(rawQuery("create_users_table")).
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			s, err := NewStore(zerolog.Nop(), dbx, 0)
			if c.Err != nil {
				assert.Equal(t, c.Err, err)
				return
			}

			assert.NoError(t, err)
			assert.NotZero(t, s.log)
			assert.Equal(t, dbx, s.db)
			assert.NotZero(t, s.q)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func Test_Store_deleteInactive(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.NoError(t, err)

	cc := map[string]struct {
		Expect func()
		Err    error
	}{
		"Error returned during inactive users deletion": {
			Expect: func() {
				mock.ExpectExec(rawQuery("delete_inactive_users")).
					WillReturnError(assert.AnError)
			},
			Err: assert.AnError,
		},
		"Successful inactive users deletion": {
			Expect: func() {
				mock.ExpectExec(rawQuery("delete_inactive_users")).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			err = s.deleteInactive()
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func Test_Store_UserStats(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.NoError(t, err)

	cc := map[string]struct {
		Expect func()
		Stats  user.Stats
		Err    error
	}{
		"Error returned during stats selection": {
			Expect: func() {
				mock.ExpectQuery(rawQuery("select_stats")).
					WillReturnError(assert.AnError)
			},
			Err: assert.AnError,
		},
		"Successful stats selection": {
			Expect: func() {
				mock.ExpectQuery(rawQuery("select_stats")).
					WillReturnRows(sqlmock.NewRows(
						[]string{"total"}).AddRow(11))
			},
			Stats: user.CoreStats{Total: 11},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			st, err := s.UserStats(context.Background())
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.Stats, st)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func Test_Store_CreateUser(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.NoError(t, err)

	inpUsr := newFullUser()

	cc := map[string]struct {
		Expect func()
		User   *user.Core
		Err    error
	}{
		"Error returned during user insertion": {
			Expect: func() {
				mock.ExpectExec(rawQuery("insert_user")).
					WithArgs(inpUsr.ID, inpUsr.CreatedAt,
						inpUsr.UpdatedAt, inpUsr.ActivatedAt,
						inpUsr.Email, inpUsr.UnverifiedEmail,
						inpUsr.PasswordHash, inpUsr.Verification.Hash,
						inpUsr.Verification.NextAt, inpUsr.Verification.ExpiresAt,
						inpUsr.Recovery.Hash, inpUsr.Recovery.NextAt,
						inpUsr.Recovery.ExpiresAt).
					WillReturnError(assert.AnError)
			},
			User: toPointer(inpUsr),
			Err:  assert.AnError,
		},
		"Successful user insertion": {
			Expect: func() {
				mock.ExpectExec(rawQuery("insert_user")).
					WithArgs(inpUsr.ID, inpUsr.CreatedAt,
						inpUsr.UpdatedAt, inpUsr.ActivatedAt,
						inpUsr.Email, inpUsr.UnverifiedEmail,
						inpUsr.PasswordHash, inpUsr.Verification.Hash,
						inpUsr.Verification.NextAt, inpUsr.Verification.ExpiresAt,
						inpUsr.Recovery.Hash, inpUsr.Recovery.NextAt,
						inpUsr.Recovery.ExpiresAt).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			User: toPointer(inpUsr),
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			err = s.CreateUser(context.Background(), c.User)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func Test_Story_FetchManyUsers(t *testing.T) {
	inpUsrs := []user.User{
		toPointer(newFullUser()),
		toPointer(newFullUser()),
		toPointer(newFullUser()),
	}

	inpEml := "1@em"

	cc := map[string]struct {
		Expect func(t *testing.T) (*sql.DB, sqlmock.Sqlmock)
		Query  httpflow.Query
		Users  []user.User
		Err    error
	}{
		"Invalid query data": {
			Expect: newDB,
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email123",
				FilterVal: inpEml,
				SortBy:    "created_at",
				Asc:       true,
			},
			Err: assert.AnError,
		},
		"Error returned during users select": {
			Expect: func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
				db, mock := newDB(t)
				mock.ExpectQuery(rawQuery("select_users_by_email_desc_created_at")).
					WithArgs(inpEml, 5, 45).
					WillReturnError(assert.AnError)

				return db, mock
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "created_at",
				Asc:       true,
			},
			Err: assert.AnError,
		},
		"Successful users select by email in desc order of creation date": {
			Expect: func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
				db, mock := newDB(t)
				mock.ExpectQuery(rawQuery("select_users_by_email_desc_created_at")).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))

				return db, mock
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "created_at",
				Asc:       false,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in asc order of creation date": {
			Expect: func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
				db, mock := newDB(t)
				mock.ExpectQuery(rawQuery("select_users_by_email_asc_created_at")).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
				return db, mock
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "created_at",
				Asc:       true,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in desc order of last update date": {
			Expect: func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
				db, mock := newDB(t)
				mock.ExpectQuery(rawQuery("select_users_by_email_desc_updated_at")).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
				return db, mock
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "updated_at",
				Asc:       false,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in asc order of last update date": {
			Expect: func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
				db, mock := newDB(t)
				mock.ExpectQuery(rawQuery("select_users_by_email_asc_updated_at")).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
				return db, mock
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "updated_at",
				Asc:       true,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in desc order of activation date": {
			Expect: func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
				db, mock := newDB(t)
				mock.ExpectQuery(rawQuery("select_users_by_email_desc_activated_at")).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
				return db, mock
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "activated_at",
				Asc:       false,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in asc order of activation date": {
			Expect: func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
				db, mock := newDB(t)
				mock.ExpectQuery(rawQuery("select_users_by_email_asc_activated_at")).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
				return db, mock
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "activated_at",
				Asc:       true,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in desc order of email": {
			Expect: func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
				db, mock := newDB(t)
				mock.ExpectQuery(rawQuery("select_users_by_email_desc_email")).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
				return db, mock
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "email",
				Asc:       false,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in asc order of email": {
			Expect: func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
				db, mock := newDB(t)
				mock.ExpectQuery(rawQuery("select_users_by_email_asc_email")).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
				return db, mock
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "email",
				Asc:       true,
			},
			Users: inpUsrs,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			db, mock := c.Expect(t)
			s := Store{db: sqlx.NewDb(db, "postgres")}
			require.NoError(t, s.initSQL())

			usrs, lastPage, err := s.FetchManyUsers(context.Background(), c.Query)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.Users, usrs)
			assert.Equal(t, len(c.Users), lastPage)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func Test_Store_FetchUserByID(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.NoError(t, err)

	inpUsr := toPointer(newFullUser())

	cc := map[string]struct {
		Expect func()
		User   *user.Core
		Err    error
	}{
		"Error returned during user selection": {
			Expect: func() {
				mock.ExpectQuery(rawQuery("select_user_by_id")).
					WithArgs(inpUsr.ID).
					WillReturnError(assert.AnError)
			},
			User: inpUsr,
			Err:  assert.AnError,
		},
		"Successful user selection": {
			Expect: func() {
				mock.ExpectQuery(rawQuery("select_user_by_id")).
					WithArgs(inpUsr.ID).
					WillReturnRows(usrsToRows(inpUsr))
			},
			User: inpUsr,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			usr, err := s.FetchUserByID(context.Background(), c.User.ID)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.User, usr)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func Test_Store_FetchUserByEmail(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.NoError(t, err)

	inpUsr := toPointer(newFullUser())

	cc := map[string]struct {
		Expect func()
		User   *user.Core
		Err    error
	}{
		"Error returned during user selection": {
			Expect: func() {
				mock.ExpectQuery(rawQuery("select_user_by_email")).
					WithArgs(inpUsr.Email).
					WillReturnError(assert.AnError)
			},
			User: inpUsr,
			Err:  assert.AnError,
		},
		"Successful user selection": {
			Expect: func() {
				mock.ExpectQuery(rawQuery("select_user_by_email")).
					WithArgs(inpUsr.Email).
					WillReturnRows(usrsToRows(inpUsr))
			},
			User: inpUsr,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			usr, err := s.FetchUserByEmail(context.Background(), c.User.Email)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.User, usr)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func Test_Store_UpdateUser(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.NoError(t, err)

	inpUsr := newFullUser()

	cc := map[string]struct {
		Expect func()
		User   *user.Core
		Err    error
	}{
		"Error returned during user update": {
			Expect: func() {
				mock.ExpectExec(rawQuery("update_user_by_id")).
					WithArgs(inpUsr.UpdatedAt, inpUsr.ActivatedAt,
						inpUsr.Email, inpUsr.UnverifiedEmail, inpUsr.PasswordHash,
						inpUsr.Verification.Hash, inpUsr.Verification.NextAt,
						inpUsr.Verification.ExpiresAt, inpUsr.Recovery.Hash,
						inpUsr.Recovery.NextAt, inpUsr.Recovery.ExpiresAt,
						inpUsr.ID).
					WillReturnError(assert.AnError)
			},
			User: toPointer(inpUsr),
			Err:  assert.AnError,
		},
		"Successful user update": {
			Expect: func() {
				mock.ExpectExec(rawQuery("update_user_by_id")).
					WithArgs(inpUsr.UpdatedAt, inpUsr.ActivatedAt,
						inpUsr.Email, inpUsr.UnverifiedEmail, inpUsr.PasswordHash,
						inpUsr.Verification.Hash, inpUsr.Verification.NextAt,
						inpUsr.Verification.ExpiresAt, inpUsr.Recovery.Hash,
						inpUsr.Recovery.NextAt, inpUsr.Recovery.ExpiresAt,
						inpUsr.ID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			User: toPointer(inpUsr),
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			err = s.UpdateUser(context.Background(), c.User)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func Test_Store_DeleteUserByID(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.NoError(t, err)

	inpUsr := newFullUser()

	cc := map[string]struct {
		Expect func()
		Err    error
	}{
		"Error returned during user deletion": {
			Expect: func() {
				mock.ExpectExec(rawQuery("delete_user_by_id")).
					WithArgs(inpUsr.ID).
					WillReturnError(assert.AnError)
			},
			Err: assert.AnError,
		},
		"Successful user deletion": {
			Expect: func() {
				mock.ExpectExec(rawQuery("delete_user_by_id")).
					WithArgs(inpUsr.ID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			err = s.DeleteUserByID(context.Background(), inpUsr.ID)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestDetectErr(t *testing.T) {
	assert.Equal(t, 400, httpflow.ErrorCode(detectErr(&pq.Error{Constraint: "email_unique"})))
	assert.Equal(t, httpflow.ErrNotFound, detectErr(sql.ErrNoRows))
	assert.Equal(t, assert.AnError, detectErr(assert.AnError))
}

func newDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)

	return db, mock
}

func newFullUser() user.Core {
	return user.Core{
		ID:              xid.New(),
		CreatedAt:       timeutil.Now(),
		UpdatedAt:       timeutil.Now(),
		ActivatedAt:     zero.TimeFrom(timeutil.Now()),
		Email:           "user@email.com",
		UnverifiedEmail: zero.StringFrom("user123@email.com"),
		PasswordHash:    []byte("password123"),
		Verification: user.Token{
			ExpiresAt: null.TimeFrom(timeutil.Now().Add(time.Hour)),
			NextAt:    null.TimeFrom(timeutil.Now().Add(time.Hour)),
			Hash:      []byte("token"),
		},
		Recovery: user.Token{
			ExpiresAt: null.TimeFrom(timeutil.Now().Add(time.Hour)),
			NextAt:    null.TimeFrom(timeutil.Now().Add(time.Hour)),
			Hash:      []byte("token"),
		},
	}
}

func toPointer(c user.Core) *user.Core {
	return &c
}

func usrsToRows(usrs ...user.User) *sqlmock.Rows {
	if len(usrs) == 0 {
		return nil
	}

	var prefixVal string

	if len(usrs) > 1 {
		prefixVal = "user."
	}

	rr := []string{
		prefixVal + "id",
		prefixVal + "created_at",
		prefixVal + "updated_at",
		prefixVal + "activated_at",
		prefixVal + "email",
		prefixVal + "unverified_email",
		prefixVal + "password_hash",
		prefixVal + "verification.hash",
		prefixVal + "verification.next_at",
		prefixVal + "verification.expires_at",
		prefixVal + "recovery.hash",
		prefixVal + "recovery.next_at",
		prefixVal + "recovery.expires_at",
	}

	if len(usrs) > 1 {
		rr = append(rr, "page_count")
	}

	rows := sqlmock.NewRows(rr)

	for _, usr := range usrs {
		cr := usr.ExposeCore()
		vals := []driver.Value{
			cr.ID,
			cr.CreatedAt,
			cr.UpdatedAt,
			cr.ActivatedAt,
			cr.Email,
			cr.UnverifiedEmail,
			cr.PasswordHash,
			cr.Verification.Hash,
			cr.Verification.NextAt,
			cr.Verification.ExpiresAt,
			cr.Recovery.Hash,
			cr.Recovery.NextAt,
			cr.Recovery.ExpiresAt,
		}

		if len(usrs) > 1 {
			vals = append(vals, len(usrs))
		}

		rows.AddRow(vals...)
	}

	return rows
}
