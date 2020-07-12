package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swithek/httpflow"
	"github.com/swithek/httpflow/testutil"
	"github.com/swithek/httpflow/user"
	"gopkg.in/guregu/null.v3"
	"gopkg.in/guregu/null.v3/zero"
)

func TestNew(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")

	cc := map[string]struct {
		Expect func()
		Err    error
	}{
		"Error returned during users table creation": {
			Expect: func() {
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	activated_at TIMESTAMPTZ,
	email TEXT NOT NULL,
	unverified_email TEXT,
	password_hash BYTEA NOT NULL,
	verification_token_hash BYTEA,
	verification_next_at TIMESTAMPTZ,
	verification_expires_at TIMESTAMPTZ,
	recovery_token_hash BYTEA,
	recovery_next_at TIMESTAMPTZ,
	recovery_expires_at TIMESTAMPTZ,
	CONSTRAINT email_unique UNIQUE(email)
);`).
					WillReturnError(assert.AnError)
			},
			Err: assert.AnError,
		},
		"Successful store init and users table creation": {
			Expect: func() {
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL,
	activated_at TIMESTAMPTZ,
	email TEXT NOT NULL,
	unverified_email TEXT,
	password_hash BYTEA NOT NULL,
	verification_token_hash BYTEA,
	verification_next_at TIMESTAMPTZ,
	verification_expires_at TIMESTAMPTZ,
	recovery_token_hash BYTEA,
	recovery_next_at TIMESTAMPTZ,
	recovery_expires_at TIMESTAMPTZ,
	CONSTRAINT email_unique UNIQUE(email)
);`).
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			s, err := New(dbx, 0, func(err error) {})
			if c.Err != nil {
				assert.Equal(t, c.Err, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, dbx, s.db)
			assert.NotZero(t, s.q)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreDeleteInactive(t *testing.T) {
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
				mock.ExpectExec("DELETE FROM users WHERE activated_at = NULL AND verification_expires_at < NOW();").
					WillReturnError(assert.AnError)
			},
			Err: assert.AnError,
		},
		"Successful inactive users deletion": {
			Expect: func() {
				mock.ExpectExec("DELETE FROM users WHERE activated_at = NULL AND verification_expires_at < NOW();").
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

func TestStoreStats(t *testing.T) {
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
				mock.ExpectQuery(`SELECT COUNT(*) AS total_count FROM users;`).
					WillReturnError(assert.AnError)
			},
			Err: assert.AnError,
		},
		"Successful stats selection": {
			Expect: func() {
				mock.ExpectQuery(`SELECT COUNT(*) AS total_count FROM users;`).
					WillReturnRows(sqlmock.NewRows(
						[]string{"total_count"}).AddRow(11))
			},
			Stats: user.CoreStats{TotalCount: 11},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			st, err := s.Stats(context.Background())
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.Stats, st)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreCreate(t *testing.T) {
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
				mock.ExpectExec("INSERT INTO users VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);").
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
				mock.ExpectExec("INSERT INTO users VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);").
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

			err = s.Create(context.Background(), c.User)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoryFetchMany(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.NoError(t, err)

	inpUsrs := []user.User{
		toPointer(newFullUser()),
		toPointer(newFullUser()),
		toPointer(newFullUser()),
	}

	inpEml := "1@em"

	cc := map[string]struct {
		Expect func()
		Query  httpflow.Query
		Users  []user.User
		Err    error
	}{
		"Invalid query data": {
			Expect: func() {},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email123",
				FilterVal: inpEml,
				SortBy:    "created_at",
				Desc:      true,
			},
			Err: assert.AnError,
		},
		"Error returned during users select": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email LIKE '%' || $1 || '%' ORDER BY created_at DESC LIMIT $2 OFFSET $3;`).
					WithArgs(inpEml, 5, 45).
					WillReturnError(assert.AnError)
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "created_at",
				Desc:      true,
			},
			Err: assert.AnError,
		},
		"Successful users select by email in desc order of creation date": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email LIKE '%' || $1 || '%' ORDER BY created_at DESC LIMIT $2 OFFSET $3;`).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "created_at",
				Desc:      true,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in asc order of creation date": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email LIKE '%' || $1 || '%' ORDER BY created_at ASC LIMIT $2 OFFSET $3;`).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "created_at",
				Desc:      false,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in desc order of last update date": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email LIKE '%' || $1 || '%' ORDER BY updated_at DESC LIMIT $2 OFFSET $3;`).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "updated_at",
				Desc:      true,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in asc order of last update date": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email LIKE '%' || $1 || '%' ORDER BY updated_at ASC LIMIT $2 OFFSET $3;`).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "updated_at",
				Desc:      false,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in desc order of activation date": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email LIKE '%' || $1 || '%' ORDER BY activated_at DESC LIMIT $2 OFFSET $3;`).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "activated_at",
				Desc:      true,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in asc order of activation date": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email LIKE '%' || $1 || '%' ORDER BY activated_at ASC LIMIT $2 OFFSET $3;`).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "activated_at",
				Desc:      false,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in desc order of email": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email LIKE '%' || $1 || '%' ORDER BY email DESC LIMIT $2 OFFSET $3;`).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "email",
				Desc:      true,
			},
			Users: inpUsrs,
		},
		"Successful users select by email in asc order of email": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email LIKE '%' || $1 || '%' ORDER BY email ASC LIMIT $2 OFFSET $3;`).
					WithArgs(inpEml, 5, 45).
					WillReturnRows(usrsToRows(inpUsrs...))
			},
			Query: httpflow.Query{
				Limit:     5,
				Page:      10,
				FilterBy:  "email",
				FilterVal: inpEml,
				SortBy:    "email",
				Desc:      false,
			},
			Users: inpUsrs,
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			usrs, err := s.FetchMany(context.Background(), c.Query)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.Users, usrs)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreFetchByID(t *testing.T) {
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
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE id = $1 LIMIT 1;`).
					WithArgs(inpUsr.ID).
					WillReturnError(assert.AnError)
			},
			User: inpUsr,
			Err:  assert.AnError,
		},
		"Successful user selection": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE id = $1 LIMIT 1;`).
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

			usr, err := s.FetchByID(context.Background(), c.User.ID)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.User, usr)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreFetchByEmail(t *testing.T) {
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
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email = $1 LIMIT 1;`).
					WithArgs(inpUsr.Email).
					WillReturnError(assert.AnError)
			},
			User: inpUsr,
			Err:  assert.AnError,
		},
		"Successful user selection": {
			Expect: func() {
				mock.ExpectQuery(`SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS "verification.hash",
verification_next_at AS "verification.next_at",
verification_expires_at AS "verification.expires_at",
recovery_token_hash AS "recovery.hash",
recovery_next_at AS "recovery.next_at",
recovery_expires_at AS "recovery.expires_at"
FROM users WHERE email = $1 LIMIT 1;`).
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

			usr, err := s.FetchByEmail(context.Background(), c.User.Email)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.Equal(t, c.User, usr)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreUpdate(t *testing.T) {
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
				mock.ExpectExec(`UPDATE users SET updated_at = $1,
activated_at = $2, 
email = $3,
unverified_email = $4,
password_hash = $5,
verification_token_hash = $6,
verification_next_at = $7,
verification_expires_at = $8,
recovery_token_hash = $9,
recovery_next_at = $10,
recovery_expires_at = $11 WHERE id = $12;`).
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
				mock.ExpectExec(`UPDATE users SET updated_at = $1,
activated_at = $2, 
email = $3,
unverified_email = $4,
password_hash = $5,
verification_token_hash = $6,
verification_next_at = $7,
verification_expires_at = $8,
recovery_token_hash = $9,
recovery_next_at = $10,
recovery_expires_at = $11 WHERE id = $12;`).
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

			err = s.Update(context.Background(), c.User)
			testutil.AssertEqualError(t, c.Err, err)
			if err != nil {
				return
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreDeleteByID(t *testing.T) {
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
				mock.ExpectExec("DELETE FROM users WHERE id = $1;").
					WithArgs(inpUsr.ID).
					WillReturnError(assert.AnError)
			},
			Err: assert.AnError,
		},
		"Successful user deletion": {
			Expect: func() {
				mock.ExpectExec("DELETE FROM users WHERE id = $1;").
					WithArgs(inpUsr.ID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
		},
	}

	for cn, c := range cc {
		c := c

		t.Run(cn, func(t *testing.T) {
			c.Expect()

			err = s.DeleteByID(context.Background(), inpUsr.ID)
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
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		ActivatedAt:     zero.TimeFrom(time.Now()),
		Email:           "user@email.com",
		UnverifiedEmail: zero.StringFrom("user123@email.com"),
		PasswordHash:    []byte("password123"),
		Verification: user.Token{
			ExpiresAt: null.TimeFrom(time.Now().Add(time.Hour)),
			NextAt:    null.TimeFrom(time.Now().Add(time.Hour)),
			Hash:      []byte("token"),
		},
		Recovery: user.Token{
			ExpiresAt: null.TimeFrom(time.Now().Add(time.Hour)),
			NextAt:    null.TimeFrom(time.Now().Add(time.Hour)),
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

	rows := sqlmock.NewRows([]string{
		"id",
		"created_at",
		"updated_at",
		"activated_at",
		"email",
		"unverified_email",
		"password_hash",
		"verification.hash",
		"verification.next_at",
		"verification.expires_at",
		"recovery.hash",
		"recovery.next_at",
		"recovery.expires_at",
	})

	for _, usr := range usrs {
		cr := usr.ExposeCore()
		rows.AddRow(cr.ID, cr.CreatedAt, cr.UpdatedAt, cr.ActivatedAt,
			cr.Email, cr.UnverifiedEmail, cr.PasswordHash,
			cr.Verification.Hash, cr.Verification.NextAt,
			cr.Verification.ExpiresAt, cr.Recovery.Hash,
			cr.Recovery.NextAt, cr.Recovery.ExpiresAt)
	}

	return rows
}
