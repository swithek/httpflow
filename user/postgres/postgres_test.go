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
		t.Run(cn, func(t *testing.T) {
			c.Expect()
			s, err := New(dbx, 0, func(err error) {})
			if c.Err != nil {
				assert.Equal(t, c.Err, err)
				return
			}

			assert.Nil(t, err)
			assert.Equal(t, dbx, s.db)
			assert.NotZero(t, s.q)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreDeleteInactive(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.Nil(t, err)

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
		t.Run(cn, func(t *testing.T) {
			c.Expect()
			err = s.deleteInactive()
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}

			assert.Nil(t, err)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}

}

func TestStoreCreate(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.Nil(t, err)

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
		t.Run(cn, func(t *testing.T) {
			c.Expect()
			err = s.Create(context.Background(), c.User)
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreFetchByID(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.Nil(t, err)

	inpUsr := newFullUser()

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
verification_token_hash AS verification.hash,
verification_next_at AS verification.next_at,
verification_expires_at AS verification.expires_at,
recovery_token_hash AS recovery.hash,
recovery_next_at AS recovery.next_at,
recovery_expires_at AS recovery.expires_at
FROM users WHERE id = $1 LIMIT 1;`).
					WithArgs(inpUsr.ID).
					WillReturnError(assert.AnError)
			},
			User: toPointer(inpUsr),
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
verification_token_hash AS verification.hash,
verification_next_at AS verification.next_at,
verification_expires_at AS verification.expires_at,
recovery_token_hash AS recovery.hash,
recovery_next_at AS recovery.next_at,
recovery_expires_at AS recovery.expires_at
FROM users WHERE id = $1 LIMIT 1;`).
					WithArgs(inpUsr.ID).
					WillReturnRows(usrToRows(inpUsr))
			},
			User: toPointer(inpUsr),
		},
	}

	for cn, c := range cc {
		t.Run(cn, func(t *testing.T) {
			c.Expect()
			usr, err := s.FetchByID(context.Background(), c.User.ID.String())
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}
			assert.Nil(t, err)
			assert.Equal(t, c.User, usr)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreFetchByEmail(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.Nil(t, err)

	inpUsr := newFullUser()

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
verification_token_hash AS verification.hash,
verification_next_at AS verification.next_at,
verification_expires_at AS verification.expires_at,
recovery_token_hash AS recovery.hash,
recovery_next_at AS recovery.next_at,
recovery_expires_at AS recovery.expires_at
FROM users WHERE email = $1 LIMIT 1;`).
					WithArgs(inpUsr.Email).
					WillReturnError(assert.AnError)
			},
			User: toPointer(inpUsr),
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
verification_token_hash AS verification.hash,
verification_next_at AS verification.next_at,
verification_expires_at AS verification.expires_at,
recovery_token_hash AS recovery.hash,
recovery_next_at AS recovery.next_at,
recovery_expires_at AS recovery.expires_at
FROM users WHERE email = $1 LIMIT 1;`).
					WithArgs(inpUsr.Email).
					WillReturnRows(usrToRows(inpUsr))
			},
			User: toPointer(inpUsr),
		},
	}

	for cn, c := range cc {
		t.Run(cn, func(t *testing.T) {
			c.Expect()
			usr, err := s.FetchByEmail(context.Background(), c.User.Email)
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}
			assert.Nil(t, err)
			assert.Equal(t, c.User, usr)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreUpdate(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.Nil(t, err)

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
		t.Run(cn, func(t *testing.T) {
			c.Expect()
			err = s.Update(context.Background(), c.User)
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}

			assert.Nil(t, err)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestStoreDeleteByID(t *testing.T) {
	db, mock := newDB(t)
	dbx := sqlx.NewDb(db, "postgres")
	s := Store{db: dbx}
	err := s.initSQL()
	require.Nil(t, err)

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
		t.Run(cn, func(t *testing.T) {
			c.Expect()
			err = s.DeleteByID(context.Background(), inpUsr.ID.String())
			if c.Err != nil {
				if c.Err == assert.AnError {
					assert.NotNil(t, err)
				} else {
					assert.Equal(t, c.Err, err)
				}
				return
			}

			assert.Nil(t, err)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestDetectErr(t *testing.T) {
	assert.Equal(t, 400, httpflow.ErrorCode(detectErr(&pq.Error{Constraint: "email_unique"})))
	assert.Equal(t, assert.AnError, detectErr(assert.AnError))
}

func newDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.Nil(t, err)
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

func usrToRows(usr user.Core) *sqlmock.Rows {
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
	rows.AddRow(usr.ID, usr.CreatedAt, usr.UpdatedAt, usr.ActivatedAt,
		usr.Email, usr.UnverifiedEmail, usr.PasswordHash,
		usr.Verification.Hash, usr.Verification.NextAt,
		usr.Verification.ExpiresAt, usr.Recovery.Hash,
		usr.Recovery.NextAt, usr.Recovery.ExpiresAt)

	return rows
}