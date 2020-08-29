// Package postgres provides functionality for interaction
// with postgres database.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gchaincl/dotsql"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/swithek/dotsqlx"
	"github.com/swithek/httpflow"
	"github.com/swithek/httpflow/logutil"
	"github.com/swithek/httpflow/user"
)

// Store contains dependencies needed for direct
// communication with the postgres data store.
//go:generate esc -o queries.go -pkg postgres -private ./queries.sql
type Store struct {
	log zerolog.Logger
	db  *sqlx.DB
	q   *dotsqlx.DotSqlx
}

// NewStore creates a fresh instance of the store.
// Last parameter specifies how often should the inactive users' cleanup
// operation execute. 0 disables cleanup.
func NewStore(log zerolog.Logger, db *sqlx.DB, d time.Duration) (*Store, error) {
	s := &Store{log: log, db: db}
	if err := s.initSQL(); err != nil {
		// unlikely to happen
		return nil, err
	}

	if _, err := s.q.Exec(db, "create_users_table"); err != nil {
		return nil, err
	}

	go s.startCleanup(d)

	return s, nil
}

// initSQL loads all the required SQL queries.
func (s *Store) initSQL() error {
	q, err := dotsql.LoadFromString(_escFSMustString(false, "/queries.sql"))
	if err != nil {
		// unlikely to happen
		return err
	}

	s.q = dotsqlx.Wrap(q)

	return nil
}

// startCleanup initiates a non-stopping cleanup cycle.
func (s *Store) startCleanup(d time.Duration) {
	if d == 0 {
		return
	}

	t := time.NewTicker(d)

	for {
		if err := s.deleteInactive(); err != nil {
			logutil.Critical(s.log, err).Msg("cannot delete inactive")
		}

		<-t.C
	}
}

// deleteInactive deletes all inactive users from the data store.
func (s *Store) deleteInactive() error {
	_, err := s.q.Exec(s.db, "delete_inactive_users")
	if err != nil {
		return err
	}

	return nil
}

// UserStats returns users' data statistics from the underlying data store.
func (s *Store) UserStats(ctx context.Context) (user.Stats, error) {
	var st user.CoreStats
	if err := s.q.GetContext(ctx, s.db, &st, "select_stats"); err != nil {
		return nil, detectErr(err)
	}

	return st, nil
}

// CreateUser inserts the freshly created user into the underlying
// data store.
func (s *Store) CreateUser(ctx context.Context, usr user.User) error {
	usrC := usr.ExposeCore()
	_, err := s.q.ExecContext(ctx, s.db, "insert_user",
		usrC.ID,
		usrC.CreatedAt,
		usrC.UpdatedAt,
		usrC.ActivatedAt,
		usrC.Email,
		usrC.UnverifiedEmail,
		usrC.PasswordHash,
		usrC.Verification.Hash,
		usrC.Verification.NextAt,
		usrC.Verification.ExpiresAt,
		usrC.Recovery.Hash,
		usrC.Recovery.NextAt,
		usrC.Recovery.ExpiresAt,
	)

	return detectErr(err)
}

// FetchManyUsers retrieves multiple users from the underlying data store by
// the provided query.
func (s *Store) FetchManyUsers(ctx context.Context, qr httpflow.Query) ([]user.User, error) {
	err := qr.Validate(user.CheckFilterKey, user.CheckSortKey)
	if err != nil {
		return nil, err
	}

	ord := "asc"
	if qr.Desc {
		ord = "desc"
	}

	name := fmt.Sprintf("select_users_by_%s_%s_%s", qr.FilterBy, ord, qr.SortBy)

	crs := []*user.Core{}

	err = s.q.SelectContext(ctx, s.db, &crs, name, qr.FilterVal, qr.Limit, qr.Limit*(qr.Page-1))
	if err != nil {
		return nil, detectErr(err)
	}

	usrs := make([]user.User, len(crs))
	for i, cr := range crs {
		usrs[i] = cr
	}

	return usrs, nil
}

// FetchUserByID retrieves a user from the underlying data store
// by their ID.
func (s *Store) FetchUserByID(ctx context.Context, id xid.ID) (user.User, error) {
	usr := &user.Core{}
	if err := s.q.GetContext(ctx, s.db, usr, "select_user_by_id", id); err != nil {
		return nil, detectErr(err)
	}

	return usr, nil
}

// FetchUserByEmail retrieves a user from the underlying data store
// by their email address.
func (s *Store) FetchUserByEmail(ctx context.Context, eml string) (user.User, error) {
	usr := &user.Core{}
	if err := s.q.GetContext(ctx, s.db, usr, "select_user_by_email", eml); err != nil {
		return nil, detectErr(err)
	}

	return usr, nil
}

// UpdateUser updates user's data in the underlying data store.
func (s *Store) UpdateUser(ctx context.Context, usr user.User) error {
	usrC := usr.ExposeCore()
	_, err := s.q.ExecContext(ctx, s.db, "update_user_by_id",
		usrC.UpdatedAt,
		usrC.ActivatedAt,
		usrC.Email,
		usrC.UnverifiedEmail,
		usrC.PasswordHash,
		usrC.Verification.Hash,
		usrC.Verification.NextAt,
		usrC.Verification.ExpiresAt,
		usrC.Recovery.Hash,
		usrC.Recovery.NextAt,
		usrC.Recovery.ExpiresAt,
		usrC.ID,
	)

	return detectErr(err)
}

// DeleteUserByID deletes the user from the underlying data store
// by their ID.
func (s *Store) DeleteUserByID(ctx context.Context, id xid.ID) error {
	_, err := s.q.ExecContext(ctx, s.db, "delete_user_by_id", id)
	return detectErr(err)
}

// detectErr determines whether postgres' error needs any additional
// modifications or not.
func detectErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return httpflow.ErrNotFound
	}

	var perr *pq.Error
	if errors.As(err, &perr) && perr.Constraint == "email_unique" {
		return httpflow.NewError(nil, http.StatusBadRequest, "email address cannot be used")
	}

	return err
}
