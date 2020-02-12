package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gchaincl/dotsql"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/swithek/httpflow"
	"github.com/swithek/httpflow/user"
)

// Store contains dependencies needed for direct
// communication with the postgres data store.
//go:generate esc -o queries.go -pkg postgres -private ./queries.sql
type Store struct {
	db      *sqlx.DB
	q       *dotsql.DotSql
	onError httpflow.ErrorExec
}

// New creates a fresh instance of the store.
// Last parameter specifies how often should the inactive users' cleanup
// operation execute. 0 disables cleanup.
func New(db *sqlx.DB, q *dotsql.DotSql, onError httpflow.ErrorExec,
	d time.Duration) (*Store, error) {
	q, err := dotsql.LoadFromString(_escFSMustString(false, "/queries.sql"))
	if err != nil {
		return nil, err
	}

	s := &Store{db: db, q: q, onError: onError}

	if _, err = s.q.Exec(db, "create_users_table"); err != nil {
		return nil, err
	}

	go s.startCleanup(d)

	return s, nil
}

// startCleanup initiates a non-stopping cleanup cycle.
func (s *Store) startCleanup(d time.Duration) {
	if d == 0 {
		return
	}

	t := time.NewTicker(d)
	for {
		if err := s.deleteInactive(); err != nil {
			s.onError(err)
		}
		<-t.C
	}
}

// deleteInactive deletes all inactive users from the data store.
func (s *Store) deleteInactive() error {
	_, err := s.q.Exec(s.db, "delete_inactive_users")
	return fmt.Errorf("inactive users deletion: %w", err)
}

// Create inserts the freshly created user into the underlying
// data store.
func (s *Store) Create(ctx context.Context, usr user.User) error {
	usrC := usr.Core()
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

// FetchByID retrieves a user from the underlying data store
// by their ID.
func (s *Store) FetchByID(ctx context.Context, id string) (user.User, error) {
	q, err := s.q.Raw("select_user_by_id")
	if err != nil {
		return nil, err
	}

	usr := &user.Core{}
	if err = s.db.GetContext(ctx, usr, q, id); err != nil {
		return nil, detectErr(err)
	}

	return usr, nil
}

// FetchByEmail retrieves a user from the underlying data store
// by their email address.
func (s *Store) FetchByEmail(ctx context.Context, eml string) (user.User, error) {
	q, err := s.q.Raw("select_user_by_email")
	if err != nil {
		return nil, err
	}

	usr := &user.Core{}
	if err = s.db.GetContext(ctx, usr, q, eml); err != nil {
		return nil, detectErr(err)
	}

	return usr, nil
}

// Update updates user's data in the underlying data store.
func (s *Store) Update(ctx context.Context, usr user.User) error {
	usrC := usr.Core()
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

// DeleteByID deletes the user from the underlying data store
// by their ID.
func (s *Store) DeleteByID(ctx context.Context, id string) error {
	_, err := s.q.ExecContext(ctx, s.db, "delete_user_by_id", id)
	return detectErr(err)
}

// detectErr determines whether postgres' error needs any additional
// modifications.
func detectErr(err error) error {
	var perr *pq.Error
	if errors.As(err, &perr) {
		switch perr.Constraint {
		case "email_unique":
			return httpflow.NewError(nil, http.StatusBadRequest,
				"email address cannot be used")
		}
	}

	return err
}
