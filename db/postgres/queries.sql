-- name: create_users_table
CREATE TABLE IF NOT EXISTS users (
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
);

-- name: insert_user
INSERT INTO users VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);

-- name: update_user_by_id
UPDATE users SET updated_at = $1,
activated_at = $2, 
email = $3,
unverified_email = $4,
password_hash = $5,
verification_token_hash = $6,
verification_next_at = $7,
verification_expires_at = $8,
recovery_token_hash = $9,
recovery_next_at = $10,
recovery_expires_at = $11 WHERE id = $12;

-- name: delete_user_by_id
DELETE FROM users WHERE id = $1;

-- name: delete_inactive_users
DELETE FROM users WHERE activated_at = NULL AND verification_expires_at < NOW();

-- name: select_customer_by_id
SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS verification.token_hash,
verification_next_at AS verification.next_at,
verification_expires_at AS verification.expires_at,
recovery_token_hash AS recovery.token_hash,
recovery_next_at AS recovery.next_at,
recovery_expires_at AS recovery.expires_at
FROM users WHERE id = $1 LIMIT 1;

-- name: select_customer_by_email
SELECT id, 
created_at,
updated_at,
activated_at,
email,
unverified_email,
password_hash,
verification_token_hash AS verification.token_hash,
verification_next_at AS verification.next_at,
verification_expires_at AS verification.expires_at,
recovery_token_hash AS recovery.token_hash,
recovery_next_at AS recovery.next_at,
recovery_expires_at AS recovery.expires_at
FROM users WHERE email = $1 LIMIT 1;
