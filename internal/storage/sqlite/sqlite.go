package sqlite

import (
	"database/sql"
	"fmt"
	"sso/internal/storage"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type Storage struct {
	db *sql.DB
}

func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"

	db, err := sql.Open("sqlite", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	stmt, err := db.Prepare(`
	CREATE TABLE IF NOT EXISTS users (
    	id Int PRIMARY KEY,
    	email TEXT NOT NULL UNIQUE,
    	password_hash TEXT NOT NULL,
    	is_admin BOOL NOT NULL);
	CREATE INDEX IF NOT EXISTS idx_email ON users(email);
    `)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	_, err = stmt.Exec()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(email string, password string) (int64, error) {
	const op = "storage.sqlite.SaveUser"
	stmt, err := s.db.Prepare("INSERT INTO urls (email, password_hash) VALUES (?, ?)")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email, password)
	if err != nil {

		if sqlErr, ok := err.(*sqlite.Error); ok && sqlErr.Code() == sqlite3.SQLITE_CONSTRAINT {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: failed to get las inserted id: %w", op, err)
	}

	return id, nil
}
