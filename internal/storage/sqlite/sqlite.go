package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"sso/internal/storage"

	"github.com/mattn/go-sqlite3"
)

type Storage struct {
	db *sql.DB
}

func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"

	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "storage.sqlite.SaveUser"
	stmt, err := s.db.Prepare("INSERT INTO urls (email, password_hash) VALUES (?, ?)")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, email, password)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && errors.Is(sqliteErr.ExtendedCode, sqlite3.ErrConstraintUnique) {
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

func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.User"

	stmt, err := s.db.Prepare("SELECT id, email, password_hash FROM users WHERE email = ?")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var user models.User
	err = stmt.QueryRowContext(ctx, email).Scan(&user.Id, &user.Email, &user.PasswordHash)

	if errors.Is(err, sql.ErrNoRows) {
		return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
	}

	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userId int64) (bool, error) {
	const op = "storage.sqlite.IsAdmin"

	stmt, err := s.db.Prepare("SELECT is_admin FROM users WHERE id = ?")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var res bool
	err = stmt.QueryRowContext(ctx, userId).Scan(&res)

	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
	}

	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return res, nil
}

func (s *Storage) App(ctx context.Context, appId int) (models.App, error) {
	const op = "storage.sqlite.User"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM users WHERE id = ?")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var app models.App
	err = stmt.QueryRowContext(ctx, appId).Scan(&app.Id, &app.Name, &app.Secret)

	if errors.Is(err, sql.ErrNoRows) {
		return models.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
	}

	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}
