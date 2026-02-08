package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		password []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userId int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appId int32) (models.App, error)
}

func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		appProvider:  appProvider,
		log:          log,
		tokenTTL:     tokenTTL,
	}
}

func (a *Auth) RegisterUser(
	ctx context.Context,
	email string,
	password []byte,
) (int64, error) {
	const op = "auth.register"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	pasHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {

		log.Info("Failed to hash password", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, pasHash)
	if errors.Is(err, storage.ErrUserExists) {

		log.Info("url already exists", slog.String("user", email))

		return 0, fmt.Errorf("%s: %w", op, err)
	}
	if err != nil {
		log.Error("failed to save url", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (a *Auth) Login(
	ctx context.Context,
	email string,
	password []byte,
	appId int32,
) (string, error) {
	panic("implement me")
}

func (a *Auth) IsAdmin(
	ctx context.Context,
	userId int64,
) (bool, error) {
	panic("implement me")
}
