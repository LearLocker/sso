package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
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
	App(ctx context.Context, appId int) (models.App, error)
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

		log.Warn("Failed to hash password", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.userSaver.SaveUser(ctx, email, pasHash)
	if errors.Is(err, storage.ErrUserExists) {

		log.Warn("user already exists", slog.String("user", email))

		return 0, fmt.Errorf("%s: %w", op, err)
	}
	if err != nil {
		log.Error("failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (a *Auth) Login(
	ctx context.Context,
	email string,
	password []byte,
	appId int,
) (string, error) {
	const op = "auth.login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	user, err := a.userProvider.User(ctx, email)
	if errors.Is(err, storage.ErrUserNotFound) {

		log.Warn("user not found", slog.String("user", email))

		return "", fmt.Errorf("%s: %w", op, err)
	}
	if err != nil {
		log.Error("invalid credentials", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {

		log.Warn("invalid credentials", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	app, err := a.appProvider.App(ctx, appId)
	if errors.Is(err, storage.ErrAppNotFound) {

		log.Warn("app not found", slog.Int("app", appId))

		return "", fmt.Errorf("%s: %w", op, err)
	}
	if err != nil {
		log.Error("failed to retrieve app", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate token", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) IsAdmin(
	ctx context.Context,
	userId int64,
) (bool, error) {
	const op = "auth.is_admin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userId),
	)

	isAdmin, err := a.userProvider.IsAdmin(ctx, userId)
	if errors.Is(err, storage.ErrUserNotFound) {

		log.Warn("user not found", slog.Int64("user", userId))

		return false, fmt.Errorf("%s: %w", op, err)
	}
	if err != nil {
		log.Error("failed to retrieve user", sl.Err(err))

		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (a *Auth) App(ctx context.Context, appId int) (models.App, error) {
	const op = "auth.login"

	log := a.log.With(
		slog.String("op", op),
		slog.Int("app_id", appId),
	)

	app, err := a.appProvider.App(ctx, appId)
	if errors.Is(err, storage.ErrAppNotFound) {

		log.Warn("app not found", slog.Int("app", appId))

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	if err != nil {
		log.Error("failed to retrieve app", sl.Err(err))

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}
