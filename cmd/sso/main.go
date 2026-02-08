package main

import (
	"log/slog"
	"os"
	"os/signal"
	"sso/internal/app"
	"sso/internal/config"
	"syscall"
)

const (
	local = "local"
	dev   = "development"
	prod  = "production"
)

func main() {
	// config
	cfg := config.MustLoad()

	// logger
	logger := setupLogger(cfg.Env)

	logger.Info("start application", slog.String("env", cfg.Env))

	// app init
	application := app.New(
		logger,
		cfg.GRPC.Port,
		cfg.StoragePath,
		cfg.TokenTTL,
	)

	// exc app
	go application.GRPCSrv.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	signalInp := <-stop

	application.GRPCSrv.Stop()

	logger.Info("application stopped by signal", slog.String("signal", signalInp.String()))
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case local:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)

	case dev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)

	case prod:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
