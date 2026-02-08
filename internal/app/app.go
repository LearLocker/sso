package app

import (
	"log/slog"
	"os"
	"sso/internal/app/grpc"
	"sso/internal/lib/logger/sl"
	"sso/internal/storage/sqlite"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration,
) *App {

	storage, err := sqlite.New(storagePath)
	if err != nil {
		log.Error("failed to create storage", sl.Err(err))
		os.Exit(1)
	}

	grpcApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}
