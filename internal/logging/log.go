package logging

import (
    "io"
    "log/slog"
    "os"
)

type Config struct {
    Level string `yaml:"level"`
    File  string `yaml:"file"`
}

// Setup configurează un logger slog și returnează logger-ul și un closer pentru fișier (dacă e cazul).
func Setup(cfg Config) (*slog.Logger, func() error, error) {
    var w io.Writer = os.Stdout
    closer := func() error { return nil }

    if cfg.File != "" {
        f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
        if err != nil {
            return nil, closer, err
        }
        w = f
        closer = f.Close
    }

    lvl := new(slog.LevelVar)
    switch cfg.Level {
    case "debug":
        lvl.Set(slog.LevelDebug)
    case "warn":
        lvl.Set(slog.LevelWarn)
    case "error":
        lvl.Set(slog.LevelError)
    default:
        lvl.Set(slog.LevelInfo)
    }

    handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl})
    logger := slog.New(handler)
    slog.SetDefault(logger)
    return logger, closer, nil
}


