package main

import (
    "context"
    "flag"
    "fmt"
    "net"
    "net/http"
    "os"
    "os/signal"
    "runtime"
    "syscall"
    "time"

    "mail-bridge/internal/admin"
    "mail-bridge/internal/config"
    "mail-bridge/internal/imap"
    "mail-bridge/internal/logging"
    "mail-bridge/internal/smtp"
    "mail-bridge/internal/store"
    "mail-bridge/internal/oauth"
)

func main() {
    cfgPath := flag.String("config", "mail-bridge.yml", "Path către fișierul de configurare YAML")
    flag.Parse()

    // Încarcă config
    cfg, err := config.Load(*cfgPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "eroare config: %v\n", err)
        os.Exit(1)
    }

    // Initializează logger-ul global
    lg, closer, err := logging.Setup(cfg.Logging)
    if err != nil {
        fmt.Fprintf(os.Stderr, "eroare logger: %v\n", err)
        os.Exit(1)
    }
    defer func() { _ = closer() }()

    lg.Info("mail-bridge pornește", "version", "0.1.0", "go", runtime.Version(), "os", runtime.GOOS, "arch", runtime.GOARCH)

    // Context de oprire grațioasă
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    // Inițializează store + oauth manager
    st := store.New()
    om := oauth.NewManager(st)

    // Pornește Admin UI
    adminSrv := &http.Server{
        Addr:              cfg.Listen.Admin,
        Handler:           admin.NewServer(lg, cfg, st, om),
        ReadHeaderTimeout: 10 * time.Second,
    }

    go func() {
        lg.Info("Admin UI ascultă", "addr", cfg.Listen.Admin)
        if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            lg.Error("Admin UI oprit cu eroare", "error", err)
        }
    }()

    // IMAP proxy (schelet)
    go func() {
        ln, err := net.Listen("tcp", cfg.Listen.IMAP)
        if err != nil {
            lg.Error("Nu pot asculta IMAP", "addr", cfg.Listen.IMAP, "error", err)
            return
        }
        lg.Info("IMAP proxy ascultă", "addr", cfg.Listen.IMAP)
        if err := imap.Serve(ctx, lg, ln, cfg, om); err != nil {
            lg.Error("IMAP proxy oprit", "error", err)
        }
    }()

    // SMTP proxy
    go func() {
        if err := smtp.Serve(ctx, lg, cfg, om); err != nil {
            lg.Error("SMTP proxy oprit", "error", err)
        }
    }()

    // Hot-reload semnal (Linux/Unix)
    go func() {
        hupCh := make(chan os.Signal, 1)
        signal.Notify(hupCh, syscall.SIGHUP)
        for range hupCh {
            lg.Info("SIGHUP primit: reîncarc config-ul")
            newCfg, err := config.Load(*cfgPath)
            if err != nil {
                lg.Error("Eroare reload config", "error", err)
                continue
            }
            cfg.ReplaceWith(newCfg)
            lg.Info("Config reîncărcat")
        }
    }()

    <-ctx.Done()
    lg.Info("Oprire în curs...")

    shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancelShutdown()
    _ = adminSrv.Shutdown(shutdownCtx)
    lg.Info("Gata.\n")
}


