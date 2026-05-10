package store

import (
    "os"
    "path/filepath"
)

func configDir() (string, error) {
    if override := os.Getenv("MB_DATA_DIR"); override != "" {
        return override, nil
    }
    if d, err := os.UserConfigDir(); err == nil && d != "" {
        return filepath.Join(d, "mail-bridge"), nil
    }
    // fallback în home
    home, err := os.UserHomeDir()
    if err != nil { return "", err }
    return filepath.Join(home, ".config", "mail-bridge"), nil
}

func tokensPath() (string, error) {
    dir, err := configDir()
    if err != nil { return "", err }
    if err := os.MkdirAll(dir, 0o700); err != nil { return "", err }
    return filepath.Join(dir, "tokens.json"), nil
}

func linuxKeyPath() (string, error) { // folosit doar pe linux
    dir, err := configDir()
    if err != nil { return "", err }
    if err := os.MkdirAll(dir, 0o700); err != nil { return "", err }
    return filepath.Join(dir, "key"), nil
}


