# oauth2-mail-proxy

Local IMAP/SMTP proxy with OAuth2 authentication (Gmail and Microsoft 365), plus a web admin UI.

## What this project does

- exposes local SMTP on `127.0.0.1:1025`
- exposes local IMAP on `127.0.0.1:1143`
- exposes Admin UI on `127.0.0.1:7777`
- lets classic mail clients work without storing provider account passwords

## Requirements

- Windows 10/11
- Go 1.22+
- PowerShell

## Quick build

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

The output binary will be available at `dist\mail-bridge.exe`.

## Configuration

1. Copy the example config:

```powershell
copy .\scripts\mail-bridge.yml.example .\mail-bridge.yml
```

2. Update `mail-bridge.yml`:
- accounts (`accounts`)
- OAuth apps (`oauth_apps`)
- admin password hash (`security.admin_password_hash`)

To generate a password hash, use:

```powershell
go run .\cmd\hashpw
```

## Run manually

```powershell
.\dist\mail-bridge.exe --config .\mail-bridge.yml
```

## Install as a Windows service (auto-start)

The `service.ps1` script installs the app as an NSSM-managed Windows service, configures restart policy, and enables auto-start.

Run PowerShell as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\service.ps1
```

The service will start automatically after a system reboot.

## Sensitive files

The local `mail-bridge.yml` file is ignored by Git (contains secrets). Do not commit real credentials.
