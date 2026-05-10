# oauth2-mail-proxy

Local IMAP/SMTP proxy with OAuth2 authentication (Gmail and Microsoft 365), plus a web admin UI.

[![Go Version](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/platform-windows-blue)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

## Features

- exposes local SMTP on `127.0.0.1:1025`
- exposes local IMAP on `127.0.0.1:1143`
- exposes Admin UI on `127.0.0.1:7777`
- lets classic mail clients work without storing provider account passwords

## Requirements

- Windows 10/11
- Go 1.22+
- PowerShell

## Quick Start

### 1) Clone and build

```powershell
git clone https://github.com/mirelsen/oauth2-mail-proxy.git
cd oauth2-mail-proxy
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

The output binary will be available at `dist\mail-bridge.exe`.

### 2) Create local config

Copy the example config:

```powershell
copy .\scripts\mail-bridge.yml.example .\mail-bridge.yml
```

Then update `mail-bridge.yml`:
- accounts (`accounts`)
- OAuth apps (`oauth_apps`)
- admin password hash (`security.admin_password_hash`)

Generate an admin password hash:

```powershell
go run .\cmd\hashpw
```

### 3) Run the proxy manually

```powershell
.\dist\mail-bridge.exe --config .\mail-bridge.yml
```

### 4) Authorize accounts in Admin UI

Open `http://127.0.0.1:7777`, sign in with your admin credentials, then complete OAuth authorization for each configured account.

## Install as a Windows service (auto-start)

The `service.ps1` script installs the app as an NSSM-managed Windows service, configures restart policy, and enables auto-start.

Run PowerShell as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\service.ps1
```

The service will start automatically after a system reboot.

## Mail client settings

After OAuth setup is complete, configure your mail client to connect locally:
- IMAP host: `127.0.0.1`, port `1143`
- SMTP host: `127.0.0.1`, port `1025`
- username/password: values from `accounts[].local_login`

## Troubleshooting

- `port already in use`: change ports in `mail-bridge.yml` under `listen`
- `OAuth callback error`: verify `redirect_url` is exactly `http://127.0.0.1:7777/oauth/callback` (or the value your app registration uses)
- service does not start: inspect `mail-bridge.out.log` and `mail-bridge.err.log`
- build fails: confirm Go 1.22+ and run `go mod tidy`

## Security Notes

The local `mail-bridge.yml` file is ignored by Git (contains secrets). Do not commit real credentials.

`mail-bridge.json` may include tenant and application details; review before sharing.

## Roadmap

- Linux service setup documentation (systemd)
- Optional Docker packaging
- CI workflow for automatic builds

## License

MIT (recommended). Add a `LICENSE` file if you want the badge and policy to be explicit.
