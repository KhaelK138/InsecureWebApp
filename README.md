# Vulnerable Basic Banking Application - Secure Branch

> **Note:** This branch is an outdated attempt at building a version of the app with all vulnerabilities patched. It is no longer actively maintained and does not reflect the current state of the main application. Many features added since this branch was created are not covered here.

## Secure Files

- `app_SECURE.py` - Hardened version of the app with most vulnerabilities remediated
- `schema_secure.sql` - Secure database schema
- `config/config.config` - Configuration for the secure app
- `templates/*_secure.html` - Secure template variants

## Known Gaps

The secure version has most vulnerabilities fixed, with the exception of:
- Flask session tokens not being invalidated
- Account email enumeration still existing (albeit with reCAPTCHA sort of implemented)

## Usage

```bash
python3 app_SECURE.py closed   # localhost only
python3 app_SECURE.py open     # all interfaces
python3 app_SECURE.py open -p 8080  # custom port
```
