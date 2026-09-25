# Tracker Beta

Tracker Beta is a local browser activity security monitoring project built with Python, Flask, SQLite, and a Chrome extension.

The project records browser activity locally and provides a dashboard for monitoring, classifying, searching, and reviewing browser events.

## Features

- Local Chrome browser activity logging
- Records:
  - Timestamp
  - macOS username
  - Domain
  - URL
  - Browser
- SQLite event database
- Web-based security dashboard
- Domain watchlist management
- Normal, Watch, and Flagged classifications
- Recent security event monitoring
- Search and filtering by domain, user, and date
- Visit statistics and activity charts
- CSV security-event export
- SHA-256 hash chaining for tamper-evident logs
- Database integrity verification
- Manual integrity verification
- Admin username/password authentication
- Hashed password storage
- Session-based dashboard protection
- Automatic startup on macOS using LaunchAgents

## Architecture

Chrome Extension  
↓  
Flask Local API  
↓  
SQLite Database  
↓  
Security Dashboard

Tracker Beta runs locally on:

`http://127.0.0.1:8765`

The Flask server is intentionally bound to localhost so the dashboard is not exposed directly to other devices on the network.

## Security

Tracker Beta includes several security controls:

### Authentication

Sensitive dashboard routes require an authenticated administrator session.

Passwords are not stored in plaintext. Werkzeug password hashing is used to store and verify the administrator password.

Authentication information is stored locally and is excluded from Git.

### Hash-Chain Integrity

Each browser event contains:

- A hash of the current event
- The hash of the previous event

This creates a continuous SHA-256 hash chain.

Tracker Beta can recalculate and verify the chain to detect whether protected historical records have been modified or whether a chain link has been broken.

### Domain Watchlist

Administrators can classify domains as:

- Normal
- Watch
- Flagged

Security events can then be reviewed separately from normal browser activity.

## Privacy

Tracker Beta is designed as a local security project.

The following files are intentionally excluded from this repository:

- Browser activity databases
- Authentication configuration
- Password hashes
- Session secrets
- Database backups
- Local development backups

Do not commit the contents of the `data/` directory.

## Technology

- Python
- Flask
- SQLite
- HTML/CSS
- JavaScript
- Chrome Extension Manifest V3
- SHA-256
- macOS LaunchAgents

## Project Status

Tracker Beta is currently under active development.

Potential future improvements include:

- Failed-login rate limiting and account lockout
- Administrative audit logging
- macOS security notifications
- Automatic database backups
- HMAC-based event integrity
- Additional browser support
- More advanced security analytics
