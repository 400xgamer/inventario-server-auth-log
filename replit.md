# Controle de Estoque - 3F Resinados

## Overview
Inventory management system (Controle de Estoque) for "3F Resinados" - a Brazilian company managing adhesives and supplies. The app provides stock tracking, product registration, dashboard analytics, and audit history with user authentication.

## Recent Changes
- 2026-02-13: Imported from GitHub and configured for Replit environment
  - Switched to HTTP mode (DISABLE_HTTPS=1) since Replit handles TLS termination
  - Set PORT=5000 for Replit webview
  - Enabled trust proxy for session cookies behind Replit's reverse proxy
  - Added Cache-Control headers to prevent stale content in iframe

## Project Architecture
- **Runtime**: Node.js 20 with Express
- **Frontend**: Single-page HTML app served statically from `public/` directory (Tailwind CSS via CDN, Font Awesome, Chart.js, QR code libs)
- **Backend**: Express server (`server.js`) with JSON file-based storage (`data.json`)
- **Authentication**: Session-based auth with bcrypt password hashing
- **Data Storage**: File-based JSON (`data.json`) - no database required

## Key Files
- `server.js` - Main server: auth, API routes, static file serving
- `public/index.html` - Complete frontend SPA (HTML + inline JS)
- `data.json` - Runtime data storage (gitignored)
- `package.json` - Node.js dependencies

## Default Login
- Username: `admin@3f.local`
- Password: `senha123`

## Environment Variables
- `PORT=5000` - Server port
- `DISABLE_HTTPS=1` - Run in HTTP mode (Replit provides TLS)
- `TRUST_PROXY=1` - Trust reverse proxy headers

## User Preferences
- Language: Portuguese (Brazilian)
