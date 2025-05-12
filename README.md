# Passkey Authentication Demo with Flask

This project demonstrates a secure passwordless authentication system using WebAuthn passkeys, built with Flask.

## Features

- User registration with CAPTCHA verification
- WebAuthn-based passwordless authentication
- Device credential management
- Mobile-responsive UI
- Admin dashboard with operation logs

## Prerequisites

1. [Docker](https://docs.docker.com/get-docker/)
2. [Docker Compose](https://docs.docker.com/compose/install/)
3. [ngrok](https://ngrok.com/download) (for HTTPS tunneling)

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/Passkey-Authentication.git
cd Passkey-Authentication
```

### 2. Build and run the application

```bash
# Build the Docker container
docker-compose build app

# Start all services (app, PostgreSQL, Redis)
docker-compose up -d

# Verify all containers are running
docker-compose ps
```

### 3. Set up HTTPS with ngrok

WebAuthn requires a secure context (HTTPS). For development purposes, we use ngrok to create a secure tunnel.

```bash
# Open a tunnel to port 5000
ngrok http 5000
```

This will provide a public HTTPS URL that forwards to your local application.

### 4. Access the application

Open the ngrok URL in your browser to use the application.

## Important Notes and Limitations

### ngrok URL Changes

In the free version of ngrok, the URL changes each time you restart the tunnel. Because WebAuthn credentials are tied to the domain name, you will need to register new credentials each time the ngrok URL changes.

### For Production Use

- Use a stable domain name with proper SSL certificates
- Configure proper database backups
- Replace the Tailwind CDN with a compiled version
- Set secure, environment-specific configuration values

## Troubleshooting

### Registration Issues

If you encounter a 500 error during registration:

1. Make sure all containers are running properly
2. Check the application logs: `docker-compose logs app`
3. Verify that Redis and PostgreSQL are accessible from the app container

### WebAuthn Not Working

1. Make sure you're using a secure context (HTTPS)
2. Confirm your browser supports WebAuthn
3. Check browser console for specific errors

## Security Features

- CAPTCHA protection for registration
- No passwords stored
- Cryptographic authentication
- Operation logging for security audits

## Data Persistence

User accounts and passkey credentials are stored in a PostgreSQL database that persists
between container restarts. If you wish to completely reset the application data, run:

```bash
# This will delete all persistent data
docker-compose down -v
```

For regular shutdowns without data loss, use:

```bash
# This preserves your data
docker-compose down
```
