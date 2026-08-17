# AdCast Player

Remote advertising player platform for Android TV, Smart TVs, and digital displays.

The public repository contains the backend, admin panel, Render deployment blueprint, and operational documentation. Device provisioning and private build artifacts are intentionally kept outside the repository.

## Estrutura

```text
adcast-player/
|-- server/         Node.js backend and admin panel
|-- docs/           architecture, recovery, test and deploy notes
|-- render.yaml     Render deployment blueprint
`-- README.md
```

## Backend

The backend is prepared for Render and must not contain secrets in the repository. Configure secrets only in the Render dashboard:

```text
ADMIN_USER
ADMIN_PASSWORD
DEVICE_TOKEN
PUBLIC_BASE_URL
STORAGE_DIR
MAX_UPLOAD_BYTES
AUTH_WINDOW_MS
ADMIN_MAX_AUTH_FAILURES
DEVICE_MAX_AUTH_FAILURES
ADMIN_RATE_LIMIT
DEVICE_RATE_LIMIT
```

Deployment guide:

```text
docs/RENDER_DEPLOY.md
```

## Security

- Admin panel protected by Basic Auth.
- Devices authenticated with `X-Device-Token`.
- Device token is never sent through query strings.
- Uploads are limited by size and `.mp4` type.
- Rate limit per IP.
- Temporary lock after repeated wrong credentials/tokens.
- No SQL database in the current backend.
- No hardcoded secrets in the repository.

## Device App

The device app is provisioned through an internal operational process before production use. APKs, Android source, signing keys, local test videos, and local deployment scripts are not part of this public repository.

## Operational Model

```text
Admin browser -> Render backend -> Devices poll backend
```

Devices do not receive inbound connections. They poll for updates, download validated media, report heartbeat/status, and keep the previous video available if an update fails.
