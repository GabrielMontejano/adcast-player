# Render Deploy

## Recommended Topology

Use Render as the public backend:

```text
Admin browser -> Render
Devices -> Render
```

Devices never receive inbound connections. They only poll the backend, download media, and send status.

## Storage

The backend stores state and uploaded videos on disk. Render's default filesystem is ephemeral, so use a Persistent Disk mounted at:

```text
/var/data
```

The included `render.yaml` uses:

```text
STORAGE_DIR=/var/data
```

## Environment Variables

Configure these values in Render:

```text
ADMIN_USER=admin
ADMIN_PASSWORD=<set-in-render>
DEVICE_TOKEN=<set-in-render>
PUBLIC_BASE_URL=https://your-service.onrender.com
STORAGE_DIR=/var/data
MAX_UPLOAD_BYTES=1073741824
AUTH_WINDOW_MS=600000
ADMIN_MAX_AUTH_FAILURES=10
DEVICE_MAX_AUTH_FAILURES=30
ADMIN_RATE_LIMIT=120
DEVICE_RATE_LIMIT=600
```

## Backend Protections

The backend applies:

```text
admin Basic Auth
required device token
temporary lock after repeated wrong credentials/tokens
IP-based rate limit
small JSON payload limit
upload size limit
single-file upload
.mp4-only upload validation
basic security headers
suspicious URL/query/JSON pattern blocking
```

There is no SQL database in the current backend. Obvious SQL injection and path traversal patterns are still blocked before route handlers.

## Deploy

1. Push this project to GitHub.
2. No Render, crie um Web Service apontando para o repo.
3. Root directory:

```text
server
```

4. Build command:

```text
npm install
```

5. Start command:

```text
npm start
```

6. Health check path:

```text
/healthz
```

7. Adicione Persistent Disk:

```text
Mount path: /var/data
Size: 10 GB ou mais
```

## Device Provisioning

Device provisioning is handled through an internal operational process using the public Render URL and the configured device token.

## Internet Test Checklist

1. Device on another network polls the backend.
2. Heartbeat aparece online.
3. `VERIFICAR AGORA` returns a health check result.
4. Publish a new version.
5. Download conclui.
6. Playback is confirmed.
7. Disconnect device internet during download.
8. Previous video keeps playing.
9. Internet returns.
10. Updater recovers.
