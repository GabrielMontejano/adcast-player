# Architecture

## Goal

AdCast Player is designed to keep advertising playback running even when remote updates fail. The update system is secondary to the playback guarantee: a known-good local video must remain available at all times.

## High-Level Flow

```text
Admin browser
  -> authenticated backend panel
  -> publish MP4
  -> backend creates manifest with size and SHA-256
  -> devices poll manifest
  -> devices download and validate media
  -> devices atomically switch to the new video
  -> devices confirm playback through status/heartbeat
```

## Backend

The backend is a Node.js service with a server-rendered admin panel.

Core responsibilities:

- admin authentication;
- device authentication;
- upload validation;
- manifest publication;
- video download;
- heartbeat and status collection;
- remote health-check command queue;
- event history for operations and troubleshooting.

The current backend does not use a SQL database. It stores state and uploaded videos on a mounted persistent disk.

## Device Update Strategy

The device app follows a conservative update model:

```text
current video remains active
new video downloads to a temporary file
temporary file is validated by size and SHA-256
validated file is installed as the active video
playback is confirmed
old version is kept as rollback fallback
```

If anything fails before playback confirmation, the previous video remains or is restored.

## Failure Handling

Expected behavior during failures:

- backend offline: device keeps playing the current local video;
- internet drops during download: current video keeps playing;
- invalid file/hash/size: update is rejected;
- app/device restarts during update: local files are reconciled before playback;
- new video fails to play: rollback restores the previous known-good video.

## Multi-Device Operation

Each device reports a `device_id`. The panel groups status by device so one backend can monitor multiple stores or display locations.

Important status fields:

- online/offline based on recent heartbeat;
- installed version;
- playback state;
- playback position;
- update state;
- last error;
- last health-check result.

## Security Model

The public backend assumes:

- the admin panel is protected by Basic Auth;
- device requests require `X-Device-Token`;
- secrets are configured only through environment variables;
- tokens are never sent in query strings;
- uploads are size-limited and restricted to MP4;
- suspicious request patterns are rejected before route handlers;
- device networks do not need inbound access.

Provisioning details and build artifacts are intentionally outside the public repository.
