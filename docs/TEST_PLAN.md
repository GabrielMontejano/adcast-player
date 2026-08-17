# Test Plan

## Minimum Acceptance Criteria

- 20 consecutive successful updates on a real test device.
- 24 hours of continuous playback.
- No black screen during update failures.
- Previous video survives failed updates.
- Remote health check confirms playback and position.
- No abnormal memory growth during long playback.

## Required Tests

### Normal Update

Expected:

```text
download -> validation -> install -> playback confirmation -> SUCCESS
```

### Network Drop During Download

Expected:

```text
previous video keeps playing
temporary download is not promoted
device recovers when network returns
```

### Backend Offline

Expected:

```text
device keeps playing local video
update attempts fail without interrupting playback
device resumes polling when backend returns
```

### Invalid File

Expected:

```text
upload/download is rejected or validation fails
active video is preserved
```

### Wrong Checksum Or Size

Expected:

```text
temporary file is rejected
player is not restarted
previous video remains active
```

### Power Loss During Download

Expected:

```text
device starts with previous video
incomplete temporary file is ignored or removed
```

### Power Loss During Install

Expected:

```text
startup recovery reconciles files
a valid video is restored before playback
```

### New Video Fails Playback

Expected:

```text
playback timeout triggers rollback
previous known-good video is restored
status reports failure
```

### Remote Health Check

Expected:

```text
admin requests health check
device responds through heartbeat/status
panel shows playback=yes and current position
```

### Multi-Device Monitoring

Expected:

```text
each device appears separately
online/offline state is independent
events include the correct device_id
```
