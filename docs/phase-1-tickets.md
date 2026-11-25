# Phase 1 — Read surface + static (ticket breakdown)

**Goal:** the Python server serves flamejob's **read-only HTTP surface + the dashboard**, behind the existing Caddy, with its JSON responses **diffed against the Rust server on live traffic** — reaching **Milestone M1 (read-shadow deploy)** at zero risk. Rust still owns every write, the scheduler, the agent WebSocket, and the live-gauge/event paths.

**Baseline:** builds on the Phase-0 foundation (`flamejob_core`, `flamejob_api`, `flamejob_server.{config,crypto,auth}`, `flamejob_db`). Estimate from the plan: **~1.5 engineer-weeks.**

**Pulls in the `server` extra:** `fastapi`, `uvicorn[standard]`, `prometheus-client`.

---

## The M1 routing split (what Python serves vs. what stays on Rust)

The strangler routes **per endpoint** at Caddy. Phase 1 moves only side-effect-free reads that Python can answer **from the database alone**.

**Python serves in M1 (DB-only reads):**
`GET /healthz` · `GET /auth/me` · `GET /auth/api-keys` · `GET /jobs` · `GET /jobs/history` · `GET /jobs/:id` · `GET /jobs/:id/tasks` · `GET /hashlists` · `GET /hashlists/:id/cracked` · `GET /files` · `GET /files/usage` · `GET /devices` · `GET /devices/:name/history` · `GET /openapi.json` · `GET /docs` · the **dashboard** page.

**Stays on Rust through M1 (needs live in-process state the scheduler/AgentHub owns, or is a write):**
`POST /auth/login` (write) · `GET /agents` (live online/busy status from the hub) · `GET /metrics` (connected-agent + running-task gauges) · `GET /events` (SSE fed by the scheduler's event bus) · `GET /agent/files/:id` (the file side-channel → served by the **proxy**, never Python — plan §5) · `/agent/stream` (WS) · all writes, `/admin/*`, `/api/directory/*`.

`/agents`, `/metrics`, and `/events` move to Python in **Phase 2**, when the scheduler + AgentHub exist to feed them.

---

## Tickets

Dependencies in brackets. Sizes are rough (S ≤ ½ day, M ≈ 1 day, L ≈ 2 days).

### P1-01 · FastAPI app skeleton + lifespan + CORS — **M**
Create `flamejob_server/app.py`: the `FastAPI()` app, uvicorn entrypoint, a `lifespan` that opens/closes the asyncpg pool (`flamejob_db.create_pool` from `Config.database`), CORS from `web.allowed_origins` (empty = allow any, as Rust), and `GET /healthz`. OpenAPI `version` = package version. **Exit:** `uvicorn flamejob_server.app:app` boots, `/healthz` 200, `/openapi.json` + `/docs` render. *(needs Phase 0 config/db)*

### P1-02 · Auth dependency (`AuthUser`) — **L** [P1-01]
Port `auth.rs::FromRequestParts` to a FastAPI dependency: parse `Authorization: Bearer`; `fj_`-prefixed → API-key path (`api_key_hash` → `SELECT … api_keys JOIN users` with `NOT revoked / NOT disabled / expiry`, then live `user_roles` load); otherwise `decode_token` (HS256 pinned). Provide `require(cap)` / `require_any(caps)` dependency factories. The API-key `last_used_at` stamp is a write — put it behind a `read_shadow` config flag so M1 can run strictly side-effect-free. **Exit:** a Rust-issued JWT and a real `fj_` key both authenticate; capability gates return 403 with the Problem body. *(the JWT/key formats are already interop-proven in Phase 0)*

### P1-03 · Error model → RFC 7807 — **M** [P1-01]
Exception handlers mapping to `flamejob_api.schemas.Problem`: 401 Unauthorized, 403 Forbidden, 404, 429 TooManyRequests, 507 InsufficientStorage, 500 Internal. **Fix FJ-015**: never surface asyncpg/driver text to clients — log server-side with a correlation id, return a generic 500 detail. **Exit:** parity with `error.rs::parts()` on status + `type`/`title`; no DB internals leak.

### P1-04 · Read query layer — **L** [P1-01]
`flamejob_server/queries.py` (or per-domain modules): the parameterized asyncpg reads behind the Phase-1 handlers (jobs incl. the `JOB_SELECT` shape with `COALESCE(priority_override, priority)` ordering, tasks, hashlists, cracked, files, storage usage, devices, device history). **Parameterized only — `$n`, no f-string SQL** (§6). **Exit:** each query returns rows mapping cleanly onto the Phase-0 DTOs; unit-tested against the seeded Postgres.

### P1-05 · Jobs read endpoints — **M** [P1-02,03,04]
`GET /jobs`, `/jobs/:id`, `/jobs/history`, `/jobs/:id/tasks` (`ViewJobs`). Response models `JobView` / `JobHistoryView` / `TaskView`, ordered by effective priority. **Exit:** shapes diff-clean vs Rust (P1-14) on the seed corpus.

### P1-06 · Hashlists + cracked read — **M** [P1-02,03,04]
`GET /hashlists`, `GET /hashlists/:id/cracked` (`ViewPlaintext`). Decrypt `hashes.plain` via `crypto.Cipher` (`key_from_config`) — the Phase-0 interop proof guarantees Rust-written records decrypt. **Carry a flag for FJ-007** (object-level authz) as a Phase-2 follow-up; keep the capability gate now. **Exit:** cracked plaintext decrypts and matches Rust output byte-for-byte.

### P1-07 · Files read — **S** [P1-02,03,04]
`GET /files` (list) + `GET /files/usage` (`StorageUsageView`: sum of file sizes, count, quota, and volume capacity/free via `os.statvfs` on `data_dir/files`). **Exit:** `files_bytes`/`quota_bytes`/disk figures match Rust.

### P1-08 · Devices / telemetry read — **M** [P1-02,03,04]
`GET /devices` (latest `current_devices` → `DeviceView`), `GET /devices/:name/history` (`metric_samples`, capped at `telemetry.history_limit` → `DeviceSample`). Read-only; the 5 s collector itself is Phase 2/4. **Exit:** device list + history shapes diff-clean.

### P1-09 · `/auth/me` + API-key list — **S** [P1-02]
`GET /auth/me` (`MeResponse`) and `GET /auth/api-keys` (`ApiKeyView`, never the secret). **Exit:** both return the caller's data under a Rust-issued token.

### P1-10 · Dashboard serving — **M** [P1-01]
Serve `dashboard.html` **copied verbatim** with the `"__FJCFG__"` placeholder replaced by the config blob (`apiBase` from `web.api_base`, `theme`, `version`), on the dashboard listener with CORS; `/healthz` there too. Keep the page's `esc()` escaping untouched. **Exit:** all six themes render from Python; browser console clean; points at the (Rust-owned) API.

### P1-11 · Capabilities endpoint (kills the `ROLE_CAPS` mirror) — **S** [P1-02]
`GET /auth/capabilities` → the role→capability map from `flamejob_core` so the dashboard derives `ROLE_CAPS` from one source instead of hand-mirroring `model.rs` (plan §7). **Exit:** endpoint returns the map; follow-up dashboard task consumes it.

### P1-12 · Response-diff harness (the M1 gate) — **L** [P1-05..09]
A tool/test that, given a token, calls each Phase-1 read endpoint on **both** Rust and Python against the same database and diffs the JSON (normalising known-volatile fields). Runnable on a captured request corpus. **Exit:** zero semantic diffs on the corpus — the gate for flipping Caddy.

### P1-13 · Caddy M1 routing config — **S** [P1-12]
A `Caddyfile` fragment implementing the routing split above (Python for the DB-only reads, Rust for the rest, proxy for `/agent/files/:id`). Documented rollback = remove the Python matchers. **Exit:** reviewed config + a dry-run against staging.

### P1-14 · Integration tests on shared Postgres — **M** [P1-05..09]
Seed fixtures (jobs/tasks/hashlists/cracked/files/devices/users/api-keys) into the CI Postgres; assert every Phase-1 endpoint's shape + a cracked-decrypt case. Wire into the existing CI `test` job. **Exit:** green in CI.

### P1-15 · File side-channel decision (plan §5) — **S**
Record and configure that `GET /agent/files/:id` is served by **Caddy/nginx** directly (sendfile / `X-Accel-Redirect`), with an auth subrequest, so the ≥10 GbE burst never touches Python. Phase 1 sets the architecture; the agent path lands in Phase 4. **Exit:** decision doc + Caddy stanza stub.

---

## Phase 1 exit criteria (→ M1)

1. All Python-served endpoints above return **diff-clean** JSON vs Rust on the corpus (P1-12).
2. Dashboard renders fully from Python (all six themes), API calls still hit Rust.
3. `ruff` + `mypy --strict` + `pytest` (incl. the new integration tests) green in CI.
4. Caddy routing reviewed; rollback is a one-line revert.
5. Deploy: Python live behind Caddy serving the read set; monitor the diff + error rate over a soak window. **M1 reached.**

## Explicitly out of scope for Phase 1 (and where it lands)
Writes / `create_job` / state changes → **P2**. `/agents` live status, `/metrics` live gauges, `/events` SSE → **P2** (need the scheduler/AgentHub). Login provider chain → **P2/P3**. Directory reads → **P3**. Agent `/agent/files/:id` serving → **P4** (proxy, per P1-15).
