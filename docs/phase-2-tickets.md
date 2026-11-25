# Phase 2 — Control-plane brain (ticket breakdown)

**Goal:** the Python server gains the stateful core — the **agent WebSocket hub, the scheduler, job writes, preemption, and the live `/agents` + `/metrics` + `/events`** endpoints Phase 1 left on Rust — so it can own the whole control plane. This is the largest, riskiest phase (plan: **4–6 engineer-weeks**) and the one that makes the **M2 atomic cutover** possible (M2 also needs Phase 3 directory + Phase 4 agent).

**Baseline:** stacks on the merged Phase 1 read surface. **Pulls in the `server` extra** already (FastAPI/uvicorn/prometheus-client); adds no new runtime deps except possibly `sse-starlette` for `/events`.

**The governing constraint (plan §3):** the scheduler + AgentHub + telemetry collector are the *singular brain* — exactly one process may run them against a given database. So Phase 2 code can be built and unit/integration-tested freely, but in deployment it only goes live at **M2** (one atomic cutover), never endpoint-by-endpoint like the M1 reads.

**Out of scope (later phases):** directory/LDAP login + pool grants → **Phase 3**; the agent binary itself (pynvml, hashcat exec, Windows service) → **Phase 4**; TUI → **Phase 6**. Phase 2 builds the *server* side of the agent protocol and tests it with a **mock agent**.

---

## Sub-phase map (suggested PR boundaries)

| Sub-phase | Theme | Rough size |
|---|---|---|
| **2a** | Agent WS hub + enrollment/PKI + mock agent harness | L (1–1.5 wk) |
| **2b** | Scheduler core (fill_fleet / claim_and_start / keyspace planning) + fairness + pools | L (1.5–2 wk) |
| **2c** | Job writes (create/patch/state) + hashlists/files writes + user/api-key admin | M–L (1 wk) |
| **2d** | Preemption + priority override + keyspace handoff | M (0.5–1 wk) |
| **2e** | Live endpoints: `/agents`, `/metrics`, `/events`, hub-fed `running_agents`; login; settings; bootstrap; audit | M (1 wk) |
| **2f** | Test port + mock-agent integration + security hardening + load check | M (0.5–1 wk) |

Dependencies: **2a → 2b** (scheduler dispatches through the hub) → **2d** (preemption drives the hub/scheduler). **2c** needs 2b (create_job plans keyspace + eligibility). **2e** needs 2a+2b (live status/metrics/events come from hub+scheduler). **2f** spans all.

---

## 2a — Agent WebSocket hub + enrollment/PKI

### P2-01 · AgentHub state + connection lifecycle — **L**
Port `agent.rs`'s AgentHub to an asyncio design: a single hub object holding the connected-agent registry (agent_id → send queue, slots, os, last_seen, live device snapshot). `WS /agent/stream`: accept, read first frame `Hello{name,cert_pem,os}`, authenticate by `SHA-256(cert_pem)` == a non-revoked `agents.fingerprint`, reply `Welcome{agent_id}` (or `Rejected`). Per-connection reader task + writer drained from an `asyncio.Queue`. **Replace tokio `broadcast`/`watch`/`mpsc`** with per-subscriber `asyncio.Queue`s / `asyncio.Event`. **Exit:** a mock agent connects, authenticates by fingerprint, appears in the hub registry; a bad fingerprint is rejected.

### P2-02 · Inbound frame handling (telemetry/results) — **M** [P2-01]
Handle A→S frames: `Ready{slots}` (update capacity), `Progress` (update task progress/speed/EMA ETA), `Metrics{samples}` → upsert `current_devices` + insert `metric_samples` (this is the 5 s collector write path — the dominant DB churn), `Cracked{items}` → `import_cracked` (encrypt each plain via `Cipher`, insert into `hashes`, bump `hashlists.cracked`), `TaskDone{task_id,state}`, `AgentError`. **Exit:** mock-agent telemetry lands in `current_devices`/`metric_samples`; a `Cracked` frame writes an encrypted row that the Phase-1 `/cracked` endpoint decrypts.

### P2-03 · Enrollment + CA/PKI — **M**
Port `pki.rs` + the enrollment HTTP endpoints to `cryptography`: self-signed CA (persisted, **key file `0600`** — FJ-020), claim-token issue, `POST /agent/enroll` `{claim_token,name,csr_pem}` → **constrained** CSR signing (fixed subject, `CA:false`, bounded validity — FJ-017, don't sign arbitrary SANs/basicConstraints) → `{agent_id,cert_pem,ca_pem}`, store `agents.fingerprint` (UNIQUE). **Exit:** claim → enroll → the issued cert's fingerprint authenticates on `/agent/stream`.

### P2-04 · File download side-channel endpoint — **S** [P2-03]
`GET /agent/files/{id}` authenticated by `x-agent-cert` fingerprint. Per plan §5 the **bytes are served by Caddy** (sendfile); Python provides a `forward_auth` subrequest (validate fingerprint → 200/403) and the file metadata/path. Implement the auth endpoint + a direct-stream fallback for non-proxied dev. **Exit:** a valid agent cert authorizes a download; an unknown cert 403s; large files never buffer in Python.

### P2-05 · Mock-agent test harness — **M** [P2-01,02]
A reusable async mock agent (connects, enrolls, answers `ComputeKeyspace`, accepts `Assign`, streams `Progress`/`Metrics`, emits `Cracked`, honours `Cancel`/`Preempt`). This is the backbone for every scheduler/preemption integration test. **Exit:** harness drives a full dispatch→progress→done cycle against the hub in-process.

---

## 2b — Scheduler core

### P2-06 · Fairness selector (pure) — **S**
Port `fairness.rs::select_job` (weighted max-min over in-flight slots: ceil-skip / floor-first / smallest `in_flight÷weight` / oldest-wait tiebreak / within-group fewest-in-flight) + the **6 fairness unit tests** verbatim. Single-ungrouped-tenant ⇒ prior behaviour. **Exit:** 6 ported tests green.

### P2-07 · Pool eligibility (pure + wiring) — **S**
Port `pools.rs::compute_eligibility` + `summarize_grants` + the **3 tests**. In Phase 2, the directory-grant inputs are empty (local/no-pool ⇒ unrestricted, the BC path); the directory-restricted branch is exercised in Phase 3. **Carry FJ-011** (don't default *local* accounts to the whole fleet — require an explicit unrestricted flag) as a flagged decision. **Exit:** 3 ported tests green; local submit is unrestricted.

### P2-08 · Keyspace planning + chunking — **M** [P2-05]
Port the `create_job` keyspace step: compute total keyspace (via an agent `ComputeKeyspace` probe — **restricted to the job's eligible agents and with `extra_args` stripped**, FJ-012), slice into chunks by `scheduler.chunk_size` / `max_chunks`, create `tasks` rows with `keyspace_offset`/`keyspace_len`. **Exit:** submitting a job produces the expected task rows for a known keyspace.

### P2-09 · fill_fleet + claim_and_start (the loop) — **L** [P2-06,07,08]
Port `scheduler.rs`: the per-free-slot loop that re-derives eligible agents, calls `select_job` (fairness), claims a task (`claim_and_start`, effective priority = `COALESCE(priority_override,priority)`), and dispatches `Assign{task}` through the hub to an allowed agent; advances `keyspace_offset` on progress; transitions job/task state on done/exhausted/error. Runs as a single asyncio task (the singular brain). **Exit:** with the mock agent, a queued job is assigned, runs, and completes; `tasks`/`jobs` states match the Rust state machine (`JobState.can_transition`).

---

## 2c — Job & resource writes

### P2-10 · create_job (submit) — **M** [P2-08]
`POST /jobs` (`SubmitJobs`): compute eligibility (P2-07) → **403** if no authorized agents; **429** (`max_submit_jobs`) backpressure; **FJ-004** — replace raw `extra_args` with a **server-validated allowlist** (reject output/restore/potfile/debug/path flags), validate `mask`. Audit the mutation. **Exit:** submit creates the job + plans keyspace; disallowed `extra_args` rejected; backpressure returns 429.

### P2-11 · Job mutations — **M** [P2-09]
`POST /jobs/{id}/state` (pause/resume/cancel via the state machine), `PATCH /jobs/{id}`, `clear_finished_jobs` (writes `job_history` at clear time). **FJ-007** — object-level authz: scope to `owner_user_id`/`owner_group_sid` unless the caller holds a cross-tenant capability. Audit. **Exit:** state transitions honour `can_transition`; a non-owner without cross-tenant cap can't mutate another tenant's job.

### P2-12 · Hashlists + file ingest writes — **M**
`POST /hashlists` + `import_hashes` (encrypt-at-rest where applicable), `POST /files` (streamed to disk under a **server-generated UUID** name — no path traversal; **8 GiB** per-request cap; **507** over `files_quota_bytes`), `DELETE /files/{id}`. **Exit:** upload streams to disk (no RAM buffering), over-quota 507s, UUID naming verified.

### P2-13 · User + API-key admin writes — **S**
`POST /admin/users` with **FJ-005** fix (forbid granting a role ≥ caller's; superadmin-only for superadmin), API-key create/revoke, **and audit every user/role mutation** (currently unaudited in Rust). **Exit:** an Admin cannot mint a superadmin/operator; all mutations audited.

---

## 2d — Preemption

### P2-14 · Preempt primitives (pure) — **S**
Port `preempt.rs::{remaining_window, is_preemptible}` + the **2 tests** (MIN_RUN_SECS=60, SHIELD_FRAC=0.90; split a chunk at its last-progress offset). **Exit:** 2 ported tests green.

### P2-15 · Preempt/priority handlers + resume — **M** [P2-09,14]
`POST /jobs/{id}/priority` (set/clear `priority_override`) and `POST /jobs/{id}/preempt` (`mode=requeue|cancel`, `target_pool_id?`, `reason`, `force?`) — **new `ManageScheduling` cap, every action audited**. `scheduler.resume_preempted_jobs()`: once a requeued chunk stops, split at its durable offset and re-dispatch the remainder (optionally to a retarget pool) via `--skip`/`--limit`, rebuilding inputs without re-planning. **Exit:** with the mock agent, preempt→requeue pauses in-flight, then resumes the remainder from the offset (not from zero).

---

## 2e — Live endpoints, login, settings, bootstrap, audit

### P2-16 · `/agents` (live) + hub-fed `running_agents` — **S** [P2-01]
`GET /agents` with live online/draining/offline status from the hub (not just DB), and fill `JobView.running_agents` for **remote mode** from the hub — removing the Phase-1 divergence the diff harness normalised. **Exit:** `/agents` reflects live connections; remote-mode `running_agents` now matches reality (diff-harness normalisation for that field can be dropped).

### P2-17 · `/metrics` (live gauges) — **S** [P2-01,09]
Prometheus via `prometheus_client`: job counts by state (DB), connected-agent count + running-task count (hub/scheduler), `flamejob_build_info`. **FJ-016** — put it behind a scrape token or a separate bind. **Exit:** scrape returns the live gauges matching Rust's.

### P2-18 · `/events` SSE bus — **M** [P2-02,09]
An in-process event bus (per-subscriber `asyncio.Queue`) the hub + scheduler publish to (`JobUpdated`/`TaskUpdated`/`HashCracked`); `GET /events` as SSE (likely `sse-starlette`). **Exit:** a client sees job/task/crack events live while the mock agent runs a job.

### P2-19 · Local login + rate limit — **M**
`POST /auth/login` local/break-glass branch only (Argon2 verify → issue HS256 JWT). **FJ-009** — per-account + per-IP rate limiting with backoff; constant-work path for unknown users. (The directory branch of the provider chain is **Phase 3**.) **Exit:** local login issues a working token; brute-force is throttled.

### P2-20 · Settings (runtime TLS) — **M**
Port `settings.rs`: `site_settings` singleton (`ManageSettings`), key encrypted via `Cipher`. **Nuance:** the Rust live `:443` listener rebind maps awkwardly onto uvicorn — recommend terminating TLS at Caddy (plan §5) and having this endpoint manage cert *material* + signal intent, rather than hot-rebinding a socket in-process. Flag the decision; implement config read/write + cert storage now. **Exit:** settings round-trip; cert material stored encrypted; the listener-rebind approach is decided, not hacked.

### P2-21 · Bootstrap + audit sink — **S**
Port `bootstrap.rs` first-run superadmin creation with **FJ-014** fix (emit the one-time password to stdout once, never through the structured logger) + change-on-first-login. Centralise the `audit_events` writer used across 2c/2d. **Exit:** first run provisions a superadmin without logging the credential; privileged mutations land in `audit_events`.

---

## 2f — Tests, hardening, load

### P2-22 · Port remaining server unit tests — **S**
Bring the rest of the 32 server + 4 runner pure-logic tests across to pytest (fairness/pools/preempt already in 2a–2d; the scheduler/eligibility/state ones here). **Exit:** the Phase-2-relevant subset of the 60 Rust tests is green in CI.

### P2-23 · Mock-agent integration suite — **M** [all]
End-to-end against a live Postgres + the mock agent: submit → keyspace probe → assign → progress → cracked (decrypt) → done; preempt→requeue→resume-from-offset; fair-share across two groups; pool restriction. **Exit:** the suite green in CI (closes the "no scheduler e2e" gap from the Rust side).

### P2-24 · Security + concurrency hardening — **S** [all]
§6 checklist pass for the new write/exec surface: parameterized SQL (re-audit the new dynamic sites), direct-`argv` for any probe exec (never `shell=True`), FJ-004/005/007/012 landed, audit coverage. **Concurrency/GIL (plan risk #2):** run Argon2 (login) and AES (cracked-result floods) off the event loop (thread pool / GIL-releasing libs), and load-test the hub at a representative fleet size before M2. **Exit:** checklist signed off; a fan-out load test shows the event loop isn't starved.

---

## Phase 2 exit criteria (→ ready for M2)
1. The Python server runs the **scheduler + agent hub** against a Postgres and drives the **mock agent** through dispatch, preemption/resume, fair-share, and pool restriction (P2-23).
2. All write endpoints enforced + audited; `/agents`, `/metrics`, `/events` live and matching Rust.
3. §6 security checklist green for the new surface; fan-out load test passes.
4. `ruff` + `mypy --strict` + `pytest` (incl. live-PG integration) green in CI.
5. **M2 is then gated only on Phase 3 (directory login parity) + Phase 4 (real agent)** — at which point the atomic cutover can run.

## Risks specific to Phase 2 (from the plan's register)
- **Scheduler/hub concurrency redesign** is the top risk — the tokio actor/channel model → asyncio tasks/queues is a *redesign*, not a translation. Mitigation: the mock-agent integration suite (P2-23) + the singular-brain rule + shadow M1 already proving the read/DB/auth stack.
- **GIL under CPU bursts** (Argon2/AES/fan-out JSON) — mitigate per P2-24 before M2.
- **`running_agents`/live status** depended on the hub — now resolved here (P2-16), so the diff harness can drop that normalisation.
