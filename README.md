# flamejob (Python 3.10+ port)

Python relanguaging of [`nc-intezra/flamejob`](https://github.com/nc-intezra/flamejob)
(Rust, v2.2.0) — a distributed hashcat job queue. Driven by the supporting
team's Python fluency; the goal is long-term maintainability.

**Planning docs** (in the Claude project): `flamejob-python-port-feasibility.md`
(can/should we) and `flamejob-python-port-plan.md` (the phased execution plan).
This repo is **Phase 0: foundations + the format-interop proofs** that underwrite
the strangler migration.

## What's here (Phase 0)

| Package | Status | Ported from |
|---|---|---|
| `flamejob_core` | ✅ model, RBAC, state machines, runner types | `flamejob-core` |
| `flamejob_api` | ✅ Pydantic DTOs + agent WS protocol | `flamejob-api` |
| `flamejob_server` | ✅ `config`, `crypto`, `auth` (rest: Phases 1–3) | `flamejob-server` |
| `flamejob_db` | ✅ asyncpg pool + sqlx-ledger-aware migration runner | `flamejob-db` |
| `flamejob_runner` / `_agent` / `_client` / `_cli` / `_tui` | 🔜 stubs | Phases 4–6 |

`migrations/` holds the 12 shipped `.sql` files **byte-for-byte** from the Rust
repo (immutable once shipped).

## The interop proofs (why Phase 0 exists)

Because JWT (HS256), Argon2id (PHC), and AES-256-GCM (`nonce‖ct`) are standard
formats, the Python server can run against the **same Postgres** and the same
token/credential population as the Rust server during the migration. `tests/`
proves it **both directions**:

- **Rust → Python**: a real Rust-minted JWT verifies, Rust-written AES records
  decrypt (both the `SHA-256(jwt_secret)` and explicit-key paths), a Rust
  Argon2id hash verifies, and `api_key_hash` matches — all against artifacts
  emitted by the **real Rust crates** (pinned versions) in
  `interop/rust-fixture/`.
- **Python → Rust**: Python-produced JWT / Argon2 / AES artifacts are piped back
  through the compiled Rust `verify` binary and must be accepted.

## Run it

```bash
uv venv --python 3.10 && source .venv/bin/activate
uv pip install -e '.[dev]'

# Generate the Rust interop fixtures (needs cargo) and enable the Python→Rust test
( cd interop/rust-fixture && cargo build --release && ./target/release/gen-fixtures > ../fixtures/rust_fixtures.json )
export FLAMEJOB_RUST_BIN="$PWD/interop/rust-fixture/target/release/gen-fixtures"

ruff check src tests
mypy
pytest -q                     # the Postgres migration test runs when FLAMEJOB_TEST_DSN is set
```

`FLAMEJOB_TEST_DSN=postgres://user:pass@host/db pytest -q` exercises the
migration runner against a real database (CI wires a Postgres service).

## Config

`flamejob_server.config.Config` mirrors the Rust figment layering: defaults →
TOML (`FLAMEJOB_CONFIG`, default `/etc/flamejob/flamejob.toml`) → `FJ_` env with
`__` nesting (env wins). An existing `flamejob.toml` / `FJ_*` environment loads
unchanged.

## Security notes carried from day one

- JWT stays **HS256 + shared secret** through the M2 cutover (interop); the
  algorithm is pinned on decode. Phase 7 swaps to EdDSA + token-epoch revocation.
- AES key separation (FJ-003): a dedicated key file is the real path; the
  `SHA-256(jwt_secret)` derivation is kept only for dev/interop.
- `extra_args` is carried on the wire for compatibility but must pass through a
  server-validated allowlist in Phase 2 (FJ-004) — never raw to hashcat.
