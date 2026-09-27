# withings-mcp

First-party Rust (`axum` + `rmcp`) streamable-HTTP MCP server for the official
Withings API. Do not wrap, vendor, or depend on third-party Withings MCP
servers or Withings client crates. Keep the client in `src/withings_client.rs`
thin and first-party.

**This repository is public.** No measurement values, no Withings user ids, no
credentials, no internal hostnames, no cluster paths — not in source, not in
tests, not in fixtures, not in issues. The fixtures here are invented numbers
and say so.

## Session protocol

1. Run `git status` when this directory is a Git worktree.
2. Report the current branch, next task, and failing tests.

Anything with a state goes in a Forgejo issue, not a file. There is no
`Plan.md` here and there should not be one.

## Read-only, and the annotation is load-bearing

Every tool carries `read_only_hint = true` and there is no tool that writes to
Withings. `bin/tool-scope.sh` generates an agent's deny list from those
annotations, so a hint that says `false` **silently widens an agent** rather
than merely mislabelling a tool. `every_tool_is_annotated_read_only_and_none_writes`
in `src/main.rs` drives `tools/list` over the real transport and asserts both
halves; adding a tool without the annotation reds it.

## Public auth contract

- Self-host. The origin is deployment configuration and is not in this
  repository.
- MCP: `https://<origin>/mcp`.
- Connector auth is `Authorization: Bearer <WITHINGS_MCP_AUTH_TOKEN>`, a value
  the deployment configures. It is **not** forwarded anywhere: unlike a
  passthrough server, the Withings credential belongs to the server.
- Bearer only. Do not serve RFC 9728 metadata.
- Unauthenticated `/mcp` returns `401` with no `WWW-Authenticate` header.
- `/.well-known/oauth-*` and `openid-configuration` return `404` with no
  `WWW-Authenticate`.
- Never log the inbound bearer, the client secret, or either Withings token.
- The public origin comes from `WITHINGS_MCP_ALLOWED_HOSTS`. It is not a
  default in `src/` and it does not go into this file or the README either.

## Withings backend

- Default base URL: `https://wbsapi.withings.net`; override only through
  `WITHINGS_MCP_API_BASE_URL`.
- Scope is `user.metrics` and the catalogue is four meastypes: 1 weight,
  6 body fat percentage, 8 fat mass, 76 muscle mass.
- `requesttoken` takes `client_secret` directly. There is no nonce/signature
  step on this flow.
- Use rustls-only reqwest.

## Verification

After every change run:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo audit
cargo deny check bans licenses sources
```

Read the exit code without a pipe between you and it: `cmd >/tmp/out 2>&1; rc=$?`.
`cargo test … | tail` reports `tail`'s status.

Required regression coverage:

- unauthenticated `/health` returns 200;
- unauthenticated `/mcp` returns 401 with no `WWW-Authenticate`;
- a *wrong* bearer returns 401, including a prefix of the right one;
- OAuth/OIDC well-known probes return 404 with no `WWW-Authenticate`;
- the first tool call refreshes and only then reads;
- a rate limit never arrives as an empty read;
- `/oauth/callback` is off without a configured `state` and rejects a wrong one
  before exchanging;
- every listed tool is annotated read-only.

## Known pitfalls

- **Withings rotates the refresh token on every refresh, and the failure is
  silent for three hours.** `grant_type=refresh_token` returns a new
  `refresh_token`; the previous one expires 8 hours after the new one is issued
  **or as soon as the new access token is used**, whichever comes first. Read
  from Withings' own guide, two pages carrying identical wording, 2026-08-29:

  | | |
  |---|---|
  | access token | 3 hours |
  | refresh token | 1 year |
  | previous refresh token | 8 hours, or the first use of the new access token |

  So the environment variable is a **seed**, not a credential. A process that
  re-reads it after every restart authenticates exactly once per restart, and
  the symptom is a Withings `status: 401` some hours later with nothing in the
  logs connecting it to the restart. `seed_refresh_token` therefore refuses to
  overwrite a stored value, and a store with nothing in it is an
  `InvalidGrant` rather than a transport error, so the message says
  re-authorisation is needed rather than "internal".

- **Persist the rotated token and read it back before using the new access
  token.** `TokenManager::persist_before_use` is that order and it is not
  cosmetic. Using first and persisting second spends the 8-hour grace
  immediately: the served call succeeds, the old refresh token dies, and if the
  write did not land the only recovery is a person authorising in a browser.
  The two orders are indistinguishable on the happy path.

  `a_refresh_that_cannot_be_persisted_never_yields_an_access_token` pins it
  with two stores. The `FailingStore` half is the easy case. The
  `WriteOnceStore` half is the one that matters: `save` returns `Ok` and keeps
  nothing, which is what a misconfigured destination actually does — no error,
  no log line — and only the read-back catches it. **Deleting the read-back
  reds exactly that test**, measured 2026-08-29: 71 passed, 1 failed.

- **The mutex and the read-back defend the same thing from two sides.** N
  concurrent refreshes rotate N times and persist only the last, leaving the
  store holding a value Withings has already retired — the same silent death as
  no write-back, reachable without a restart. Do not remove either on the
  grounds that the other exists.

- **The store has three mutations. Two are behind the gate and pinned; the
  third happens before the manager exists.** `adopt` and the whole
  refresh-persist-read-back-return sequence take `store_gate`, and removing it
  from either reds `an_adopt_cannot_interleave_with_a_refresh`, measured
  2026-08-29: 72 passed, 1 failed each time.

  The hole a refresh-only gate leaves is not obvious, which is why it survived
  the first version: `/oauth/callback` adopting a new authorisation between a
  refresh's read-back and its return leaves the store holding a token that does
  not match the access token just handed out, so the atomicity
  `persist_before_use` exists to provide is gone while every individual step
  looks correct. Found in cross-engine review of `token.rs` by asking one
  specific question about the new code rather than for a review of it.

  `an_adopt_cannot_interleave_with_a_refresh` pins write **order** rather than
  outcome, which is the right instrument for a race: the refresh is delayed
  300 ms, the adopt is issued 50 ms in, and the recorded order must be seed,
  refresh, adopt.

- **Seeding is a constructor argument rather than a method, and that is the
  fix rather than the style.** It was `pub async fn seed_refresh_token`, taking
  the gate, and **removing that lock reddened nothing** — a peer measured it,
  73 passed, 0 failed. The lock was not load-bearing: what made the race
  unreachable was `main` seeding before the listener bound, an ordering nothing
  asserted and any later edit could move.

  A gate whose necessity rests on an unasserted ordering is a gate a reader
  cannot evaluate. `seed` now runs inside `with_refresh_skew`, against a store
  that has not yet been handed to a `TokenManager`, so nothing can share it and
  there is no ordering to get wrong. **Do not reintroduce a public seeding
  method.**

  A seed never overwrites a stored value: the stored one is newer by
  construction, and preferring the environment hands Withings a token it
  retired at the previous rotation. **Deleting that check reds
  `a_seed_never_overwrites_a_stored_rotation`**, measured 2026-08-29.

- **The gate is per manager, so one `TokenStore` must not be shared by two.**
  Two managers over one store have two mutexes and none of the above holds.
  There is one manager per process and nothing in the type enforces it.

- **Withings answers HTTP 200 for application errors.** The real outcome is in
  the body's `status` field, so a check on the HTTP status alone reports
  success for an expired token. `read_envelope` is the only place either layer
  becomes an error, and `an_expired_token_arrives_as_http_200_and_becomes_unauthorized`
  pins it. An envelope with no numeric `status` is an error rather than an
  empty body, because a parse that silently yields nothing is indistinguishable
  from an account with no measurements.

  Known statuses: `0` ok, `247` bad userid, `250` not authorised, `342` bad
  OAuth signature, `401` invalid token, `503` invalid params, `601` too many
  requests. `401` is separated from `250` because only the first is
  recoverable by refreshing.

- **The two grants answer with different shapes, and only a refresh may
  inherit identity.** Withings' documented `authorization_code` response
  carries `userid` (a JSON **number**) and `scope`; its documented
  `refresh_token` response carries only `access_token`, `refresh_token` and
  `expires_in`. Requiring either field made every successful refresh a
  `withings_invalid_response` with the rotation unpersisted, and every
  fixture used a string `userid`, so the suite stayed green. A refresh now
  carries `userid`/`scope` forward from the stored record, and the read-back
  compares the **whole** record, so a store that keeps the token and loses the
  identity is refused like one that loses the token. A consent is the
  record's origin and fails closed without both, in `exchange_code` and again
  in `adopt`. Making `userid` required again reds six tests, measured
  2026-09-28.

- **A Withings failure names its stage and number.** `mcp::map_withings_error`
  puts `stage` (`refresh` for anything behind `access_token`, `measure` for
  `getmeas`) and `withings_status` / `http_status` into `error.data`, and
  emits one `Withings call failed` warn with only those fields and the code
  string — never the error's `Display`, a body, a token or a userid.
  `whoami` never reaches `measure`, so it failing the same way as a read
  isolates the refresh. A status such as `503` ("invalid params") says
  Withings refused the request, not which input it objected to.

- **A measure is an integer and a base-10 exponent, so an unscaled value is a
  confidently wrong number rather than a missing one.** 70.5 kg arrives as
  `{"value": 70500, "unit": -3}`. Emitting `value` reports a weight of 70,500.
  **Removing the scaling reds four tests** in `measures.rs`, measured
  2026-08-29.

- **Absent is not zero, and a caller cannot tell them apart unless we say
  so.** A type with no reading is left out of `latest_measurements` and named
  in `no_reading_in_window`; an unknown type *name* is an error rather than a
  quiet omission. Returning three series where four were asked for looks
  exactly like a person not having taken the fourth measurement.

- **A rate limit and an empty read must never be the same silence, and one
  function decides.** `audit::class_for_code` is the only place a JSON-RPC code
  becomes a class, and the audit event's `outcome`, its `error_class` field and
  the `data.class` a client sees are all derived from it. Do not add a second
  mapping. `a_rate_limit_never_arrives_as_an_empty_read` in `src/main.rs`
  drives the real transport rather than the constructor: a test that builds the
  error by calling `structured_error` directly pins nothing about the call
  site.

  Do not add a retry. A retry that succeeds hides how often the first read
  fails, and that rate is the measurement worth having.

- **The inbound bearer is compared by digest, in constant time, and a prefix
  must not pass.** `the_expected_token_matches_only_itself` includes
  `"correct"` against `"correct-horse"`. **Replacing the comparison with
  `starts_with` reds that test and
  `a_wrong_bearer_is_rejected_rather_than_forwarded`**, measured 2026-08-29 —
  which is the point of having both, since the unit test alone would let a
  routing change go unnoticed.

- **`/oauth/callback` replaces the server's credential and cannot carry the MCP
  bearer**, because the caller is a browser following a Withings redirect. It
  is off unless `WITHINGS_MCP_OAUTH_STATE` is set and the `state` parameter
  matches it in constant time. Without that guard, anyone who reaches the
  origin points this server at their own Withings account, and every subsequent
  read is of a stranger's body metrics while every signal stays green.

- **`WITHINGS_MCP_ALLOWED_HOSTS` is load-bearing and its default will not serve
  a public deployment.** rmcp validates `Host` against the list and answers
  `403` to anything outside it. The default is `localhost,127.0.0.1,::1` and
  names no origin, so a deployment on a public name that does not set the
  variable rejects every real request with 403 while `/health` keeps answering
  200 — a green pod serving nothing. Both directions are pinned by tests in
  `src/main.rs`, and putting a public host into `DEFAULT_ALLOWED_HOSTS` turns
  two of them red.

  The bearer middleware answers before rmcp's host check, so an unauthenticated
  probe cannot see a host misconfiguration: a `POST /mcp` with no
  `Authorization` is 401 whether the allow-list is right or wrong. The check
  needs the bearer, and `measurement_types` never calls Withings, so it is the
  probe that separates "reachable and authorised" from "reachable".

- **A default nobody tests is a default nobody has checked.** `caldav-mcp`
  passed 120 tests over values its deployment ran on, because every test passed
  the parameter in. Here `the_no_argument_constructor_uses_the_documented_skew`
  and `the_defaults_a_deployment_gets_when_it_sets_nothing` construct through
  the no-argument path on purpose. **Setting `DEFAULT_REFRESH_SKEW` to zero
  reds two tests**, measured 2026-08-29.

- **The tree builds on rustc 1.93 and lints on clippy 1.98, and those are two
  different floors.** `Cargo.toml`'s `rust-version = "1.93"` and the
  digest-pinned `rust:1.93-bookworm` builder make the build floor a gate rather
  than a comment: `cargo +1.93.0 check --all-features --locked` passes, so
  anything reaching past 1.93 fails the release build and not only the lint.

  The lint floor is set by one attribute and it is not removable: the
  `#[allow(clippy::unused_async_trait_impl)]` above `#[tool_handler]` in
  `src/mcp.rs`. The lint fires on methods the macro generates, so there is
  nothing to rewrite, and bumping rmcp is the only thing that could retire it.
  An `#[allow]` naming a lint the running clippy does not have is itself an
  error under `-D warnings`, so that line reds 1.97 and below. That is why
  `ci.yml` names `1.98.0` rather than `stable` or a range. Classify a red
  clippy with `cargo clippy --version` before reading the diff.

- **Exactly one `docker` job may export to `:buildcache`, and it is the `main`
  one.** Merging a pull request and pushing the release tag behind it are two
  pushes seconds apart, so two `docker` jobs run at once, and while both
  exported `mode=max` to the same unqualified ref one lost the blob write.
  `grep -c export-cache .forgejo/workflows/ci.yml` is 1 and should stay 1. Do
  not reach for a job-level `concurrency:` group: Forgejo ignores it in
  silence, so it looks applied and does nothing.

- **A `docker` job skipped because `needs: cargo` failed posts `success` to the
  commit status.** So a green docker beside a red cargo means nothing, and
  reading the status API alone will tell you an image built when none did.
  Confirm a docker job by finding its task on `/actions/tasks`, matching
  `head_branch` as well as `name`, not by reading its tick.

- Forgejo Actions may fail during `Set up job` when a pinned action commit is
  no longer advertised by the action mirror. Verify pinned revisions with
  `git ls-remote` and update to an advertised immutable commit.
- Forgejo Runner does not apply `dtolnay/rust-toolchain`'s default input, so
  `toolchain:` must be given explicitly. Give it an exact version, never
  `stable`.

## What has and has not been measured against Withings

**Nothing in this repository has ever spoken to the live Withings API.** Every
claim about request and response shapes is read from Withings' published
documentation and pinned against a local fixture, so a green suite proves the
code parses the JSON as the documentation describes it and proves nothing about
what Withings actually returns.

The parts that need a live credential to confirm, in the order they become
checkable:

1. `requesttoken` with `grant_type=authorization_code` accepts `client_secret`
   without a nonce and signature.
2. A refresh returns a **different** refresh token, which is the rotation this
   whole design rests on. Seeding writes `expires_at: 0`, so the first tool
   call after a credential lands performs a refresh — this is checkable in one
   call rather than after three hours.
3. `measure?action=getmeas` returns `measuregrps` with the field names and the
   `value`/`unit` encoding assumed in `src/measures.rs`.
4. The meastype numbers 1, 6, 8 and 76 carry the quantities the catalogue says
   they do.

Update this section when one of them is measured, and say which.
