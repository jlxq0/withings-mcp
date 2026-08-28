# withings-mcp

Rust MCP server for Withings body metrics. It uses axum, rmcp streamable HTTP,
and a thin rustls-only client for the official Withings API. It does not use a
third-party Withings MCP server or a Withings client crate.

Read-only. There is no tool that writes to Withings.

Self-host the `/mcp` endpoint on your own domain.

## Authentication

Two credentials, in opposite directions.

**Inbound**, from the caller, is a shared bearer the deployment configures:

```http
Authorization: Bearer <WITHINGS_MCP_AUTH_TOKEN>
```

Missing, malformed or wrong `Authorization` on `/mcp` returns `401` with no
`WWW-Authenticate` header. OAuth and OIDC well-known probes return `404`. The
server refuses to start with no inbound bearer configured rather than serving
open.

**Outbound**, to Withings, is OAuth2. Withings issues no long-lived API key: a
user authorises once with `scope=user.metrics`, and the server holds a refresh
token it exchanges for three-hour access tokens itself. Nothing about the
caller reaches Withings; every request reads one account.

### Refresh tokens rotate

Every `grant_type=refresh_token` call returns a **new** refresh token, and the
previous one expires 8 hours after the new one is issued or as soon as the new
access token is used, whichever comes first.

So `WITHINGS_MCP_REFRESH_TOKEN` is a *seed* rather than a standing credential.
It is used only when the token store holds nothing, because the stored value is
newer by construction, and it is applied while the manager is being built
rather than by a method anything could call later. A deployment that sets no `WITHINGS_MCP_TOKEN_STATE_PATH`
keeps the rotated token in memory, authenticates once per restart, and then
cannot — so it logs a warning at startup saying exactly that.

The refresh path writes the rotated token down and reads it back **before** the
new access token is used for anything. A failed or silently dropped write
aborts the refresh and surfaces an error, which leaves the previous refresh
token alive for its 8 hours; using first and persisting second would trade that
window for none at all, and the two orders look identical while everything
works.

## Getting the first refresh token

An authorisation code lives minutes, so the exchange runs from a terminal and
needs no deployment. It writes no file and reads its three secrets from stdin,
one per line, so none of them reaches a shell history or a process listing.

```sh
# 1. Build the consent URL (client id on stdin).
printf '%s\n' "$CLIENT_ID" \
  | withings-mcp exchange --authorize-url \
      --redirect-uri https://withings-mcp.example/oauth/callback \
      --state "$STATE"

# 2. Open it, approve, and copy `code` out of the browser's address bar.

# 3. Exchange it. The refresh token is the only thing on stdout.
printf '%s\n%s\n%s\n' "$CLIENT_ID" "$CLIENT_SECRET" "$CODE" \
  | withings-mcp exchange --redirect-uri https://withings-mcp.example/oauth/callback
```

A running deployment can also complete the flow at `GET /oauth/callback`, which
exchanges the code and adopts the tokens. That endpoint **replaces the server's
credential**, so it is disabled unless `WITHINGS_MCP_OAUTH_STATE` is set, and
the `state` query parameter must match it.

## Tools

| tool | reads Withings | what it returns |
|---|---|---|
| `whoami` | only to refresh | the authorised user id, the scope, and how long the access token is still valid |
| `measurement_types` | no | the four supported types with their meastype numbers and units |
| `list_measurements` | yes | a series over a time range, newest first |
| `latest_measurements` | yes | the most recent reading of each requested type |

Every tool is annotated `read_only_hint = true`.

| meastype | name | unit |
|---|---|---|
| 1 | `weight` | kg |
| 6 | `body_fat_percentage` | % |
| 8 | `fat_mass` | kg |
| 76 | `muscle_mass` | kg |

Values are scaled: Withings sends an integer and a base-10 exponent, so 70.5 kg
arrives as `{"value": 70500, "unit": -3}` and is returned as `70.5`.

A type with no reading in the window is **absent** from `latest_measurements`
and named in `no_reading_in_window`, never returned as zero. An unknown type
name is an error rather than a silent omission, because three series where four
were asked for is indistinguishable from a missing measurement.

A rate limit — ours or Withings' — reaches the caller as a JSON-RPC error with
`data.class == "rate_limited"`. An empty series is a successful result. One
comparison separates "unreadable" from "nothing recorded".

## Environment

```text
WITHINGS_MCP_AUTH_TOKEN=<inbound bearer>
WITHINGS_MCP_CLIENT_ID=<Withings client id>
WITHINGS_MCP_CLIENT_SECRET=<Withings client secret>
WITHINGS_MCP_REFRESH_TOKEN=<seed refresh token>
WITHINGS_MCP_TOKEN_STATE_PATH=/var/lib/withings-mcp/tokens.json
WITHINGS_MCP_REDIRECT_URI=https://withings-mcp.example/oauth/callback
WITHINGS_MCP_OAUTH_STATE=<opaque value>
WITHINGS_MCP_ALLOWED_HOSTS=withings-mcp.example
WITHINGS_MCP_API_BASE_URL=https://wbsapi.withings.net
WITHINGS_MCP_BIND_ADDR=0.0.0.0:3000
WITHINGS_MCP_METRICS_BIND_ADDR=127.0.0.1:9090
WITHINGS_MCP_RATE_LIMIT_READS_PER_MIN=60
WITHINGS_MCP_LOG_FORMAT=json
```

The first three have no default and the server will not start without them.

`WITHINGS_MCP_ALLOWED_HOSTS` defaults to `localhost,127.0.0.1,::1`, and a
request whose `Host` is not on the list is answered `403`, so a deployment
reachable on a public name must set it to that name or it will reject every
real request while `/health` keeps answering `200`. The default is loopback
rather than any particular origin because this repository is public and an
origin is deployment configuration.

The token state file holds a live credential. It is written `0600` and replaced
atomically, and it belongs only on storage the deployment already treats as
secret.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo audit
cargo deny check bans licenses sources
```
