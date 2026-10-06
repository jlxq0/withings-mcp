//! MCP tool catalogue for Withings body metrics.
//!
//! Every tool is read-only and carries `read_only_hint = true`. There is no
//! write tool and there is not meant to be one: the deny lists other agents
//! run are generated from these annotations, so a wrong hint widens an agent
//! rather than merely mislabelling a tool.

use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{Instrument as _, Span};

use crate::audit::{self, WITHINGS_RATE_LIMITED_CODE, outcome};
use crate::auth::AccessToken;
use crate::measures::{self, Measurement};
use crate::rate_limit::Limiter;
use crate::token::{TokenManager, now_unix};
use crate::withings_client::{MeasureQuery, WithingsClient, WithingsError};

const WITHINGS_NOT_AUTHORIZED_CODE: i32 = -32_010;
const WITHINGS_INVALID_GRANT_CODE: i32 = -32_011;

/// Ceiling on `limit`, so a caller cannot ask for an unbounded page.
const MAX_LIMIT: usize = 500;
/// Default number of measurements returned when `limit` is absent.
const DEFAULT_LIMIT: usize = 50;

#[derive(Clone)]
pub struct WithingsMcpService {
    withings: WithingsClient,
    tokens: Arc<TokenManager>,
    rate_limiter: Arc<Limiter>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for WithingsMcpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithingsMcpService").finish()
    }
}

impl WithingsMcpService {
    pub fn new(
        withings: WithingsClient,
        tokens: Arc<TokenManager>,
        rate_limiter: Arc<Limiter>,
    ) -> Self {
        Self {
            withings,
            tokens,
            rate_limiter,
            tool_router: Self::withings_router(),
        }
    }

    fn rate_limit_check(&self, context: &RequestContext<RoleServer>) -> Result<(), ErrorData> {
        let token = token_from_context(context).ok_or_else(missing_token_error)?;
        let bearer_hash = audit::token_hash(&token.0);
        self.rate_limiter.check(&bearer_hash).map_err(|_| {
            structured_error(
                audit::RATE_LIMITED_CODE,
                "rate_limited",
                "rate limit exceeded; try again in a minute",
            )
        })
    }

    /// Run one read: quota, then a fresh access token, then the call.
    ///
    /// The token is fetched inside this wrapper rather than at the call site
    /// so that a refresh failure is classified by the same function as an
    /// upstream failure and lands in the audit event as one event.
    async fn run_read<F, Fut>(
        &self,
        context: &RequestContext<RoleServer>,
        tool: &'static str,
        resource: Option<&str>,
        call: F,
    ) -> Result<rmcp::model::CallToolResult, ErrorData>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Result<Value, WithingsError>>,
    {
        let started = Instant::now();
        let token_hash = token_hash_from_context(context).unwrap_or_default();
        let span = make_tool_span(tool, &token_hash, resource);
        let result = async {
            self.rate_limit_check(context)?;
            let tokens = self
                .tokens
                .access_token()
                .await
                .map_err(|error| map_withings_error(Stage::Refresh, error))?;
            let value = call(tokens.access_token)
                .await
                .map_err(|error| map_withings_error(Stage::Measure, error))?;
            Ok(structured_result(&value))
        }
        .instrument(span.clone())
        .await;
        emit_tool_audit(tool, &token_hash, resource, started, None, &span, &result);
        result
    }

    async fn measurements(
        &self,
        access_token: &str,
        query: &MeasureQuery,
    ) -> Result<Vec<Measurement>, WithingsError> {
        let body = self.withings.get_measures(access_token, query).await?;
        Ok(measures::flatten(&body))
    }
}

fn token_from_context(context: &RequestContext<RoleServer>) -> Option<AccessToken> {
    let parts = context.extensions.get::<http::request::Parts>()?;
    parts.extensions.get::<AccessToken>().cloned()
}

fn token_hash_from_context(context: &RequestContext<RoleServer>) -> Option<String> {
    token_from_context(context).map(|token| audit::token_hash(&token.0))
}

fn structured_result(value: &Value) -> rmcp::model::CallToolResult {
    rmcp::model::CallToolResult::structured(value.clone())
}

fn missing_token_error() -> ErrorData {
    ErrorData::internal_error("no access token in request context", None)
}

/// Build an application error whose `data` a caller can match on.
///
/// `code` identifies the exact condition; `class` is the single predicate,
/// derived from `audit::class_for_code` so the wire, the audit event and the
/// metric always agree. Both rate limits carry `class == "rate_limited"`, so
/// a caller telling "unreadable" from "no measurements" writes one comparison
/// rather than enumerating codes or substring-matching an English sentence.
fn structured_error(code: i32, condition: &str, message: &str) -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode(code),
        message.to_owned(),
        Some(json!({ "code": condition, "class": audit::class_for_code(code) })),
    )
}

/// Which Withings call a failure came from.
///
/// `Refresh` is everything behind [`TokenManager::access_token`]: reading the
/// store, the `requesttoken` call when the access token is spent, and the
/// persist-and-read-back. `Measure` is the `getmeas` call after a token was in
/// hand. `whoami` never reaches `Measure`, so a `whoami` failing the same way
/// as a read isolates the refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Refresh,
    Measure,
}

impl Stage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Refresh => "refresh",
            Self::Measure => "measure",
        }
    }
}

/// Map a Withings failure to the error a caller sees, with a diagnostic.
///
/// `data` always carries `stage`, and carries the numeric `withings_status`
/// (body `status`) or `http_status` when Withings answered with one. Without
/// them every unmapped status reads as the same `withings_api_error`, and
/// `503` during a refresh cannot be told from `503` during a read. The same
/// fields go to one `warn` event.
///
/// A local token-store failure carries `store_step` (`load`, `persist`,
/// `read_back` or `mismatch`) in the same way, and never the store's text.
///
/// Only the stage, the stable code string and the numbers leave this
/// function: never the error's `Display` (a transport error's source can name
/// the URL), a response body, a token or a user id.
fn map_withings_error(stage: Stage, error: WithingsError) -> ErrorData {
    let code = error.code();
    let withings_status = match error {
        WithingsError::Api { status } => Some(status),
        _ => None,
    };
    let http_status = match error {
        WithingsError::Upstream { status } => Some(status),
        _ => None,
    };
    let store_step = match error {
        WithingsError::TokenStore { step } => Some(step.as_str()),
        _ => None,
    };
    tracing::warn!(
        stage = stage.as_str(),
        code,
        withings_status,
        http_status,
        store_step,
        "Withings call failed"
    );
    let mut mapped = match error {
        WithingsError::Unauthorized => structured_error(
            WITHINGS_NOT_AUTHORIZED_CODE,
            "withings_not_authorized",
            "Withings rejected the access token",
        ),
        WithingsError::InvalidGrant => structured_error(
            WITHINGS_INVALID_GRANT_CODE,
            "withings_invalid_grant",
            "the stored Withings authorisation is no longer valid; re-authorisation is required",
        ),
        WithingsError::RateLimited => structured_error(
            WITHINGS_RATE_LIMITED_CODE,
            "withings_rate_limited",
            "Withings is rate limiting this client; try again in a minute",
        ),
        WithingsError::InvalidInput(message) => ErrorData::invalid_params(message, None),
        WithingsError::Api { status } => ErrorData::internal_error(
            format!(
                "{code}: Withings returned status {status} during {}",
                stage.as_str()
            ),
            None,
        ),
        WithingsError::TokenStore { step } => ErrorData::internal_error(
            format!(
                "{code}: the local token store failed at {step} during {}; no new access token was used",
                stage.as_str()
            ),
            None,
        ),
        other => ErrorData::internal_error(other.code(), None),
    };
    let class = audit::error_class(&mapped);
    let data = mapped
        .data
        .get_or_insert_with(|| json!({ "code": code, "class": class }));
    if let Some(fields) = data.as_object_mut() {
        fields.insert("stage".to_owned(), json!(stage.as_str()));
        if let Some(status) = withings_status {
            fields.insert("withings_status".to_owned(), json!(status));
        }
        if let Some(status) = http_status {
            fields.insert("http_status".to_owned(), json!(status));
        }
        if let Some(step) = store_step {
            fields.insert("store_step".to_owned(), json!(step));
        }
    }
    mapped
}

fn make_tool_span(tool: &'static str, token_hash: &str, resource: Option<&str>) -> Span {
    tracing::info_span!(
        "mcp.tool",
        tool,
        token_hash,
        resource = resource.unwrap_or(""),
        outcome = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
    )
}

fn emit_tool_audit(
    tool: &'static str,
    token_hash: &str,
    resource: Option<&str>,
    started: Instant,
    result_count: Option<usize>,
    span: &Span,
    result: &Result<rmcp::model::CallToolResult, ErrorData>,
) {
    let (outcome_value, error_class) = match result {
        Ok(_) => (outcome::OK, None),
        Err(error) => {
            // One function decides, so the two fields cannot disagree about
            // one event. See `audit::error_class`.
            let class = audit::error_class(error);
            let outcome_value = if class == outcome::RATE_LIMITED {
                outcome::RATE_LIMITED
            } else {
                outcome::ERROR
            };
            (outcome_value, Some(class))
        }
    };
    span.record("outcome", outcome_value);
    span.record(
        "latency_ms",
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
    audit::tool_call(
        tool,
        token_hash,
        resource,
        outcome_value,
        started,
        result_count,
        error_class,
    );
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListMeasurementsParams {
    /// Measurement names to return, from `measurement_types`. Omit for all
    /// four.
    #[serde(default)]
    types: Option<Vec<String>>,
    /// Unix seconds; only measurements taken at or after this are returned.
    #[serde(default)]
    start: Option<i64>,
    /// Unix seconds; only measurements taken at or before this are returned.
    #[serde(default)]
    end: Option<i64>,
    /// Maximum measurements to return. Defaults to 50, capped at 500.
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LatestMeasurementsParams {
    /// Measurement names to return, from `measurement_types`. Omit for all
    /// four.
    #[serde(default)]
    types: Option<Vec<String>>,
    /// How far back to look, in days. Defaults to 90.
    #[serde(default)]
    within_days: Option<u32>,
}

/// Resolve caller-supplied names to Withings meastype numbers.
///
/// An unknown name is an error rather than a silent omission: returning three
/// series when four were asked for looks identical to a person having taken
/// no fourth measurement.
fn resolve_types(names: Option<&Vec<String>>) -> Result<Vec<u16>, ErrorData> {
    let Some(names) = names else {
        return Ok(measures::all_meastypes());
    };
    if names.is_empty() {
        return Ok(measures::all_meastypes());
    }
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let kind = measures::by_name(name).ok_or_else(|| {
            let known: Vec<&str> = measures::SUPPORTED.iter().map(|entry| entry.name).collect();
            ErrorData::invalid_params(
                format!("unknown measurement type {name:?}; known types: {known:?}"),
                None,
            )
        })?;
        out.push(kind.meastype);
    }
    Ok(out)
}

fn clamp_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

#[tool_router(router = withings_router)]
impl WithingsMcpService {
    #[tool(
        description = "Report which Withings account this server is authorised against, the \
                       granted scope, and how long the current access token is still valid. \
                       Does not read any measurement.",
        annotations(title = "Who am I", read_only_hint = true, idempotent_hint = true)
    )]
    async fn whoami(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let token_hash = token_hash_from_context(&context).unwrap_or_default();
        let span = make_tool_span("whoami", &token_hash, None);
        let result = async {
            self.rate_limit_check(&context)?;
            let tokens = self
                .tokens
                .access_token()
                .await
                .map_err(|error| map_withings_error(Stage::Refresh, error))?;
            let now = now_unix();
            Ok(structured_result(&json!({
                "userid": tokens.userid,
                "scope": tokens.scope,
                "access_token_expires_in_seconds": tokens.expires_in(now),
                "measurement_types": measures::SUPPORTED
                    .iter()
                    .map(|entry| entry.name)
                    .collect::<Vec<_>>(),
                "read_only": true,
            })))
        }
        .instrument(span.clone())
        .await;
        emit_tool_audit("whoami", &token_hash, None, started, None, &span, &result);
        result
    }

    #[tool(
        description = "List the measurement types this server can read, with their Withings \
                       meastype numbers and units. Reads nothing from the account.",
        annotations(
            title = "Measurement types",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn measurement_types(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let token_hash = token_hash_from_context(&context).unwrap_or_default();
        let span = make_tool_span("measurement_types", &token_hash, None);
        let result = async {
            self.rate_limit_check(&context)?;
            let types: Vec<Value> = measures::SUPPORTED
                .iter()
                .map(|entry| {
                    json!({
                        "name": entry.name,
                        "meastype": entry.meastype,
                        "unit": entry.unit,
                        "description": entry.description,
                    })
                })
                .collect();
            Ok(structured_result(&json!({ "types": types })))
        }
        .instrument(span.clone())
        .await;
        emit_tool_audit(
            "measurement_types",
            &token_hash,
            None,
            started,
            Some(measures::SUPPORTED.len()),
            &span,
            &result,
        );
        result
    }

    #[tool(
        description = "List body measurements over a time range, newest first. Values are \
                       scaled to their unit: weight, fat mass and muscle mass in kilograms, \
                       body fat as a percentage.",
        annotations(
            title = "List measurements",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn list_measurements(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<ListMeasurementsParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let meastypes = resolve_types(params.types.as_ref())?;
        let resource = meastypes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let limit = clamp_limit(params.limit);
        let query = MeasureQuery {
            meastypes,
            category: Some(1),
            startdate: params.start,
            enddate: params.end,
            ..MeasureQuery::default()
        };
        self.run_read(
            &context,
            "list_measurements",
            Some(&resource),
            |access_token| async move {
                let mut measurements = self.measurements(&access_token, &query).await?;
                measurements.sort_by_key(|measurement| std::cmp::Reverse(measurement.taken_at));
                let total = measurements.len();
                measurements.truncate(limit);
                Ok(json!({
                    "measurements": measurements,
                    "returned": measurements.len(),
                    "total_in_range": total,
                    "truncated": total > limit,
                }))
            },
        )
        .await
    }

    #[tool(
        description = "The most recent reading of each requested measurement type. A type with \
                       no reading in the window is absent from the result rather than zero.",
        annotations(
            title = "Latest measurements",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn latest_measurements(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(params): Parameters<LatestMeasurementsParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let meastypes = resolve_types(params.types.as_ref())?;
        let resource = meastypes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let within_days = i64::from(params.within_days.unwrap_or(90));
        let startdate = now_unix()
            .try_into()
            .map(|now: i64| now.saturating_sub(within_days.saturating_mul(86_400)))
            .ok();
        let requested: Vec<u16> = meastypes.clone();
        let query = MeasureQuery {
            meastypes,
            category: Some(1),
            startdate,
            ..MeasureQuery::default()
        };
        self.run_read(
            &context,
            "latest_measurements",
            Some(&resource),
            |access_token| async move {
                let measurements = self.measurements(&access_token, &query).await?;
                let latest = measures::latest_per_type(&measurements)
                    .into_iter()
                    .filter(|measurement| requested.contains(&measurement.meastype))
                    .collect::<Vec<_>>();
                let missing: Vec<&str> = requested
                    .iter()
                    .filter(|meastype| {
                        !latest
                            .iter()
                            .any(|measurement| measurement.meastype == **meastype)
                    })
                    .filter_map(|meastype| measures::by_meastype(*meastype).map(|entry| entry.name))
                    .collect();
                Ok(json!({
                    "measurements": latest,
                    "within_days": within_days,
                    // Naming what was asked for and not found keeps "never
                    // measured" from reading as "measured as nothing".
                    "no_reading_in_window": missing,
                }))
            },
        )
        .await
    }
}

// `#[tool_handler]` generates methods that trip this lint; there is nothing
// written here to rewrite, and bumping rmcp is the only thing that retires it.
// The attribute is also what pins the tree's lint floor: an `#[allow]` naming
// a lint the running clippy does not have is itself an error under
// `-D warnings`. See AGENTS.md.
#[allow(clippy::unused_async_trait_impl)]
#[tool_handler(router = self.tool_router)]
impl ServerHandler for WithingsMcpService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "withings-mcp reads body metrics from one authorised Withings account: weight, body \
             fat percentage, fat mass and muscle mass. It is read-only and has no tool that \
             writes to Withings. Call measurement_types for the names and units, \
             latest_measurements for the current state, and list_measurements for a series over \
             time. A measurement type absent from a result had no reading in the window; it is \
             never reported as zero.",
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn omitted_and_empty_type_lists_both_mean_all_four() {
        assert_eq!(resolve_types(None).unwrap(), vec![1, 6, 8, 76]);
        assert_eq!(resolve_types(Some(&vec![])).unwrap(), vec![1, 6, 8, 76]);
    }

    #[test]
    fn named_types_resolve_in_the_order_given() {
        let names = vec!["muscle_mass".to_owned(), "weight".to_owned()];
        assert_eq!(resolve_types(Some(&names)).unwrap(), vec![76, 1]);
    }

    /// An unknown name must fail rather than being dropped. Three series
    /// returned where four were asked for is indistinguishable from a person
    /// not having taken the fourth measurement.
    #[test]
    fn an_unknown_type_is_an_error_rather_than_a_silent_omission() {
        let names = vec!["weight".to_owned(), "vo2max".to_owned()];
        let error = resolve_types(Some(&names)).unwrap_err();
        let message = format!("{}", error.message);
        assert!(message.contains("vo2max"), "{message}");
        assert!(message.contains("weight"), "{message}");
    }

    #[test]
    fn the_limit_default_and_ceiling_are_the_ones_a_caller_gets() {
        assert_eq!(clamp_limit(None), 50);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(10_000)), MAX_LIMIT);
        // Zero would be a page with nothing in it, which reads as an empty
        // account rather than as a bad argument.
        assert_eq!(clamp_limit(Some(0)), 1);
    }

    #[test]
    fn both_rate_limits_reach_a_caller_as_one_class() {
        let ours = structured_error(audit::RATE_LIMITED_CODE, "rate_limited", "slow down");
        let theirs = map_withings_error(Stage::Measure, WithingsError::RateLimited);
        for error in [&ours, &theirs] {
            let data = error.data.as_ref().unwrap();
            assert_eq!(data["class"], "rate_limited", "{error:?}");
        }
        // The codes still separate ours from theirs underneath the class.
        assert_ne!(ours.code.0, theirs.code.0);
    }

    #[test]
    fn an_expired_authorisation_says_so_rather_than_reading_as_internal() {
        let error = map_withings_error(Stage::Refresh, WithingsError::InvalidGrant);
        let data = error.data.as_ref().unwrap();
        assert_eq!(data["code"], "withings_invalid_grant");
        assert!(
            error.message.contains("re-authorisation"),
            "the message must say what a person has to do: {}",
            error.message
        );
    }
}
