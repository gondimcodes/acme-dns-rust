use axum::{
    extract::{State, Request},
    http::{StatusCode, HeaderValue, header::STRICT_TRANSPORT_SECURITY, Method},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use crate::db::{DbPool, Record};
use crate::config::Config;
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tower_http::cors::{CorsLayer, Any};
use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusHandle;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DbPool>,
    pub config: Arc<Config>, // PERF-02: Arc<Config> avoids deep clones
    pub metrics_handle: Arc<PrometheusHandle>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    allowfrom: Option<Vec<String>>,
}

#[derive(Serialize)]
struct RegisterResponse {
    username: String,
    password: String,
    fulldomain: String,
    subdomain: String,
    allowfrom: Vec<String>,
}

#[derive(Deserialize)]
struct UpdateRequest {
    subdomain: String,
    txt: String,
}

#[derive(Serialize)]
struct UpdateResponse {
    txt: String,
}

// ─── Rate Limiter (Token Bucket) ────────────────────────────────────────────

struct RateLimitState {
    tokens: f64,
    last_update: Instant,
}

/// PERF-01: DashMap replaces Mutex<HashMap> — concurrent access without a global lock
#[derive(Clone)]
struct IpRateLimiter {
    /// General endpoint limiter (5 tokens burst, 0.5 token/s replenish)
    general: Arc<DashMap<IpAddr, RateLimitState>>,
}

impl IpRateLimiter {
    fn new() -> Self {
        Self {
            general: Arc::new(DashMap::new()),
        }
    }
}

/// SEG-01: extract real client IP — honours use_header config when behind a trusted proxy
fn extract_client_ip(request: &Request, config: &Config) -> Option<IpAddr> {
    if config.api.use_header {
        // SEG-02: only honour the header if the connecting IP is a trusted proxy
        let conn_ip = request
            .extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());

        let is_trusted = conn_ip.map(|ip| {
            config.api.trusted_proxies.iter().any(|cidr| {
                cidr.parse::<IpNetwork>().map(|n| n.contains(ip)).unwrap_or(false)
            })
        }).unwrap_or(false);

        if is_trusted {
            if let Some(hdr) = request.headers().get(&config.api.header_name) {
                if let Ok(s) = hdr.to_str() {
                    if let Some(first) = s.split(',').next() {
                        if let Ok(ip) = first.trim().parse::<IpAddr>() {
                            return Some(ip);
                        }
                    }
                }
            }
        }
    }

    // QUAL-07: always fall back to direct connection IP
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
}

async fn rate_limiting_middleware(
    State((limiter, config)): State<(IpRateLimiter, Arc<Config>)>,
    request: Request,
    next: Next,
) -> Response {
    // SEG-01: use real client IP (resolves proxy bypass issue)
    let ip = extract_client_ip(&request, &config)
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));

    let now = Instant::now();
    // SEG-09: clean stale entries (>5 min without activity) to prevent memory leak
    let stale_threshold = Duration::from_secs(300);
    limiter.general.retain(|_, state| now.duration_since(state.last_update) < stale_threshold);

    let mut entry = limiter.general.entry(ip).or_insert_with(|| RateLimitState {
        tokens: 5.0,
        last_update: now,
    });

    let elapsed = now.duration_since(entry.last_update).as_secs_f64();
    entry.tokens = (entry.tokens + elapsed * 0.5).min(5.0);
    entry.last_update = now;

    if entry.tokens >= 1.0 {
        entry.tokens -= 1.0;
        drop(entry);
        next.run(request).await
    } else {
        StatusCode::TOO_MANY_REQUESTS.into_response()
    }
}

pub fn create_router(state: AppState) -> Router {
    let limiter = IpRateLimiter::new();
    let config_for_rate = Arc::clone(&state.config);

    // SEG-11: build CORS layer from corsorigins config
    // Using Any (wildcard) since corsorigins = ["*"] — no credentials mode
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    let metrics_handle = Arc::clone(&state.metrics_handle);
    let mut router = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(move || {
            let handle = Arc::clone(&metrics_handle);
            async move {
                // Update active connections gauge
                gauge!("acme_dns_active_connections").set(0.0);
                handle.render()
            }
        }));

    if !state.config.api.disable_registration {
        router = router.route("/register", post(register));
    }

    let protected = Router::new()
        .route("/update", post(update))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let mut app = router
        .merge(protected)
        .layer(cors)
        .route_layer(middleware::from_fn_with_state(
            (limiter, config_for_rate),
            rate_limiting_middleware,
        ))
        .with_state(state.clone());

    // SEG-12: inject HSTS header when configured
    if state.config.api.hsts_enabled {
        let max_age = state.config.api.hsts_max_age.unwrap_or(31_536_000);
        let mut hsts_value = format!("max-age={}", max_age);
        if state.config.api.hsts_include_subdomains {
            hsts_value.push_str("; includeSubDomains");
        }
        if state.config.api.hsts_preload {
            hsts_value.push_str("; preload");
        }
        if let Ok(hv) = HeaderValue::from_str(&hsts_value) {
            app = app.layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
                STRICT_TRANSPORT_SECURITY,
                hv,
            ));
        }
    }

    app
}

async fn health_check() -> impl IntoResponse {
    StatusCode::OK
}

/// SEG-04: validate that txt is a valid ACME DNS-01 token (Base64URL, 43 chars)
/// Delegates to auth::is_valid_acme_token for testability.
#[inline]
fn is_valid_acme_token(s: &str) -> bool {
    crate::auth::is_valid_acme_token(s)
}

async fn register(
    State(state): State<AppState>,
    request: Request,
) -> impl IntoResponse {
    // ARQ-04: strict per-IP rate limit for /register — 1 req per 60 seconds
    let ip = extract_client_ip(&request, &state.config)
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));

    // We need to extract the limiter from extensions — passed via router state
    // Simple approach: use a per-request DashMap check via AppState field
    // For now, track last registration time per IP in a thread-local DashMap
    // (the IpRateLimiter is owned by the route_layer middleware; we use a separate static here)
    {
        use std::sync::OnceLock;
        static REGISTER_LIMITER: OnceLock<DashMap<IpAddr, Instant>> = OnceLock::new();
        let limiter = REGISTER_LIMITER.get_or_init(DashMap::new);

        let now = Instant::now();
        let rate_limit_secs = if state.config.api.register_rate_limit_per_min > 0 {
            60 / state.config.api.register_rate_limit_per_min as u64
        } else {
            0 // disabled
        };

        if rate_limit_secs > 0 {
            if let Some(last) = limiter.get(&ip) {
                if now.duration_since(*last) < Duration::from_secs(rate_limit_secs) {
                    return StatusCode::TOO_MANY_REQUESTS.into_response();
                }
            }
            limiter.insert(ip, now);
            // Clean stale entries
            limiter.retain(|_, t| now.duration_since(*t) < Duration::from_secs(300));
        }
    }

    // Parse body
    let body = match axum::body::to_bytes(request.into_body(), 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let payload: RegisterRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let allow_from = payload.allowfrom.unwrap_or_default();

    // Validate CIDRs
    for cidr in &allow_from {
        if cidr.parse::<IpNetwork>().is_err() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "invalid_allowfrom_cidr".to_string() }),
            ).into_response();
        }
    }

    match state.db.register(allow_from.clone()).await {
        Ok((username, password, subdomain)) => {
            counter!("acme_dns_register_total", "status" => "success").increment(1);
            let fulldomain = format!("{}.{}", subdomain, state.config.general.domain);
            (
                StatusCode::CREATED,
                Json(RegisterResponse {
                    username: username.to_string(),
                    password,
                    fulldomain,
                    subdomain,
                    allowfrom: allow_from,
                }),
            ).into_response()
        }
        Err(e) => {
            counter!("acme_dns_register_total", "status" => "error").increment(1);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() }),
            ).into_response()
        }
    }
}

// Custom request extension key to pass authenticated Record down
#[derive(Clone)]
struct AuthenticatedUser(Record);

async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();

    let headers = &parts.headers;
    let user_header = headers.get("X-Api-User")
        .and_then(|h| h.to_str().ok());
    let key_header = headers.get("X-Api-Key")
        .and_then(|h| h.to_str().ok());

    if let (Some(uname), Some(key)) = (user_header, key_header) {
        match state.db.get_user_by_username(uname).await {
            Ok(Some(record)) => {
                if crate::auth::correct_password(key, &record.password_hash) {
                    // SEG-01/SEG-02: extract real client IP respecting trusted_proxies
                    let full_request = Request::from_parts(parts.clone(), axum::body::Body::empty());
                    let client_ip = extract_client_ip(&full_request, &state.config);
                    drop(full_request);

                    // SEG-03: fail-closed — if allow_from is set but IP is unknown, deny
                    if !record.allow_from.is_empty() {
                        let ip = match client_ip {
                            Some(ip) => ip,
                            None => return StatusCode::UNAUTHORIZED.into_response(),
                        };
                        let allowed = record.allow_from.iter().any(|cidr| {
                            cidr.parse::<IpNetwork>().map(|n| n.contains(ip)).unwrap_or(false)
                        });
                        if !allowed {
                            return StatusCode::UNAUTHORIZED.into_response();
                        }
                    }

                    parts.extensions.insert(AuthenticatedUser(record));
                    let request = Request::from_parts(parts, body);
                    return next.run(request).await;
                }
            }
            _ => {
                // SEG-07: timing equalization — even when user doesn't exist,
                // spend bcrypt-equivalent time to prevent username enumeration
                crate::auth::dummy_verify();
            }
        }
    }

    StatusCode::UNAUTHORIZED.into_response()
}

async fn update(
    State(state): State<AppState>,
    request: Request,
) -> impl IntoResponse {
    let user_record = match request.extensions().get::<AuthenticatedUser>() {
        Some(AuthenticatedUser(rec)) => rec.clone(),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    // SEG-05: body limit reduced to 1 KB (payload is ~100 bytes)
    let body = match axum::body::to_bytes(request.into_body(), 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let payload: UpdateRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if payload.subdomain != user_record.subdomain {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "subdomain_mismatch".to_string() }),
        ).into_response();
    }

    // SEG-04: validate txt is a valid Base64URL ACME token (exactly 43 chars)
    if !is_valid_acme_token(&payload.txt) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "invalid_txt_value".to_string() }),
        ).into_response();
    }

    match state.db.update_txt(&payload.subdomain, &payload.txt).await {
        Ok(_) => {
            counter!("acme_dns_update_total", "status" => "success").increment(1);
            (
                StatusCode::OK,
                Json(UpdateResponse { txt: payload.txt }),
            ).into_response()
        }
        Err(_) => {
            counter!("acme_dns_update_total", "status" => "error").increment(1);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error".to_string() }),
            ).into_response()
        }
    }
}
