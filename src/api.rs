use axum::{
    extract::{State, Request},
    http::StatusCode,
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
use std::net::IpAddr;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DbPool>,
    pub config: Config,
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

// Simple IP-based Rate Limiter (Token Bucket implementation)
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Mutex;

struct RateLimitState {
    tokens: f64,
    last_update: Instant,
}

#[derive(Clone)]
struct IpRateLimiter {
    limits: Arc<Mutex<HashMap<IpAddr, RateLimitState>>>,
}

impl IpRateLimiter {
    fn new() -> Self {
        Self {
            limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

async fn rate_limiting_middleware(
    State(limiter): State<IpRateLimiter>,
    request: Request,
    next: Next,
) -> Response {
    // Attempt to extract remote IP. Since we behind middlewares, look for connection metadata or headers
    let ip = if let Some(addr) = request.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>() {
        addr.ip()
    } else {
        // Fallback to loopback if unable to detect
        IpAddr::from([127, 0, 0, 1])
    };

    let mut limits = limiter.limits.lock().await;
    let now = Instant::now();
    
    let bucket = limits.entry(ip).or_insert_with(|| RateLimitState {
        tokens: 5.0, // Max burst tokens
        last_update: now,
    });

    // Replenish 1 token per 2 seconds (0.5 tokens/sec)
    let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * 0.5).min(5.0);
    bucket.last_update = now;

    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        drop(limits); // Release lock
        next.run(request).await
    } else {
        StatusCode::TOO_MANY_REQUESTS.into_response()
    }
}

pub fn create_router(state: AppState) -> Router {
    let limiter = IpRateLimiter::new();
    let mut router = Router::new()
        .route("/health", get(health_check));

    if !state.config.api.disable_registration {
        router = router.route("/register", post(register));
    }

    let protected = Router::new()
        .route("/update", post(update))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    router
        .merge(protected)
        .route_layer(middleware::from_fn_with_state(limiter, rate_limiting_middleware))
        .with_state(state)
}

async fn health_check() -> impl IntoResponse {
    StatusCode::OK
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
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
    
    // Convert parts back or extract manually using parts
    let headers = &parts.headers;
    let user_header = headers.get("X-Api-User")
        .and_then(|h| h.to_str().ok());
    let key_header = headers.get("X-Api-Key")
        .and_then(|h| h.to_str().ok());

    if let (Some(uname), Some(key)) = (user_header, key_header) {
        if let Ok(Some(record)) = state.db.get_user_by_username(uname).await {
            if crate::auth::correct_password(key, &record.password_hash) {
                // Check allowed IP rules
                let mut client_ip = None;
                if state.config.api.use_header {
                    if let Some(hdr) = headers.get(&state.config.api.header_name) {
                        if let Ok(hdr_str) = hdr.to_str() {
                            if let Some(first_ip) = hdr_str.split(',').next() {
                                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                                    client_ip = Some(ip);
                                }
                            }
                        }
                    }
                }
                
                // Fallback to connection Remote Address if not set or found via header
                if client_ip.is_none() {
                    // Axum state request extensions or connection info
                    // Simple dummy fallback/mock check (we'll bind actual remote addr in main)
                }

                // If whitelist exists, validate client IP matches at least one network
                if !record.allow_from.is_empty() {
                    if let Some(ip) = client_ip {
                        let mut allowed = false;
                        for cidr in &record.allow_from {
                            if let Ok(net) = cidr.parse::<IpNetwork>() {
                                if net.contains(ip) {
                                    allowed = true;
                                    break;
                                }
                            }
                        }
                        if !allowed {
                            return StatusCode::UNAUTHORIZED.into_response();
                        }
                    }
                }

                parts.extensions.insert(AuthenticatedUser(record));
                let request = Request::from_parts(parts, body);
                return next.run(request).await;
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
    // Parse body manually because we already consumed or need to parse body parts
    let body = match axum::body::to_bytes(request.into_body(), 1024 * 16).await {
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

    match state.db.update_txt(&payload.subdomain, &payload.txt).await {
        Ok(_) => {
            (
                StatusCode::OK,
                Json(UpdateResponse { txt: payload.txt }),
            ).into_response()
        }
        Err(_) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error".to_string() }),
            ).into_response()
        }
    }
}
