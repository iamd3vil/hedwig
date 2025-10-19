use std::convert::Infallible;
use std::net::SocketAddr;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Spawns a lightweight HTTP server that reports liveness for Hedwig.
pub fn spawn_health_server(addr: SocketAddr, shutdown: CancellationToken) {
    info!(%addr, "starting health endpoint");

    tokio::spawn(async move {
        let shutdown_for_service = shutdown.clone();
        let make_svc = make_service_fn(move |_conn| {
            let shutdown = shutdown_for_service.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    handle_health_request(req, shutdown.clone())
                }))
            }
        });

        let server = Server::bind(&addr).serve(make_svc);
        let server = server.with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        });

        if let Err(err) = server.await {
            error!(%addr, error = %err, "health server exited unexpectedly");
        } else {
            info!(%addr, "health server stopped");
        }
    });
}

async fn handle_health_request(
    req: Request<Body>,
    shutdown: CancellationToken,
) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") | (&Method::HEAD, "/healthz") => {
            let status = if shutdown.is_cancelled() {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            };

            let body = if status == StatusCode::OK {
                "ok"
            } else {
                "shutting down"
            };

            let response = Response::builder()
                .status(status)
                .body(Body::from(body))
                .expect("failed to build health response");
            Ok(response)
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .expect("failed to build health 404 response")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn liveness_returns_ok_when_running() {
        let token = CancellationToken::new();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();

        let response = handle_health_request(request, token).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn liveness_reflects_shutdown() {
        let token = CancellationToken::new();
        token.cancel();

        let request = Request::builder()
            .method(Method::GET)
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();

        let response = handle_health_request(request, token).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
