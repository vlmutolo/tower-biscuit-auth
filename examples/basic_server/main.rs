use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    extract::Path,
    routing::{get, post},
    Router, Server,
};
use base64::URL_SAFE;
use biscuit_auth::{Authorizer, Biscuit, PublicKey};
use http::{Request, StatusCode};
use tower::{filter::Filter, ServiceBuilder};
use tower_biscuit_auth::{
    http::ExtensionBiscuit, AuthConfig, AuthExtract, AuthPredicate, BiscuitAuthError, ErrorMode,
    RootKeys, SharedAuth,
};

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let _rt_guard = rt.enter();

    let name_extractor = ExtensionBiscuit::new(move |req, config, authorizer| {
        // TODO: We can probably come up with a better abstraction
        // that doesn't require the user to re-write a bunch of
        // "if the biscuit doesn't already exist" logic.
        //
        // Parse out the biscuit from the request if we haven't already.
        if req.extensions().get::<Biscuit>().is_none() {
            let biscuit = req
                .headers()
                .get("x-biscuit-auth")
                .ok_or(BiscuitAuthError::MissingBiscuit)?;

            let biscuit = Biscuit::from_base64(biscuit.as_ref(), |id| config.pubkey_by_id(id))?;
            let _ = req.extensions_mut().insert(biscuit);
        }

        // TODO: There should be a way to re-use the `Path` extractor here.
        let user_name = req
            .uri()
            .path()
            .split('/')
            .nth(2)
            .ok_or(BiscuitAuthError::MissingBiscuit)?;

        // FIXME: This is very likely to be a code-injection vulnerability.
        authorizer.add_code(format!(r#"check if user("{user_name}")"#));

        Ok(())
    });

    let biscuit_auth = load_auth(None);
    let biscuit_predicate = biscuit_auth.into_predicate(name_extractor);
    let auth_layer = Filter::<Request<Body>, AuthPredicate<_>>::layer(biscuit_predicate);

    let app: Router<Body> = Router::new()
        // This route is public.
        .route("/", get(|| async { "Hello, World!" }))
        // This one requires a biscuit with an authority fact
        // indicating that the bearer is "user($user_id)".
        .route(
            "/admin/:name",
            get(admin).layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_auth_error))
                    .layer(auth_layer),
            ),
        )
        // This route makes the server reload its authentication config.
        .route(
            "/auth/reload",
            post({
                let biscuit_auth = biscuit_auth.clone();
                move || async {
                    let _ = load_auth(Some(biscuit_auth));
                    "Reloaded auth."
                }
            }),
        );

    let server = Server::bind(&"127.0.0.1:3000".parse().unwrap());
    let server = server.serve(app.into_make_service());
    rt.block_on(server).unwrap();
}

async fn admin(Path(user_id): Path<String>) -> String {
    format!("Hello, admin {user_id}!")
}

async fn handle_auth_error(err: tower::BoxError) -> (StatusCode, String) {
    match err.downcast_ref::<BiscuitAuthError>() {
        Some(err) => (StatusCode::UNAUTHORIZED, err.to_string()),
        None => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
    }
}

fn load_auth(old_auth: Option<SharedAuth>) -> SharedAuth {
    let pubkey: String = std::fs::read_to_string("assets/public.key").unwrap();
    let pubkey: Vec<u8> = hex::decode(pubkey.trim()).unwrap();
    let pubkey = PublicKey::from_bytes(&pubkey).unwrap();
    let root_keys = RootKeys::new(pubkey);

    let mut authorizer = Authorizer::new().unwrap();

    let policy = std::fs::read_to_string("assets/policy.txt").unwrap();
    authorizer.add_code(&policy).unwrap();

    // WARNING: You probably don't want to use ErrorMode::Verbose in production.
    // It can give attackers more information about the system they're trying to
    // break. Prefer ErrorMode::Secure instead.
    let auth_config = AuthConfig::new(root_keys, authorizer, ErrorMode::Verbose);

    // If we're passed in an existing `BiscuitAuth<_>`, we should update it
    // instead of returning a new one. This way, the rest of the endpoints
    // already using the existing `BiscuitAuth` actually get the new information.
    match old_auth {
        None => SharedAuth::new(auth_config),
        Some(old_auth) => {
            old_auth.update(auth_config);
            old_auth
        }
    }
}

fn parse_auth_token<T>(
    req: &Request<T>,
    auth_config: &AuthConfig,
) -> Result<Biscuit, BiscuitAuthError> {
    let biscuit_val = req.headers().get("x-biscuit-auth").ok_or_else(|| {
        BiscuitAuthError::Other(anyhow::anyhow!("couldn't find biscuit header").into())
    })?;

    let biscuit = biscuit_val.as_bytes();
    let biscuit =
        base64::decode_config(biscuit, URL_SAFE).map_err(|e| BiscuitAuthError::Other(e.into()))?;

    auth_config.biscuit(&biscuit)
}
