use biscuit_auth::{Authorizer, Biscuit, KeyPair, PrivateKey, PublicKey};
use tokio_test::assert_ready_ok;
use tower::filter::Filter;
use tower_test::{assert_request_eq, mock};

use tower_biscuit_auth::{
    AuthConfig, AuthExtract, AuthPredicate, BiscuitAuthError, ErrorMode, RootKeys, SharedAuth,
};

fn gen_test_auth_info(error_mode: ErrorMode) -> AuthConfig {
    let pubkey: PublicKey = keys().public();
    let pubkeys: RootKeys = RootKeys::new(pubkey);

    let mut authorizer = Authorizer::new().unwrap();

    // Load policy from "database".
    let policy = r#"allow if right("write");"#;

    authorizer.add_code(policy).unwrap();

    AuthConfig::new(pubkeys, authorizer, error_mode)
}

fn keys() -> KeyPair {
    let private = PrivateKey::from_bytes(&[42; 32]).unwrap();
    KeyPair::from(private)
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Request(u8);

#[derive(Clone, Debug)]
struct Extractor;

impl AuthExtract<Request> for Extractor {
    fn auth_token(
        &self,
        req: &Request,
        _auth_config: &AuthConfig,
    ) -> Result<Biscuit, BiscuitAuthError> {
        let keypair = keys();
        let biscuit = mock_biscuit(keypair, req)?;
        Ok(biscuit)
    }
}

fn mock_biscuit(keypair: KeyPair, req: &Request) -> Result<Biscuit, BiscuitAuthError> {
    let mut builder = Biscuit::builder(&keypair);
    builder.add_authority_fact(r#"right("read")"#)?;
    if let Request(0) = req {
        builder.add_authority_fact(r#"right("write")"#)?;
    }
    let biscuit = builder.build()?;
    Ok(biscuit)
}

#[tokio::test(flavor = "current_thread")]
async fn simple_request_allowed() {
    let error_mode = ErrorMode::Verbose;
    let biscuit_auth = SharedAuth::new(gen_test_auth_info(error_mode));
    let predicate = biscuit_auth.into_predicate(Extractor);
    let auth_layer = Filter::<Request, AuthPredicate<_>>::layer(predicate);

    let (mut service, mut handle) = mock::spawn_layer(auth_layer);
    assert_ready_ok!(service.poll_ready());

    let request = Request(0);
    let response = service.call(request);

    assert_request_eq!(handle, request).send_response(());
    assert!(response.await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn simple_request_denied_with_context() {
    let error_mode = ErrorMode::Verbose;
    let biscuit_auth = SharedAuth::new(gen_test_auth_info(error_mode));
    let predicate = biscuit_auth.into_predicate(Extractor);
    let auth_layer = Filter::<Request, AuthPredicate<_>>::layer(predicate);

    let (mut service, mut _handle) = mock::spawn_layer::<_, (), _>(auth_layer);
    assert_ready_ok!(service.poll_ready());

    let request = Request(1);
    let response = service.call(request).await;

    let error = response.unwrap_err();
    let error: Box<BiscuitAuthError> = error.downcast().unwrap();
    assert!(error.auth_error().is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn simple_request_denied_no_context() {
    let error_mode = ErrorMode::Secure;
    let biscuit_auth = SharedAuth::new(gen_test_auth_info(error_mode));
    let predicate = biscuit_auth.into_predicate(Extractor);
    let auth_layer = Filter::<Request, AuthPredicate<_>>::layer(predicate);

    let (mut service, mut _handle) = mock::spawn_layer::<_, (), _>(auth_layer);
    assert_ready_ok!(service.poll_ready());

    let request = Request(1);
    let response = service.call(request).await;

    let error = response.unwrap_err();
    let error: Box<BiscuitAuthError> = error.downcast().unwrap();
    assert!(error.auth_error().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn dynamic_policy_change() {
    let error_mode = ErrorMode::Secure;
    let biscuit_auth = SharedAuth::new(gen_test_auth_info(error_mode));
    let predicate = biscuit_auth.clone().into_predicate(Extractor);
    let auth_layer = Filter::<Request, AuthPredicate<_>>::layer(predicate);

    let (mut service, mut _handle) = mock::spawn_layer::<_, (), _>(auth_layer);
    assert_ready_ok!(service.poll_ready());

    let request = Request(1);
    let response = service.call(request).await;

    let error = response.unwrap_err();
    let error: Box<BiscuitAuthError> = error.downcast().unwrap();

    // This error doesn't contain any failure info.
    assert!(error.auth_error().is_none());

    // Change the policy to ErrorMode::Verbose.
    let mut new_auth_info = biscuit_auth.to_auth_info();
    new_auth_info.error_mode = ErrorMode::Verbose;
    biscuit_auth.update(new_auth_info);

    let response = service.call(request).await;

    let error = response.unwrap_err();
    let error: Box<BiscuitAuthError> = error.downcast().unwrap();

    // The new error contains the verification failure info.
    assert!(error.auth_error().is_some());
}
