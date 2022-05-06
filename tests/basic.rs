use biscuit_auth::{Authorizer, Biscuit, KeyPair, PrivateKey, PublicKey};
use tokio_test::assert_ready_ok;
use tower::filter::Filter;
use tower_test::{assert_request_eq, mock};

use tower_biscuit_auth::{
    AuthConfig, AuthExtract, BiscuitAuth, BiscuitAuthError, ErrorMode, RootKeys,
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

impl AuthExtract for Extractor {
    type Request = Request;

    fn auth_token(&self, req: &Self::Request) -> Result<Vec<u8>, BiscuitAuthError> {
        let keypair = keys();

        let mut builder = Biscuit::builder(&keypair);
        builder.add_authority_fact(r#"right("read")"#)?;

        if let Request(0) = req {
            builder.add_authority_fact(r#"right("write")"#)?;
        }

        let biscuit = builder.build()?;
        Ok(biscuit.to_vec()?)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn simple_request_allowed() {
    let error_mode = ErrorMode::Verbose;
    let biscuit_auth = BiscuitAuth::new(gen_test_auth_info(error_mode), Extractor);
    let auth_layer = Filter::<Request, BiscuitAuth<_>>::layer(biscuit_auth);

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
    let biscuit_auth = BiscuitAuth::new(gen_test_auth_info(error_mode), Extractor);
    let auth_layer = Filter::<Request, BiscuitAuth<_>>::layer(biscuit_auth);

    let (mut service, mut _handle) = mock::spawn_layer::<_, (), _>(auth_layer);
    assert_ready_ok!(service.poll_ready());

    let request = Request(1);
    let response = service.call(request).await;

    let error = response.unwrap_err();
    let error: Box<BiscuitAuthError> = error.downcast().unwrap();
    assert!(error.failure_info().is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn simple_request_denied_no_context() {
    let error_mode = ErrorMode::Secure;
    let biscuit_auth = BiscuitAuth::new(gen_test_auth_info(error_mode), Extractor);
    let auth_layer = Filter::<Request, BiscuitAuth<_>>::layer(biscuit_auth);

    let (mut service, mut _handle) = mock::spawn_layer::<_, (), _>(auth_layer);
    assert_ready_ok!(service.poll_ready());

    let request = Request(1);
    let response = service.call(request).await;

    let error = response.unwrap_err();
    let error: Box<BiscuitAuthError> = error.downcast().unwrap();
    assert!(error.failure_info().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn dynamic_policy_change() {
    let error_mode = ErrorMode::Secure;
    let biscuit_auth = BiscuitAuth::new(gen_test_auth_info(error_mode), Extractor);

    let auth_layer = Filter::<Request, BiscuitAuth<_>>::layer(biscuit_auth.clone());

    let (mut service, mut _handle) = mock::spawn_layer::<_, (), _>(auth_layer);
    assert_ready_ok!(service.poll_ready());

    let request = Request(1);
    let response = service.call(request).await;

    let error = response.unwrap_err();
    let error: Box<BiscuitAuthError> = error.downcast().unwrap();

    // This error doesn't contain any failure info.
    assert!(error.failure_info().is_none());

    // Change the policy to ErrorMode::Verbose.
    let mut new_auth_info = biscuit_auth.to_auth_info();
    new_auth_info.error_mode = ErrorMode::Verbose;
    biscuit_auth.update(new_auth_info);

    let response = service.call(request).await;

    let error = response.unwrap_err();
    let error: Box<BiscuitAuthError> = error.downcast().unwrap();

    // The new error contains the verification failure info.
    assert!(error.failure_info().is_some());
}
