use std::{
    fmt,
    sync::{Arc, RwLock},
};

use biscuit_auth::{Authorizer, Biscuit, PublicKey};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
pub struct BiscuitAuth {
    auth_info: Arc<RwLock<AuthInfo>>,
}

impl<Request> tower::filter::Predicate<Request> for BiscuitAuth
where
    Request: AuthToken,
{
    type Request = Request;

    fn check(&mut self, request: Request) -> Result<Self::Request, tower::BoxError> {
        // None of the data inside the RwLock is mutable anyway, even after
        // acquiring the lock. It doesn't seem like there's much chance that
        // poisoning could introduce invalid state.
        let auth_info = match self.auth_info.read() {
            Ok(auth_info) => auth_info,
            Err(poison) => poison.into_inner(),
        };

        let biscuit = Biscuit::from(request.auth_token(), |_root_id| *auth_info.root_pubkey())?;
        auth_info.authorize(&biscuit)?;

        Ok(request)
    }
}

// TODO: Store more info here? Maybe the reason for failure?
#[derive(Clone, Debug)]
pub struct BiscuitAuthError;

impl fmt::Display for BiscuitAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("couldn't authorize biscuit")
    }
}

pub trait AuthToken {
    fn auth_token(&self) -> &[u8];
}

#[derive(Debug, Clone)]
struct AuthInfo {
    root_pubkeys: Arc<PublicKey>,
    authorizor_serialized: Arc<[u8]>,
}

impl AuthInfo {
    fn root_pubkey(&self) -> &PublicKey {
        &self.root_pubkeys
    }

    fn authorizer_serialized(&self) -> &[u8] {
        &self.authorizor_serialized
    }

    fn authorize(&self, biscuit: &Biscuit) -> Result<usize, biscuit_auth::error::Token> {
        let mut authorizer = Authorizer::from(self.authorizer_serialized())?;
        authorizer.add_token(biscuit)?;
        authorizer.authorize()
    }
}
