use arc_swap::ArcSwap;
use std::{fmt, sync::Arc};

use biscuit_auth::{error::Token, Authorizer, Biscuit, PublicKey};

pub trait RequestExtract<R> {
    fn extract(&self, request: &R, authorizer: &mut Authorizer) -> Result<(), Token>;
}

#[derive(Debug, Clone)]
pub struct BiscuitAuth<Extractor> {
    auth_info: Arc<ArcSwap<AuthInfo>>,
    extractor: Extractor,
}

impl<Request, Extractor> tower::filter::Predicate<Request> for BiscuitAuth<Extractor>
where
    Request: AuthToken,
{
    type Request = Request;

    fn check(&mut self, request: Request) -> Result<Self::Request, tower::BoxError> {
        let biscuit = {
            let auth_info_guard: arc_swap::Guard<_, _> = self.auth_info.load();
            let auth_info: &AuthInfo = &auth_info_guard;
            Biscuit::from(request.auth_token(), |_root_id| *auth_info.root_pubkey())?
        };

        let mut authorizer = Authorizer::new()?;
        self.extractor.extract(&request, &mut authorizer)?;
        authorizer.add_token(&biscuit)?;

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
pub struct AuthInfo {
    root_pubkeys: PublicKey,
    authorizor_serialized: Box<[u8]>,
}

impl AuthInfo {
    fn root_pubkey(&self) -> &PublicKey {
        &self.root_pubkeys
    }

    fn authorizer_serialized(&self) -> &[u8] {
        &self.authorizor_serialized
    }
}
