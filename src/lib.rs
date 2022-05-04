use arc_swap::ArcSwap;
use std::{fmt, sync::Arc};

use biscuit_auth::{error::Token, Authorizer, Biscuit, PublicKey};

#[derive(Clone)]
pub struct BiscuitAuth {
    auth_info: Arc<ArcSwap<AuthInfo>>,
}

impl BiscuitAuth {
    pub fn new(auth_info: AuthInfo) -> Self {
        Self {
            auth_info: Arc::new(ArcSwap::from_pointee(auth_info)),
        }
    }

    pub fn update(&self, auth_info: AuthInfo) {
        self.auth_info.store(Arc::new(auth_info))
    }

    pub fn check<R>(&self, request: &R) -> Result<(), BiscuitAuthError>
    where
        R: AuthExtract,
    {
        let auth_info_guard: arc_swap::Guard<_, _> = self.auth_info.load();
        let auth_info: &AuthInfo = &auth_info_guard;

        // We play some weird error-handling games here so that we don't
        // accidentally emit sensitive information in errors, which are
        // likely to end up in logs somewhere.
        let try_auth = || -> Result<(), Token> {
            let biscuit = auth_info.biscuit(request.auth_token())?;

            let mut authorizer = auth_info.authorizer.clone();
            authorizer.add_token(&biscuit)?;

            request.extract_context(&mut authorizer)?;

            authorizer.authorize()?;

            Ok(())
        };

        try_auth().map_err(|token| {
            let error_context = match auth_info.error_mode {
                ErrorMode::Secure => None,
                ErrorMode::Verbose => Some(token),
            };
            BiscuitAuthError(error_context)
        })
    }
}

type TowerError = tower::BoxError;

impl<Request> tower::filter::Predicate<Request> for BiscuitAuth
where
    Request: AuthExtract,
{
    type Request = Request;

    fn check(&mut self, request: Request) -> Result<Self::Request, TowerError> {
        BiscuitAuth::check(self, &request)?;
        Ok(request)
    }
}

#[derive(Debug)]
pub struct BiscuitAuthError(Option<Token>);

impl fmt::Display for BiscuitAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("failed to authorize request")
    }
}

impl std::error::Error for BiscuitAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // TODO: There has to be a better way to do this. It's not
        // wrong. It's just dumb.
        match &self.0 {
            Some(e) => Some(e),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ErrorMode {
    Secure,
    Verbose,
}

pub trait AuthExtract {
    fn auth_token(&self) -> &[u8];

    /// Use the information in the request to add any relevant infoformation
    /// to the authorizer, such as if the request is a read or write request,
    /// or the specific resource the request is trying to access.
    fn extract_context(&self, _authorizer: &mut Authorizer) -> Result<(), Token> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct AuthInfo {
    root_pubkeys: PublicKey,
    authorizer: Authorizer<'static>,
    error_mode: ErrorMode,
}

impl AuthInfo {
    pub fn new(pubkey: PublicKey, authorizer: Authorizer<'static>, error_mode: ErrorMode) -> Self {
        Self {
            root_pubkeys: pubkey,
            authorizer,
            error_mode,
        }
    }

    fn biscuit(&self, token: &[u8]) -> Result<Biscuit, Token> {
        Biscuit::from(token, |_| self.root_pubkeys)
    }
}
