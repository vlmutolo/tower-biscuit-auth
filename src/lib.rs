use arc_swap::ArcSwap;
use std::{collections::BTreeMap, fmt, sync::Arc};

use biscuit_auth::{error::Token, Authorizer, Biscuit, PublicKey};

pub use auth_handles::AuthHandles;

mod auth_handles;

// TODO: We can probably provide our own "Extension" extractor type so
// that the user just has to add the `tower_biscuit_auth::PassToken` to a
// handler for protection. Then if that function is ever entered, we know
// that the extractor successfully parsed and authorized the request.

#[cfg(feature = "http")]
pub mod http;

type TowerError = tower::BoxError;

#[derive(Clone, Debug)]
pub struct SharedAuth {
    auth_config: Arc<ArcSwap<AuthConfig>>,
}

impl SharedAuth {
    pub fn new(auth_info: AuthConfig) -> Self {
        Self {
            auth_config: Arc::new(ArcSwap::from_pointee(auth_info)),
        }
    }

    pub fn update(&self, auth_info: AuthConfig) {
        self.auth_config.store(Arc::new(auth_info))
    }

    pub fn to_auth_info(&self) -> AuthConfig {
        self.auth_config.load().as_ref().clone()
    }

    pub fn into_predicate<E>(self, extractor: E) -> AuthPredicate<E> {
        AuthPredicate {
            shared_auth: self.clone(),
            extractor,
        }
    }

    pub fn check<R, E>(&self, request: &R, extractor: &E) -> Result<(), BiscuitAuthError>
    where
        E: AuthExtract<R>,
    {
        let auth_config_guard: arc_swap::Guard<_, _> = self.auth_config.load();
        let auth_config: &AuthConfig = &auth_config_guard;

        // We play some weird error-handling games here so that we don't
        // accidentally emit sensitive information in errors, which are
        // likely to end up in logs somewhere.

        let try_auth = || -> Result<(), BiscuitAuthError> {
            let biscuit = &extractor.auth_token(request, auth_config)?;

            let mut authorizer = auth_config.authorizer.clone();

            authorizer.add_token(&biscuit)?;
            extractor.extract_context(request, auth_config, &mut authorizer)?;

            authorizer.authorize()?;

            Ok(())
        };

        try_auth().map_err(|err| match auth_config.error_mode {
            ErrorMode::Secure => BiscuitAuthError::Unknown,
            ErrorMode::Verbose => err,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AuthPredicate<E> {
    shared_auth: SharedAuth,
    extractor: E,
}

impl<Request, Extract> tower::filter::Predicate<Request> for AuthPredicate<Extract>
where
    Extract: AuthExtract<Request>,
{
    type Request = Request;

    fn check(&mut self, request: Request) -> Result<Self::Request, TowerError> {
        self.shared_auth.check(&request, &self.extractor)?;
        Ok(request)
    }
}

#[derive(Debug)]
pub enum BiscuitAuthError {
    Unknown,
    MissingBiscuit,
    Other(tower::BoxError),
    Failure(Token),
}

impl BiscuitAuthError {
    pub fn auth_error(&self) -> Option<&Token> {
        match self {
            Self::Failure(token) => Some(token),
            _ => None,
        }
    }
}

impl fmt::Display for BiscuitAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BiscuitAuthError::Unknown => f.write_str("unauthorized"),
            BiscuitAuthError::Other(err) => {
                f.write_str("other error: ")?;
                err.fmt(f)
            }
            BiscuitAuthError::MissingBiscuit => f.write_str("missing biscuit"),
            BiscuitAuthError::Failure(err_token) => {
                f.write_str("verification failure: ")?;
                err_token.fmt(f)
            }
        }
    }
}

impl std::error::Error for BiscuitAuthError {}

impl From<Token> for BiscuitAuthError {
    fn from(err: Token) -> Self {
        Self::Failure(err)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ErrorMode {
    Secure,
    Verbose,
}

pub trait AuthExtract<Request> {
    /// How to find the
    fn auth_token(&self, req: &Request, config: &AuthConfig) -> Result<Biscuit, BiscuitAuthError>;

    /// Use the information in the request to add any relevant infoformation
    /// to the authorizer, such as if the request is a read or write request,
    /// or the specific resource the request is trying to access.
    fn extract_context(
        &self,
        _req: &Request,
        _config: &AuthConfig,
        _authorizer: &mut Authorizer,
    ) -> Result<(), BiscuitAuthError> {
        Ok(())
    }
}

pub struct AuthContext {}

#[derive(Clone, Debug)]
pub struct RootKeys {
    base: PublicKey,
    by_id: BTreeMap<u32, PublicKey>,
}

impl RootKeys {
    pub fn new(base: PublicKey) -> Self {
        Self {
            base,
            by_id: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct AuthConfig {
    pub root_pubkeys: RootKeys,
    pub authorizer: Authorizer<'static>,
    pub error_mode: ErrorMode,
}

impl AuthConfig {
    pub fn new(pubkey: RootKeys, authorizer: Authorizer<'static>, error_mode: ErrorMode) -> Self {
        Self {
            root_pubkeys: pubkey,
            authorizer,
            error_mode,
        }
    }

    pub fn biscuit(&self, token: &[u8]) -> Result<Biscuit, BiscuitAuthError> {
        Biscuit::from(token, |id| self.pubkey_by_id(id)).map_err(BiscuitAuthError::from)
    }

    pub fn pubkey_by_id(&self, id: Option<u32>) -> PublicKey {
        match id {
            None => self.root_pubkeys.base,
            Some(id) => self
                .root_pubkeys
                .by_id
                .get(&id)
                .copied()
                .unwrap_or(self.root_pubkeys.base),
        }
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Why does this warn here? Can we fix the warning?
        #[allow(dead_code)]
        #[derive(Debug)]
        struct InnerAuthConfig<'a> {
            root_keys: &'a RootKeys,
            error_mode: &'a ErrorMode,
        }

        let inner = InnerAuthConfig {
            root_keys: &self.root_pubkeys,
            error_mode: &self.error_mode,
        };

        inner.fmt(f)
    }
}
