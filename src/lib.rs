use arc_swap::ArcSwap;
use std::{collections::BTreeMap, fmt, sync::Arc};

use biscuit_auth::{error::Token, Authorizer, Biscuit, PublicKey};

// mod http;

#[derive(Clone)]
pub struct BiscuitAuth<E> {
    auth_info: Arc<ArcSwap<AuthConfig>>,
    extractor: E,
}

impl<E> BiscuitAuth<E> {
    pub fn new(auth_info: AuthConfig, extractor: E) -> Self {
        Self {
            auth_info: Arc::new(ArcSwap::from_pointee(auth_info)),
            extractor,
        }
    }

    pub fn update(&self, auth_info: AuthConfig) {
        self.auth_info.store(Arc::new(auth_info))
    }

    pub fn to_auth_info(&self) -> AuthConfig {
        self.auth_info.load().as_ref().clone()
    }

    pub fn check<R>(&self, request: &R, extractor: &E) -> Result<(), BiscuitAuthError>
    where
        E: AuthExtract<Request = R>,
    {
        let auth_info_guard: arc_swap::Guard<_, _> = self.auth_info.load();
        let auth_info: &AuthConfig = &auth_info_guard;

        // We play some weird error-handling games here so that we don't
        // accidentally emit sensitive information in errors, which are
        // likely to end up in logs somewhere.
        let try_auth = || -> Result<(), BiscuitAuthError> {
            let biscuit = auth_info.biscuit(&extractor.auth_token(request)?)?;

            let mut authorizer = auth_info.authorizer.clone();
            authorizer.add_token(&biscuit)?;

            extractor.extract_context(request, &mut authorizer)?;

            authorizer.authorize()?;

            Ok(())
        };

        try_auth().map_err(|err| match auth_info.error_mode {
            ErrorMode::Secure => BiscuitAuthError::Unknown,
            ErrorMode::Verbose => err,
        })
    }
}

type TowerError = tower::BoxError;

impl<Request, Extract> tower::filter::Predicate<Request> for BiscuitAuth<Extract>
where
    Extract: AuthExtract<Request = Request>,
{
    type Request = Request;

    fn check(&mut self, request: Request) -> Result<Self::Request, TowerError> {
        BiscuitAuth::check(self, &request, &self.extractor)?;
        Ok(request)
    }
}

#[derive(Debug)]
pub enum BiscuitAuthError {
    Unknown,
    Other(tower::BoxError),
    Failure(Token),
}

impl fmt::Display for BiscuitAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BiscuitAuthError::Unknown => f.write_str("unauthorized"),
            BiscuitAuthError::Other(err) => {
                f.write_str("other error: ")?;
                err.fmt(f)
            }
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

pub trait AuthExtract {
    type Request;

    /// How to find the
    fn auth_token(&self, req: &Self::Request) -> Result<Vec<u8>, BiscuitAuthError>;

    /// Use the information in the request to add any relevant infoformation
    /// to the authorizer, such as if the request is a read or write request,
    /// or the specific resource the request is trying to access.
    fn extract_context(
        &self,
        _req: &Self::Request,
        _authorizer: &mut Authorizer,
    ) -> Result<(), Token> {
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

    fn biscuit(&self, token: &[u8]) -> Result<Biscuit, Token> {
        Biscuit::from(token, |id| self.pubkey_by_id(id))
    }

    fn pubkey_by_id(&self, id: Option<u32>) -> PublicKey {
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
