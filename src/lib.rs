use arc_swap::ArcSwap;
use std::{collections::BTreeMap, fmt, sync::Arc};

use biscuit_auth::{error::Token, Authorizer, Biscuit, PublicKey};

#[derive(Clone)]
pub struct BiscuitAuth<E> {
    auth_info: Arc<ArcSwap<AuthInfo>>,
    extractor: E,
}

impl<E> BiscuitAuth<E> {
    pub fn new(auth_info: AuthInfo, extractor: E) -> Self {
        Self {
            auth_info: Arc::new(ArcSwap::from_pointee(auth_info)),
            extractor,
        }
    }

    pub fn update(&self, auth_info: AuthInfo) {
        self.auth_info.store(Arc::new(auth_info))
    }

    pub fn to_auth_info(&self) -> AuthInfo {
        self.auth_info.load().as_ref().clone()
    }

    pub fn check<R>(&self, request: &R, extractor: &E) -> Result<(), BiscuitAuthError>
    where
        E: AuthExtract<Request = R>,
    {
        let auth_info_guard: arc_swap::Guard<_, _> = self.auth_info.load();
        let auth_info: &AuthInfo = &auth_info_guard;

        // We play some weird error-handling games here so that we don't
        // accidentally emit sensitive information in errors, which are
        // likely to end up in logs somewhere.
        let try_auth = || -> Result<(), Token> {
            let biscuit = auth_info.biscuit(&extractor.auth_token(request))?;

            let mut authorizer = auth_info.authorizer.clone();
            authorizer.add_token(&biscuit)?;

            extractor.extract_context(request, &mut authorizer)?;

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
pub struct BiscuitAuthError(Option<Token>);

impl BiscuitAuthError {
    pub fn token(&self) -> Option<&Token> {
        self.0.as_ref()
    }
}

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
    type Request;

    /// How to find the
    fn auth_token(&self, req: &Self::Request) -> Vec<u8>;

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

#[derive(Clone)]
pub struct PubKeys {
    base: PublicKey,
    by_id: BTreeMap<u32, PublicKey>,
}

impl PubKeys {
    pub fn new(base: PublicKey) -> Self {
        Self {
            base,
            by_id: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct AuthInfo {
    pub root_pubkeys: PubKeys,
    pub authorizer: Authorizer<'static>,
    pub error_mode: ErrorMode,
}

impl AuthInfo {
    pub fn new(pubkey: PubKeys, authorizer: Authorizer<'static>, error_mode: ErrorMode) -> Self {
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
