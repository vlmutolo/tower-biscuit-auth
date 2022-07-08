use std::marker::PhantomData;

use biscuit_auth::{Authorizer, Biscuit};
use http::Request;

use crate::{AuthConfig, AuthExtract, BiscuitAuthError};

#[derive(Clone)]
pub struct ExtensionBiscuit<T, F> {
    context: F,
    phantom: PhantomData<T>,
}

impl<T, F> ExtensionBiscuit<T, F>
where
    F: Fn(&mut Request<T>, &AuthConfig, &mut Authorizer) -> Result<(), BiscuitAuthError>,
{
    /// The passed function should do two things:
    ///  1. Add the biscuit to the extensions if it's not already there.
    ///  2. Add any requried code to the authorizer.
    pub fn new(context: F) -> Self {
        Self {
            context,
            phantom: PhantomData,
        }
    }
}

impl<T, F> AuthExtract<Request<T>> for ExtensionBiscuit<T, F>
where
    F: Fn(&Request<T>, &AuthConfig, &mut Authorizer) -> Result<(), BiscuitAuthError>,
{
    fn auth_token(
        &self,
        req: &Request<T>,
        _config: &AuthConfig,
    ) -> Result<Biscuit, BiscuitAuthError> {
        req.extensions()
            .get::<Biscuit>()
            .cloned()
            .ok_or(BiscuitAuthError::MissingBiscuit)
    }

    fn extract_context(
        &self,
        req: &Request<T>,
        config: &AuthConfig,
        authorizer: &mut Authorizer,
    ) -> Result<(), BiscuitAuthError> {
        (self.context)(req, config, authorizer)
    }
}
