use thiserror::Error;

#[derive(Error, Debug, Clone)]
#[error("Got invalid API URI")]
pub struct InvalidApiUriError;
