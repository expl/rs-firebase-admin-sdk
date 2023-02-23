//! HTTP(S) client traits for hanling API calls

pub mod error;
pub mod url_params;

use crate::credentials::Credentials;
use async_trait::async_trait;
use bytes::Bytes;
use error::{ApiClientError, FireBaseAPIErrorResponse};
use error_stack::{IntoReport, Report, ResultExt};
use headers::{ContentType, HeaderMapExt};
use http::{request::Builder, StatusCode, Uri};
use hyper::{
    client::{Client, HttpConnector},
    Body, Method, Request,
};
use hyper_openssl::HttpsConnector;
use serde::{de::DeserializeOwned, Serialize};
use serde_json;
use std::iter::Iterator;
use std::sync::Arc;
use url_params::UrlParams;

pub(crate) fn build_https_client() -> HyperClient {
    let https_connector =
        HttpsConnector::new().expect("Could not construct TLS connector for API client");

    Client::builder().build(https_connector)
}

#[async_trait]
pub trait ApiHttpClient: Send + Sync {
    async fn send_request<ResponseT>(
        &self,
        uri: Uri,
        method: Method,
        oauth_scopes: &[&str],
    ) -> Result<ResponseT, Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        ResponseT: DeserializeOwned + Send + Sync;

    async fn send_request_with_params<ResponseT, ParamsT>(
        &self,
        uri: Uri,
        params: ParamsT,
        method: Method,
        oauth_scopes: &[&str],
    ) -> Result<ResponseT, Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        ResponseT: DeserializeOwned + Send + Sync,
        ParamsT: Iterator<Item = (String, String)> + Send + Sync;

    async fn send_request_body<RequestT, ResponseT>(
        &self,
        uri: Uri,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> Result<ResponseT, Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        RequestT: Serialize + Send + Sync,
        ResponseT: DeserializeOwned + Send + Sync;

    async fn send_request_body_get_bytes<RequestT>(
        &self,
        uri: Uri,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> Result<Bytes, Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        RequestT: Serialize + Send + Sync;

    async fn send_request_body_empty_response<RequestT>(
        &self,
        uri: Uri,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> Result<(), Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        RequestT: Serialize + Send + Sync;
}

pub type HyperClient = Client<HttpsConnector<HttpConnector>>;

pub struct HyperApiClient<CredentialSourceT> {
    http_client: HyperClient,
    credential_source: Arc<CredentialSourceT>,
}

impl<CredentialSourceT> HyperApiClient<CredentialSourceT>
where
    CredentialSourceT: Credentials + Send + Sync + 'static,
{
    pub fn new(credential_source: Arc<CredentialSourceT>) -> Self {
        Self {
            http_client: build_https_client(),
            credential_source,
        }
    }

    fn deserialize_body<ResponseT: DeserializeOwned>(
        body: &Bytes,
    ) -> Result<ResponseT, Report<ApiClientError>> {
        let json_payload_view = std::str::from_utf8(body)
            .into_report()
            .change_context(ApiClientError::FailedToDeserializeResponse)?;

        let response = serde_json::from_str(json_payload_view)
            .into_report()
            .change_context(ApiClientError::FailedToDeserializeResponse)
            .attach_printable_lazy(|| format!("JSON: {json_payload_view}"))?;

        Ok(response)
    }

    async fn handle_response<ResponseT>(
        &self,
        request: Request<Body>,
    ) -> Result<ResponseT, Report<ApiClientError>>
    where
        ResponseT: DeserializeOwned + Send + Sync,
    {
        let response_body = self.handle_byte_response(request).await?;

        Self::deserialize_body(&response_body)
    }

    async fn handle_byte_response(
        &self,
        request: Request<Body>,
    ) -> Result<Bytes, Report<ApiClientError>> {
        let response = self
            .http_client
            .request(request)
            .await
            .into_report()
            .change_context(ApiClientError::FailedToReceiveResponse)?;

        let response_status = response.status();
        let response_body = hyper::body::to_bytes(response.into_body())
            .await
            .into_report()
            .change_context(ApiClientError::FailedToReceiveResponse)?;

        if response_status != StatusCode::OK {
            let error_response: FireBaseAPIErrorResponse = Self::deserialize_body(&response_body)?;
            return Err(Report::new(ApiClientError::ServerError(
                error_response.error,
            )));
        }

        Ok(response_body)
    }
}

#[async_trait]
impl<CredentialSourceT> ApiHttpClient for HyperApiClient<CredentialSourceT>
where
    CredentialSourceT: Credentials + Send + Sync + 'static,
{
    async fn send_request<ResponseT>(
        &self,
        uri: Uri,
        method: Method,
        oauth_scopes: &[&str],
    ) -> Result<ResponseT, Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        ResponseT: DeserializeOwned + Send + Sync,
    {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .set_credentials(&*self.credential_source, oauth_scopes)
            .await?
            .body(Body::empty())
            .into_report()
            .change_context(ApiClientError::FailedToSendRequest)?;

        self.handle_response(request).await
    }

    async fn send_request_with_params<ResponseT, ParamsT>(
        &self,
        uri: Uri,
        params: ParamsT,
        method: Method,
        oauth_scopes: &[&str],
    ) -> Result<ResponseT, Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        ResponseT: DeserializeOwned + Send + Sync,
        ParamsT: Iterator<Item = (String, String)> + Send + Sync,
    {
        let uri_str: String = uri.to_string() + &params.into_url_params();
        let uri = uri_str
            .parse()
            .into_report()
            .change_context(ApiClientError::FailedToSendRequest)?;

        self.send_request(uri, method, oauth_scopes).await
    }

    async fn send_request_body<RequestT, ResponseT>(
        &self,
        uri: Uri,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> Result<ResponseT, Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        RequestT: Serialize + Send + Sync,
        ResponseT: DeserializeOwned + Send + Sync,
    {
        let body: Body = serde_json::to_string(&request_body)
            .into_report()
            .change_context(ApiClientError::FailedToSerializeRequest)?
            .into();

        let request = Request::builder()
            .method(method)
            .uri(uri)
            .set_json_content_type()
            .set_credentials(&*self.credential_source, oauth_scopes)
            .await?
            .body(body)
            .into_report()
            .change_context(ApiClientError::FailedToSendRequest)?;

        self.handle_response(request).await
    }

    async fn send_request_body_get_bytes<RequestT>(
        &self,
        uri: Uri,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> Result<Bytes, Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        RequestT: Serialize + Send + Sync,
    {
        let body: Body = serde_json::to_string(&request_body)
            .into_report()
            .change_context(ApiClientError::FailedToSerializeRequest)?
            .into();

        let request = Request::builder()
            .method(method)
            .uri(uri)
            .set_json_content_type()
            .set_credentials(&*self.credential_source, oauth_scopes)
            .await?
            .body(body)
            .into_report()
            .change_context(ApiClientError::FailedToSendRequest)?;

        self.handle_byte_response(request).await
    }

    async fn send_request_body_empty_response<RequestT>(
        &self,
        uri: Uri,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> Result<(), Report<ApiClientError>>
    where
        Self: Sized + Send + Sync,
        RequestT: Serialize + Send + Sync,
    {
        self.send_request_body_get_bytes(uri, method, request_body, oauth_scopes)
            .await?;

        Ok(())
    }
}

trait SetRequestJsonContentType {
    fn set_json_content_type(self) -> Self;
}

impl SetRequestJsonContentType for Builder {
    fn set_json_content_type(mut self) -> Self {
        if let Some(headers) = self.headers_mut() {
            headers.typed_insert(ContentType::json())
        }

        self
    }
}

#[async_trait]
trait SetRequestCredentials: Sized {
    async fn set_credentials<CredentialsT>(
        self,
        source: &CredentialsT,
        scopes: &[&str],
    ) -> Result<Self, Report<ApiClientError>>
    where
        CredentialsT: Credentials + Send + Sync;
}

#[async_trait]
impl SetRequestCredentials for Builder {
    async fn set_credentials<CredentialsT>(
        mut self,
        source: &CredentialsT,
        scopes: &[&str],
    ) -> Result<Self, Report<ApiClientError>>
    where
        CredentialsT: Credentials + Send + Sync,
    {
        let headers = self
            .headers_mut()
            .ok_or(Report::new(ApiClientError::FailedToSendRequest))?;

        source
            .set_credentials(headers, scopes)
            .await
            .change_context(ApiClientError::FailedToSendRequest)?;

        Ok(self)
    }
}
