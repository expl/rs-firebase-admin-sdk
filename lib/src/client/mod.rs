//! HTTP(S) client traits for hanling API calls

pub mod error;
pub mod url_params;

use crate::credentials::Credentials;
use bytes::Bytes;
use error::{ApiClientError, FireBaseAPIErrorResponse};
use error_stack::{Report, ResultExt};
use http::Method;
use serde::{de::DeserializeOwned, Serialize};
use std::future::Future;
use std::iter::Iterator;
use url_params::UrlParams;

pub trait ApiHttpClient: Send + Sync + 'static {
    fn send_request<ResponseT: Send + DeserializeOwned>(
        &self,
        uri: String,
        method: Method,
        oauth_scopes: &[&str],
    ) -> impl Future<Output = Result<ResponseT, Report<ApiClientError>>> + Send;

    fn send_request_with_params<
        ResponseT: DeserializeOwned + Send,
        ParamsT: Iterator<Item = (String, String)> + Send,
    >(
        &self,
        uri: String,
        params: ParamsT,
        method: Method,
        oauth_scopes: &[&str],
    ) -> impl Future<Output = Result<ResponseT, Report<ApiClientError>>> + Send;

    fn send_request_body<RequestT: Serialize + Send, ResponseT: DeserializeOwned + Send>(
        &self,
        uri: String,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> impl Future<Output = Result<ResponseT, Report<ApiClientError>>> + Send;

    fn send_request_body_get_bytes<RequestT: Serialize + Send>(
        &self,
        uri: String,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> impl Future<Output = Result<Bytes, Report<ApiClientError>>> + Send;

    fn send_request_body_empty_response<RequestT: Serialize + Send>(
        &self,
        uri: String,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> impl Future<Output = Result<(), Report<ApiClientError>>> + Send;
}

trait SetReqBody<T: Serialize> {
    fn set_request_body(self, body: Option<T>) -> Self;
}

impl<T: Serialize> SetReqBody<T> for reqwest::RequestBuilder {
    fn set_request_body(self, body: Option<T>) -> Self {
        if let Some(body) = body {
            return self.json(&body);
        }

        self
    }
}

pub struct ReqwestApiClient<C> {
    client: reqwest::Client,
    credentials: C,
    project_id: String,
}

impl<C: Credentials> ReqwestApiClient<C> {
    pub fn new(client: reqwest::Client, credentials: C, project_id: String) -> Self {
        Self {
            client,
            credentials,
            project_id,
        }
    }

    async fn handle_response(
        resp: reqwest::Response,
    ) -> Result<reqwest::Response, Report<ApiClientError>> {
        if resp.status() != reqwest::StatusCode::OK {
            let error_response: FireBaseAPIErrorResponse = resp
                .json()
                .await
                .change_context(ApiClientError::FailedToReceiveResponse)?;

            return Err(Report::new(ApiClientError::ServerError(
                error_response.error,
            )));
        }

        Ok(resp)
    }

    async fn handle_request<B: Serialize + Send>(
        &self,
        url: &str,
        method: Method,
        oauth_scopes: &[&str],
        body: Option<B>,
    ) -> Result<reqwest::Response, Report<ApiClientError>> {
        self.client
            .request(method, url)
            .bearer_auth(
                self.credentials
                    .get_access_token(oauth_scopes)
                    .await
                    .change_context(ApiClientError::FailedToSendRequest)?,
            )
            .set_request_body(body)
            .header("x-goog-user-project", &self.project_id)
            .send()
            .await
            .change_context(ApiClientError::FailedToSendRequest)
    }
}

impl<C: Credentials> ApiHttpClient for ReqwestApiClient<C> {
    async fn send_request<ResponseT: Send + DeserializeOwned>(
        &self,
        url: String,
        method: Method,
        oauth_scopes: &[&str],
    ) -> Result<ResponseT, Report<ApiClientError>> {
        Self::handle_response(
            self.handle_request::<()>(&url, method, oauth_scopes, None)
                .await?,
        )
        .await?
        .json()
        .await
        .change_context(ApiClientError::FailedToReceiveResponse)
    }

    async fn send_request_with_params<
        ResponseT: DeserializeOwned + Send,
        ParamsT: Iterator<Item = (String, String)> + Send,
    >(
        &self,
        url: String,
        params: ParamsT,
        method: Method,
        oauth_scopes: &[&str],
    ) -> Result<ResponseT, Report<ApiClientError>> {
        let url: String = url + &params.into_url_params();
        Self::handle_response(
            self.handle_request::<()>(&url, method, oauth_scopes, None)
                .await?,
        )
        .await?
        .json()
        .await
        .change_context(ApiClientError::FailedToReceiveResponse)
    }

    async fn send_request_body<RequestT: Serialize + Send, ResponseT: DeserializeOwned + Send>(
        &self,
        url: String,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> Result<ResponseT, Report<ApiClientError>> {
        Self::handle_response(
            self.handle_request(&url, method, oauth_scopes, Some(request_body))
                .await?,
        )
        .await?
        .json()
        .await
        .change_context(ApiClientError::FailedToReceiveResponse)
    }

    async fn send_request_body_get_bytes<RequestT: Serialize + Send>(
        &self,
        url: String,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> Result<Bytes, Report<ApiClientError>> {
        Self::handle_response(
            self.handle_request(&url, method, oauth_scopes, Some(request_body))
                .await?,
        )
        .await?
        .bytes()
        .await
        .change_context(ApiClientError::FailedToReceiveResponse)
    }

    async fn send_request_body_empty_response<RequestT: Serialize + Send>(
        &self,
        url: String,
        method: Method,
        request_body: RequestT,
        oauth_scopes: &[&str],
    ) -> Result<(), Report<ApiClientError>> {
        Self::handle_response(
            self.handle_request(&url, method, oauth_scopes, Some(request_body))
                .await?,
        )
        .await?;

        Ok(())
    }
}
