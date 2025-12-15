//! HTTP(S) client traits for hanling API calls

pub mod error;
pub mod url_params;

use google_cloud_auth::credentials::CredentialsProvider;
use bytes::Bytes;
use error::{ApiClientError, FireBaseAPIErrorResponse};
use error_stack::{Report, ResultExt};
use http::Method;
use serde::{Serialize, de::DeserializeOwned};
use std::future::Future;
use std::iter::Iterator;
use url_params::UrlParams;
use crate::credentials::get_headers;

pub trait ApiHttpClient: Send + Sync + 'static {
    fn send_request<ResponseT: Send + DeserializeOwned>(
        &self,
        uri: String,
        method: Method,
    ) -> impl Future<Output = Result<ResponseT, Report<ApiClientError>>> + Send;

    fn send_request_with_params<
        ResponseT: DeserializeOwned + Send,
        ParamsT: Iterator<Item = (String, String)> + Send,
    >(
        &self,
        uri: String,
        params: ParamsT,
        method: Method,
    ) -> impl Future<Output = Result<ResponseT, Report<ApiClientError>>> + Send;

    fn send_request_body<RequestT: Serialize + Send, ResponseT: DeserializeOwned + Send>(
        &self,
        uri: String,
        method: Method,
        request_body: RequestT,
    ) -> impl Future<Output = Result<ResponseT, Report<ApiClientError>>> + Send;

    fn send_request_body_get_bytes<RequestT: Serialize + Send>(
        &self,
        uri: String,
        method: Method,
        request_body: RequestT,
    ) -> impl Future<Output = Result<Bytes, Report<ApiClientError>>> + Send;

    fn send_request_body_empty_response<RequestT: Serialize + Send>(
        &self,
        uri: String,
        method: Method,
        request_body: RequestT,
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
}

impl<C: CredentialsProvider> ReqwestApiClient<C> {
    pub fn new(client: reqwest::Client, credentials: C) -> Self {
        Self {
            client,
            credentials,
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
        body: Option<B>,
    ) -> Result<reqwest::Response, Report<ApiClientError>> {
        self.client
            .request(method, url)
            .headers(
                get_headers(&self.credentials).await
                    .change_context(ApiClientError::FailedToSendRequest)?
            )
            .set_request_body(body)
            .send()
            .await
            .change_context(ApiClientError::FailedToSendRequest)
    }
}

impl<C: CredentialsProvider + Send + Sync + 'static> ApiHttpClient for ReqwestApiClient<C> {
    async fn send_request<ResponseT: Send + DeserializeOwned>(
        &self,
        url: String,
        method: Method,
    ) -> Result<ResponseT, Report<ApiClientError>> {
        Self::handle_response(
            self.handle_request::<()>(&url, method, None)
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
    ) -> Result<ResponseT, Report<ApiClientError>> {
        let url: String = url + &params.into_url_params();
        Self::handle_response(
            self.handle_request::<()>(&url, method, None)
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
    ) -> Result<ResponseT, Report<ApiClientError>> {
        Self::handle_response(
            self.handle_request(&url, method, Some(request_body))
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
    ) -> Result<Bytes, Report<ApiClientError>> {
        Self::handle_response(
            self.handle_request(&url, method,Some(request_body))
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
    ) -> Result<(), Report<ApiClientError>> {
        Self::handle_response(
            self.handle_request(&url, method, Some(request_body))
                .await?,
        )
        .await?;

        Ok(())
    }
}
