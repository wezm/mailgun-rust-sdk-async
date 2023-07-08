use crate::endpoints::{
    get_bounces::{GetBouncesParamList, GetBouncesResponse},
    get_complaints::{GetComplaintsParamList, GetComplaintsResponse},
    get_events::{GetEventsParamList, GetEventsResponse},
    get_stats::{GetStatsParamList, GetStatsResponse},
    get_unsubscribes::{GetUnsubscribesParamList, GetUnsubscribesResponse},
    get_whitelists::{GetWhitelistsParamList, GetWhitelistsResponse},
    send_message::{SendMessageParamList, SendMessageResponse},
};
use crate::param::{Param, ParamError};
use crate::MAILGUN_API_BASE;
use thiserror::Error;

#[derive(Debug)]
pub struct Client {
    client: reqwest::Client,
    api_key: String,
    domain: String,
}

impl Client {
    /// Create a new client.
    pub fn new(api_key: &str, domain: &str) -> Self {
        Self::new_with_client(api_key, domain, reqwest::Client::new())
    }

    /// Create a new client using the supplied reqwest client.
    pub fn new_with_client(api_key: &str, domain: &str, client: reqwest::Client) -> Self {
        Self {
            api_key: api_key.to_string(),
            domain: domain.to_string(),
            client,
        }
    }

    /// Make an API call from a URL.
    ///
    /// This will primarily be used with pagination URLs.
    pub async fn call<T>(&self, url: &str) -> Result<T, ClientError>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self
            .client
            .get(url)
            .basic_auth("api", Some(&self.api_key))
            .send()
            .await?;

        let status = response.status();
        let raw = response
            .text()
            .await
            .map_err(|error| ClientError::ReadResponse(error))?;

        if status != 200 {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&raw) {
                return Err(ClientError::ApiError(error));
            }

            return Err(ClientError::HttpError(status.as_u16(), raw));
        }

        serde_json::from_str(&raw).map_err(|error| ClientError::ParseResponse(error))
    }

    /// View all bounces.
    ///
    /// [Mailgun Documentation](https://documentation.mailgun.com/en/latest/api-suppressions.html#bounces)
    pub async fn get_bounces(
        &self,
        params: GetBouncesParamList,
    ) -> Result<GetBouncesResponse, ClientError> {
        let url = format!("{}/{}/bounces", MAILGUN_API_BASE, self.domain);

        let mut request = self.client.get(&url).basic_auth("api", Some(&self.api_key));

        for (key, value) in params.values.iter().map(|param| param.as_tuple()) {
            request = request.query(&[(&key, &value)]);
        }

        let response = request.send().await?;
        let status = response.status();

        let raw = response
            .text()
            .await
            .map_err(|error| ClientError::ReadResponse(error))?;

        if status != 200 {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&raw) {
                return Err(ClientError::ApiError(error));
            }

            return Err(ClientError::HttpError(status.as_u16(), raw));
        }

        serde_json::from_str(&raw).map_err(|error| ClientError::ParseResponse(error))
    }

    /// View all complaints.
    ///
    /// [Mailgun Documentation](https://documentation.mailgun.com/en/latest/api-suppressions.html#view-all-complaints)
    pub async fn get_complaints(
        &self,
        params: GetComplaintsParamList,
    ) -> Result<GetComplaintsResponse, ClientError> {
        let url = format!("{}/{}/complaints", MAILGUN_API_BASE, self.domain);

        let mut request = self.client.get(&url).basic_auth("api", Some(&self.api_key));

        for (key, value) in params.values.iter().map(|param| param.as_tuple()) {
            request = request.query(&[(&key, &value)]);
        }

        let response = request.send().await?;
        let status = response.status();

        let raw = response
            .text()
            .await
            .map_err(|error| ClientError::ReadResponse(error))?;

        if status != 200 {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&raw) {
                return Err(ClientError::ApiError(error));
            }

            return Err(ClientError::HttpError(status.as_u16(), raw));
        }

        serde_json::from_str(&raw).map_err(|error| ClientError::ParseResponse(error))
    }

    /// View all events.
    ///
    /// [Mailgun Documentation](https://documentation.mailgun.com/en/latest/api-events.html)
    pub async fn get_events(
        &self,
        params: GetEventsParamList<'_>,
    ) -> Result<GetEventsResponse, ClientError> {
        let url = format!("{}/{}/events", MAILGUN_API_BASE, self.domain);

        let mut request = self.client.get(&url).basic_auth("api", Some(&self.api_key));

        for (key, value) in params.values.iter().map(|param| param.as_tuple()) {
            request = request.query(&[(&key, &value)]);
        }

        let response = request.send().await?;
        let status = response.status();

        let raw = response
            .text()
            .await
            .map_err(|error| ClientError::ReadResponse(error))?;

        if status != 200 {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&raw) {
                return Err(ClientError::ApiError(error));
            }

            return Err(ClientError::HttpError(status.as_u16(), raw));
        }

        serde_json::from_str(&raw).map_err(|error| ClientError::ParseResponse(error))
    }

    /// View all stats.
    ///
    /// [Mailgun Documentation](https://documentation.mailgun.com/en/latest/api-stats.html)
    pub async fn get_stats(
        &self,
        params: GetStatsParamList<'_>,
    ) -> Result<GetStatsResponse, ClientError> {
        let url = format!("{}/{}/stats/total", MAILGUN_API_BASE, self.domain);

        let mut request = self.client.get(&url).basic_auth("api", Some(&self.api_key));

        for (key, value) in params.values.iter().map(|param| param.as_tuple()) {
            request = request.query(&[(&key, &value)]);
        }

        let response = request.send().await?;
        let status = response.status();

        let raw = response
            .text()
            .await
            .map_err(|error| ClientError::ReadResponse(error))?;

        if status != 200 {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&raw) {
                return Err(ClientError::ApiError(error));
            }

            return Err(ClientError::HttpError(status.as_u16(), raw));
        }

        serde_json::from_str(&raw).map_err(|error| ClientError::ParseResponse(error))
    }

    /// View all unsubscribes.
    ///
    /// [Mailgun Documentation](https://documentation.mailgun.com/en/latest/api-suppressions.html#unsubscribes)
    pub async fn get_unsubscribes(
        &self,
        params: GetUnsubscribesParamList,
    ) -> Result<GetUnsubscribesResponse, ClientError> {
        let url = format!("{}/{}/unsubscribes", MAILGUN_API_BASE, self.domain);

        let mut request = self.client.get(&url).basic_auth("api", Some(&self.api_key));

        for (key, value) in params.values.iter().map(|param| param.as_tuple()) {
            request = request.query(&[(&key, &value)]);
        }

        let response = request.send().await?;
        let status = response.status();

        let raw = response
            .text()
            .await
            .map_err(|error| ClientError::ReadResponse(error))?;

        if status != 200 {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&raw) {
                return Err(ClientError::ApiError(error));
            }

            return Err(ClientError::HttpError(status.as_u16(), raw));
        }

        serde_json::from_str(&raw).map_err(|error| ClientError::ParseResponse(error))
    }

    /// View all whitelist records.
    ///
    /// [Mailgun Documentation](https://documentation.mailgun.com/en/latest/api-suppressions.html#view-all-whitelist-records)
    pub async fn get_whitelists(
        &self,
        params: GetWhitelistsParamList,
    ) -> Result<GetWhitelistsResponse, ClientError> {
        let url = format!("{}/{}/whitelists", MAILGUN_API_BASE, self.domain);

        let mut request = self.client.get(&url).basic_auth("api", Some(&self.api_key));

        for (key, value) in params.values.iter().map(|param| param.as_tuple()) {
            request = request.query(&[(&key, &value)]);
        }

        let response = request.send().await?;
        let status = response.status();

        let raw = response
            .text()
            .await
            .map_err(|error| ClientError::ReadResponse(error))?;

        if status != 200 {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&raw) {
                return Err(ClientError::ApiError(error));
            }

            return Err(ClientError::HttpError(status.as_u16(), raw));
        }

        serde_json::from_str(&raw).map_err(|error| ClientError::ParseResponse(error))
    }

    pub async fn send_message(
        &self,
        params: SendMessageParamList<'_, String>,
    ) -> Result<SendMessageResponse, ClientError> {
        self.send_message_vars(params).await
    }

    pub async fn send_message_vars<T: serde::Serialize>(
        &self,
        params: SendMessageParamList<'_, T>,
    ) -> Result<SendMessageResponse, ClientError> {
        let url = format!("{}/{}/messages", MAILGUN_API_BASE, self.domain);

        let mut request = self
            .client
            .post(&url)
            .basic_auth("api", Some(&self.api_key));

        for param in params.values {
            let (key, value) = param.try_as_tuple()?;

            // TODO: If key == "attachment", set content-type to "multipart/form-data".

            request = request.query(&[(&key, &value)]);
        }

        let response = request.send().await?;
        let status = response.status();

        let raw = response
            .text()
            .await
            .map_err(|error| ClientError::ReadResponse(error))?;

        if status != 200 {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&raw) {
                return Err(ClientError::ApiError(error));
            }

            return Err(ClientError::HttpError(status.as_u16(), raw));
        }

        serde_json::from_str(&raw).map_err(|error| ClientError::ParseResponse(error))
    }
}

#[derive(Debug, Deserialize, Error)]
#[serde(untagged)]
pub enum ErrorResponse {
    #[error("With error: {error}")]
    WithError {
        #[serde(alias = "Error")]
        error: String,
    },
    #[error("With message: {message}")]
    WithMessage { message: String },
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Received an error message from the server: {0}")]
    ApiError(#[from] ErrorResponse),

    #[error("Received a {0} HTTP status code: {1}")]
    HttpError(u16, String),

    #[error("HTTP request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("A request parameter is invalid: {0}")]
    ParamError(#[from] ParamError),

    #[error("Failed to parse response string: {0}")]
    ParseResponse(serde_json::error::Error),

    #[error("Failed to read response string: {0}")]
    ReadResponse(reqwest::Error),
}

#[cfg(test)]
mod tests {
    use crate::endpoints::{
        get_bounces::{GetBouncesParam, GetBouncesParamList},
        get_complaints::{GetComplaintsParam, GetComplaintsParamList},
        get_events::{GetEventsParam, GetEventsParamList, GetEventsResponse},
        get_stats::GetStatsParamList,
        get_unsubscribes::{GetUnsubscribesParam, GetUnsubscribesParamList},
        get_whitelists::{GetWhitelistsParam, GetWhitelistsParamList},
        send_message::{SendMessageParam, SendMessageParamList},
    };
    use crate::param::ParamList;
    use crate::test_util::test_client;

    #[test]
    fn call() {
        let (_config, rt, client) = test_client();

        let all = rt
            .block_on(client.get_events(GetEventsParamList::default()))
            .unwrap();
        let _: GetEventsResponse = rt.block_on(client.call(&all.paging.next)).unwrap();
    }

    #[test]
    fn get_bounces() {
        let (_config, rt, client) = test_client();

        let _all = rt
            .block_on(client.get_bounces(GetBouncesParamList::default()))
            .unwrap();

        let params = GetBouncesParamList::default().add(GetBouncesParam::Limit(1));
        let _single = rt.block_on(client.get_bounces(params)).unwrap();

        // TODO: Test the response.
    }

    #[test]
    fn get_complains() {
        let (_config, rt, client) = test_client();

        let _all = rt
            .block_on(client.get_complaints(GetComplaintsParamList::default()))
            .unwrap();

        let params = GetComplaintsParamList::default().add(GetComplaintsParam::Limit(1));
        let _single = rt.block_on(client.get_complaints(params)).unwrap();

        // TODO: Test the response.
    }

    #[test]
    fn get_events() {
        let (_config, rt, client) = test_client();

        let _all = rt
            .block_on(client.get_events(GetEventsParamList::default()))
            .unwrap();

        let params = GetEventsParamList::default().add(GetEventsParam::Limit(1));
        let _single = rt.block_on(client.get_events(params)).unwrap();
    }

    #[test]
    fn get_stats() {
        let (_config, rt, client) = test_client();

        let _response = rt
            .block_on(client.get_stats(GetStatsParamList::default()))
            .unwrap();

        // TODO: Test the response.
    }

    #[test]
    fn get_unsubscribes() {
        let (_config, rt, client) = test_client();

        let _all = rt
            .block_on(client.get_unsubscribes(GetUnsubscribesParamList::default()))
            .unwrap();

        let params = GetUnsubscribesParamList::default().add(GetUnsubscribesParam::Limit(1));
        let _single = rt.block_on(client.get_unsubscribes(params)).unwrap();

        // TODO: Test the response.
    }

    #[test]
    fn get_whitelists() {
        let (_config, rt, client) = test_client();

        let _all = rt
            .block_on(client.get_whitelists(GetWhitelistsParamList::default()))
            .unwrap();

        let params = GetWhitelistsParamList::default().add(GetWhitelistsParam::Limit(1));
        let _single = rt.block_on(client.get_whitelists(params)).unwrap();

        // TODO: Test the response.
    }

    #[test]
    fn send_message() {
        let (config, rt, client) = test_client();

        let from = format!("Test <test@{}>", &config.mailgun_domain);
        let params = SendMessageParamList::default()
            .add(SendMessageParam::Text("test message"))
            .add(SendMessageParam::To("wes@wezm.net"))
            .add(SendMessageParam::From(&from))
            .add(SendMessageParam::OTestMode(true));

        rt.block_on(client.send_message(params)).unwrap();
    }
}
