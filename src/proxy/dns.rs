use anyhow::Result;
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use reqwest::Client;

pub async fn doh(req_wireformat: Vec<u8>) -> Result<Bytes> {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/dns-message"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("application/dns-message"));

    let response = Client::new()
        .post("https://cloudflare-dns.com/dns-query")
        .headers(headers)
        .body(req_wireformat)
        .send()
        .await?
        .bytes()
        .await?;

    Ok(response)
}
