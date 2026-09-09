use worker::*;

#[durable_object]
pub struct Stats {
    state: State,
}

#[durable_object]
impl DurableObject for Stats {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&mut self, req: Request) -> Result<Response> {
        let url = req.url()?;

        match url.path() {
            "/stats" => self.get_stats().await,
            "/report" => self.report(&url).await,
            _ => Response::ok("not found"),
        }
    }
}

impl Stats {
    async fn get_stats(&mut self) -> Result<Response> {
        let mut storage = self.state.storage();

        let first_seen: u64 = match storage.get::<u64>("first_seen").await {
            Ok(v) => v,
            Err(_) => {
                let now = Date::now().as_millis();
                storage.put("first_seen", now).await?;
                now
            }
        };
        let up_bytes: u64 = storage.get::<u64>("up_bytes").await.unwrap_or(0);
        let down_bytes: u64 = storage.get::<u64>("down_bytes").await.unwrap_or(0);

        let now = Date::now().as_millis();
        let uptime_seconds = now.saturating_sub(first_seen) / 1000;

        let body = serde_json::json!({
            "uptime_seconds": uptime_seconds,
            "first_seen": first_seen,
            "up_bytes": up_bytes,
            "down_bytes": down_bytes,
        })
        .to_string();

        Response::from_body(ResponseBody::Body(body.into()))
    }

    async fn report(&mut self, url: &Url) -> Result<Response> {
        let mut up: u64 = 0;
        let mut down: u64 = 0;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "up" => up = value.parse().unwrap_or(0),
                "down" => down = value.parse().unwrap_or(0),
                _ => {}
            }
        }

        let mut storage = self.state.storage();
        let up_bytes: u64 = storage.get::<u64>("up_bytes").await.unwrap_or(0);
        let down_bytes: u64 = storage.get::<u64>("down_bytes").await.unwrap_or(0);

        storage.put("up_bytes", up_bytes.saturating_add(up)).await?;
        storage.put("down_bytes", down_bytes.saturating_add(down)).await?;

        Response::ok("ok")
    }
}
