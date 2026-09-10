use worker::*;

#[durable_object]
pub struct Stats {
    sql: SqlStorage,
}

impl DurableObject for Stats {
    fn new(state: State, _env: Env) -> Self {
        let sql = state.storage().sql();

        sql.exec(
            "CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY,
                first_seen INTEGER NOT NULL,
                up_bytes INTEGER NOT NULL,
                down_bytes INTEGER NOT NULL
            );",
            None,
        )
        .expect("create stats table");

        let now = Date::now().as_millis() as i64;
        sql.exec(
            "INSERT OR IGNORE INTO stats (id, first_seen, up_bytes, down_bytes) VALUES (1, ?, 0, 0);",
            vec![now.into()],
        )
        .expect("seed stats row");

        Self { sql }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;

        match url.path() {
            "/stats" => self.get_stats(),
            "/report" => self.report(&url),
            _ => Response::ok("not found"),
        }
    }
}

impl Stats {
    fn get_stats(&self) -> Result<Response> {
        #[derive(serde::Deserialize)]
        struct Row {
            first_seen: i64,
            up_bytes: i64,
            down_bytes: i64,
        }

        let rows: Vec<Row> = self
            .sql
            .exec("SELECT first_seen, up_bytes, down_bytes FROM stats WHERE id = 1;", None)?
            .to_array()?;

        let now = Date::now().as_millis() as i64;
        let (first_seen, up_bytes, down_bytes) = match rows.into_iter().next() {
            Some(r) => (r.first_seen, r.up_bytes, r.down_bytes),
            None => (now, 0, 0),
        };

        let uptime_seconds = (now - first_seen).max(0) / 1000;

        let body = serde_json::json!({
            "uptime_seconds": uptime_seconds,
            "first_seen": first_seen,
            "up_bytes": up_bytes,
            "down_bytes": down_bytes,
        })
        .to_string();

        Response::from_body(ResponseBody::Body(body.into()))
    }

    fn report(&self, url: &Url) -> Result<Response> {
        let mut up: i64 = 0;
        let mut down: i64 = 0;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "up" => up = value.parse().unwrap_or(0),
                "down" => down = value.parse().unwrap_or(0),
                _ => {}
            }
        }

        self.sql.exec(
            "UPDATE stats SET up_bytes = up_bytes + ?, down_bytes = down_bytes + ? WHERE id = 1;",
            vec![up.into(), down.into()],
        )?;

        Response::ok("ok")
    }
}
