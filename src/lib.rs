mod common;
mod config;
mod proxy;
mod stats;

use crate::config::{parse_proxyip_pool, pick_sticky, Config, Protocol, ProxyEntry, ProxyType};
use crate::proxy::*;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde_json::json;
use uuid::Uuid;
use worker::*;

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    let uuid = env
        .var("UUID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    let main_page_url = env.var("MAIN_PAGE_URL").map(|x|x.to_string()).unwrap();
    let sub_page_url = env.var("SUB_PAGE_URL").map(|x|x.to_string()).unwrap();

    let default_proxyip = env.var("PROXYIP").map(|x| x.to_string()).unwrap_or_default();
    let proxy_pool = parse_proxyip_pool(&default_proxyip);

    let config = Config {
        uuid,
        host: host.clone(),
        proxy_addr: String::new(),
        proxy_port: 0,
        proxy_type: ProxyType::Direct,
        proxy_credentials: None,
        proxy_pool,
        env: env.clone(),
        main_page_url,
        sub_page_url,
    };

    Router::with_data(config)
        .on_async("/", fe)
        .on_async("/sub", sub)
        .on("/link", link)
        .on_async("/api/stats", stats)
        .on_async("/vless", tunnel_vless)
        .on_async("/vmess", tunnel_vmess)
        .on_async("/trojan", tunnel_trojan)
        .run(req, env)
        .await
}

async fn get_response_from_url(url: String) -> Result<Response> {
    let req = Fetch::Url(Url::parse(url.as_str())?);
    let mut res = req.send().await?;
    Response::from_html(res.text().await?)
}

async fn fe(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.main_page_url).await
}

async fn sub(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.sub_page_url).await
}

async fn stats(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    let namespace = cx.data.env.durable_object("DurableObject")?;
    let id = namespace.id_from_name("global")?;
    let stub = id.get_stub()?;
    stub.fetch_with_str("https://do/stats").await
}

async fn tunnel(req: Request, mut cx: RouteContext<Config>, protocol: Protocol) -> Result<Response> {
    let mut override_pool: Option<Vec<ProxyEntry>> = None;
    let mut sticky_override: Option<String> = None;
    if let Ok(url) = req.url() {
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "proxyip" => override_pool = Some(parse_proxyip_pool(&value)),
                "sid" => sticky_override = Some(value.into_owned()),
                _ => {}
            }
        }
    }

    let default_pool = cx.data.proxy_pool.as_slice();
    let pool: &[ProxyEntry] = match &override_pool {
        Some(p) => p.as_slice(),
        None => default_pool,
    };

    let sticky_id = sticky_override.unwrap_or_else(|| client_ip(&req));
    let sticky_key = format!("{}:{}", sticky_id, protocol_tag(protocol));

    let picked = pick_sticky(pool, &sticky_key).cloned();
    if let Some(entry) = picked {
        cx.data.proxy_type = entry.proxy_type;
        cx.data.proxy_addr = entry.addr;
        cx.data.proxy_port = entry.port;
        cx.data.proxy_credentials = entry.credentials;
    }

    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade == "websocket".to_string() {
        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;
    
        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().unwrap();
            if let Err(e) = ProxyStream::new(cx.data, &server, events).process(protocol).await {
                console_error!("[tunnel]: {}", e);
            }
        });
    
        Response::from_websocket(client)
    } else {
        Response::from_html("hi from wasm!")
    }
}

fn client_ip(req: &Request) -> String {
    req.headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn protocol_tag(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Vless => "vless",
        Protocol::Vmess => "vmess",
        Protocol::Trojan => "trojan",
    }
}

async fn tunnel_vless(req: Request, cx: RouteContext<Config>) -> Result<Response> {
    tunnel(req, cx, Protocol::Vless).await
}

async fn tunnel_vmess(req: Request, cx: RouteContext<Config>) -> Result<Response> {
    tunnel(req, cx, Protocol::Vmess).await
}

async fn tunnel_trojan(req: Request, cx: RouteContext<Config>) -> Result<Response> {
    tunnel(req, cx, Protocol::Trojan).await
}

fn link(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    let host = cx.data.host.to_string();
    let uuid = cx.data.uuid.to_string();

    let vmess_link = {
        let config = json!({
            "ps": "siren vmess",
            "v": "2",
            "add": host,
            "port": "443",
            "id": uuid,
            "aid": "0",
            "scy": "zero",
            "net": "ws",
            "type": "none",
            "host": host,
            "path": "/vmess",
            "tls": "tls",
            "sni": host,
            "alpn": ""}
        );
        format!("vmess://{}", URL_SAFE.encode(config.to_string()))
    };
    let vless_link = format!("vless://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2Fvless&security=tls&sni={host}#siren vless");
    let trojan_link = format!("trojan://{uuid}@{host}:443?encryption=none&type=ws&host={host}&path=%2Ftrojan&security=tls&sni={host}#siren trojan");

    Response::from_body(ResponseBody::Body(format!("{vmess_link}\n{vless_link}\n{trojan_link}").into()))
}
