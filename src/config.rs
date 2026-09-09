use uuid::Uuid;
use worker::Env;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProxyType {
    Direct,
    Socks5,
    Http,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
}

#[derive(Clone)]
pub struct ProxyEntry {
    pub proxy_type: ProxyType,
    pub addr: String,
    pub port: u16,
    pub credentials: Option<(String, String)>,
}

pub struct Config {
    pub uuid: Uuid,
    pub host: String,
    pub proxy_addr: String,
    pub proxy_port: u16,
    pub proxy_type: ProxyType,
    pub proxy_credentials: Option<(String, String)>,
    pub proxy_pool: Vec<ProxyEntry>,
    pub env: Env,
    pub main_page_url: String,
    pub sub_page_url: String,
}

pub fn parse_proxyip(raw: &str) -> Option<ProxyEntry> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let (proxy_type, rest) = if let Some(rest) = raw.strip_prefix("socks://") {
        (ProxyType::Socks5, rest)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        (ProxyType::Http, rest)
    } else {
        (ProxyType::Direct, raw)
    };

    let (credentials, hostport) = if proxy_type == ProxyType::Direct {
        (None, rest)
    } else if let Some((userinfo, hostport)) = rest.rsplit_once('@') {
        let (user, pass) = match userinfo.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (userinfo.to_string(), String::new()),
        };
        (Some((user, pass)), hostport)
    } else {
        (None, rest)
    };

    let (addr, port_str) = hostport.rsplit_once(':')?;
    if addr.is_empty() {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;

    Some(ProxyEntry {
        proxy_type,
        addr: addr.to_string(),
        port,
        credentials,
    })
}

pub fn parse_proxyip_pool(raw: &str) -> Vec<ProxyEntry> {
    raw.split(',').filter_map(parse_proxyip).collect()
}

pub fn pick_sticky<'a>(pool: &'a [ProxyEntry], key: &str) -> Option<&'a ProxyEntry> {
    if pool.is_empty() {
        return None;
    }
    let index = (fnv1a_hash(key) as usize) % pool.len();
    pool.get(index)
}

fn fnv1a_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
