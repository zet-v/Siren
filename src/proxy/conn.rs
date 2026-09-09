use crate::config::{Config, Protocol, ProxyType};

use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::{BufMut, BytesMut};
use futures_util::Stream;
use pin_project_lite::pin_project;
use pretty_bytes::converter::convert;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use worker::*;

static MAX_WEBSOCKET_SIZE: usize = 64 * 1024; // 64kb
static MAX_BUFFER_SIZE: usize = 512 * 1024; // 512kb

pin_project! {
    pub struct ProxyStream<'a> {
        pub config: Config,
        pub ws: &'a WebSocket,
        pub buffer: BytesMut,
        #[pin]
        pub events: EventStream<'a>,
    }
}

impl<'a> ProxyStream<'a> {
    pub fn new(config: Config, ws: &'a WebSocket, events: EventStream<'a>) -> Self {
        let buffer = BytesMut::with_capacity(MAX_BUFFER_SIZE);

        Self {
            config,
            ws,
            buffer,
            events,
        }
    }

    pub async fn process(&mut self, protocol: Protocol) -> Result<()> {
        match protocol {
            Protocol::Vless => {
                console_log!("vless connection");
                self.process_vless().await
            }
            Protocol::Vmess => {
                console_log!("vmess connection");
                self.process_vmess().await
            }
            Protocol::Trojan => {
                console_log!("trojan connection");
                self.process_trojan().await
            }
        }
    }

    pub async fn handle_tcp_outbound(&mut self, remote_addr: String, remote_port: u16) -> Result<()> {
        match Self::dial(&remote_addr, remote_port).await {
            Ok(mut socket) => {
                return self.relay(&mut socket, &remote_addr, remote_port).await;
            }
            Err(e) => {
                console_error!("direct connect to {}:{} failed: {}", remote_addr, remote_port, e);
            }
        }

        if self.config.proxy_addr.is_empty() {
            return Err(Error::RustError("direct connection failed and no proxyip is configured".to_string()));
        }

        let proxy_addr = self.config.proxy_addr.clone();
        let proxy_port = self.config.proxy_port;
        let proxy_credentials = self.config.proxy_credentials.clone();

        match self.config.proxy_type {
            ProxyType::Direct => {
                let mut socket = Self::dial(&proxy_addr, proxy_port).await?;
                self.relay(&mut socket, &proxy_addr, proxy_port).await
            }
            ProxyType::Socks5 => {
                let mut socket = Self::dial(&proxy_addr, proxy_port).await?;
                Self::socks5_handshake(&mut socket, &remote_addr, remote_port, &proxy_credentials).await?;
                self.relay(&mut socket, &remote_addr, remote_port).await
            }
            ProxyType::Http => {
                let mut socket = Self::dial(&proxy_addr, proxy_port).await?;
                Self::http_connect_handshake(&mut socket, &remote_addr, remote_port, &proxy_credentials).await?;
                self.relay(&mut socket, &remote_addr, remote_port).await
            }
        }
    }

    async fn dial(addr: &str, port: u16) -> Result<Socket> {
        let mut socket = Socket::builder()
            .connect(addr, port)
            .map_err(|e| Error::RustError(e.to_string()))?;

        socket
            .opened()
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;

        Ok(socket)
    }

    async fn report_stats(env: &Env, up_bytes: u64, down_bytes: u64) -> Result<()> {
        let namespace = env.durable_object("DurableObject")?;
        let id = namespace.id_from_name("global")?;
        let stub = id.get_stub()?;

        let url = format!("https://do/report?up={}&down={}", up_bytes, down_bytes);
        stub.fetch_with_str(&url).await?;

        Ok(())
    }

    async fn relay(&mut self, remote_socket: &mut Socket, addr: &str, port: u16) -> Result<()> {
        let result = tokio::io::copy_bidirectional(self, remote_socket).await;

        if let Ok((a_to_b, b_to_a)) = &result {
            console_log!("copied data via {}:{}, up: {} and dl: {}", addr, port, convert(*a_to_b as f64), convert(*b_to_a as f64));
            if let Err(e) = Self::report_stats(&self.config.env, *a_to_b, *b_to_a).await {
                console_error!("failed to report stats: {}", e);
            }
        }

        result.map(|_| ()).map_err(|e| Error::RustError(e.to_string()))
    }

    async fn socks5_handshake(
        socket: &mut Socket,
        dest_addr: &str,
        dest_port: u16,
        credentials: &Option<(String, String)>,
    ) -> Result<()> {
        let methods: &[u8] = if credentials.is_some() { &[0x00, 0x02] } else { &[0x00] };
        let mut greeting = vec![0x05u8, methods.len() as u8];
        greeting.extend_from_slice(methods);
        socket
            .write_all(&greeting)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;

        let mut method_resp = [0u8; 2];
        socket
            .read_exact(&mut method_resp)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;
        if method_resp[0] != 0x05 {
            return Err(Error::RustError("socks5 proxy sent an invalid greeting reply".to_string()));
        }

        match method_resp[1] {
            0x00 => {}
            0x02 => {
                let (user, pass) = credentials.as_ref().ok_or_else(|| {
                    Error::RustError("socks5 proxy requires username/password authentication".to_string())
                })?;
                if user.len() > 255 || pass.len() > 255 {
                    return Err(Error::RustError("socks5 username/password must each be at most 255 bytes".to_string()));
                }

                let mut auth_req = vec![0x01u8, user.len() as u8];
                auth_req.extend_from_slice(user.as_bytes());
                auth_req.push(pass.len() as u8);
                auth_req.extend_from_slice(pass.as_bytes());
                socket
                    .write_all(&auth_req)
                    .await
                    .map_err(|e| Error::RustError(e.to_string()))?;

                let mut auth_resp = [0u8; 2];
                socket
                    .read_exact(&mut auth_resp)
                    .await
                    .map_err(|e| Error::RustError(e.to_string()))?;
                if auth_resp[1] != 0x00 {
                    return Err(Error::RustError("socks5 proxy authentication failed".to_string()));
                }
            }
            0xFF => return Err(Error::RustError("socks5 proxy rejected all offered auth methods".to_string())),
            other => return Err(Error::RustError(format!("socks5 proxy selected an unsupported auth method ({})", other))),
        }

        let mut connect_req = vec![0x05u8, 0x01, 0x00];
        match dest_addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                connect_req.push(0x01);
                connect_req.extend_from_slice(&ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                connect_req.push(0x04);
                connect_req.extend_from_slice(&ip.octets());
            }
            Err(_) => {
                connect_req.push(0x03);
                connect_req.push(dest_addr.len() as u8);
                connect_req.extend_from_slice(dest_addr.as_bytes());
            }
        }
        connect_req.extend_from_slice(&dest_port.to_be_bytes());

        socket
            .write_all(&connect_req)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;

        let mut reply_head = [0u8; 4];
        socket
            .read_exact(&mut reply_head)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;
        if reply_head[1] != 0x00 {
            return Err(Error::RustError(format!("socks5 proxy refused connection (code {})", reply_head[1])));
        }

        match reply_head[3] {
            0x01 => {
                let mut rest = [0u8; 4 + 2];
                socket.read_exact(&mut rest).await.map_err(|e| Error::RustError(e.to_string()))?;
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                socket.read_exact(&mut len_buf).await.map_err(|e| Error::RustError(e.to_string()))?;
                let mut rest = vec![0u8; len_buf[0] as usize + 2];
                socket.read_exact(&mut rest).await.map_err(|e| Error::RustError(e.to_string()))?;
            }
            0x04 => {
                let mut rest = [0u8; 16 + 2];
                socket.read_exact(&mut rest).await.map_err(|e| Error::RustError(e.to_string()))?;
            }
            _ => return Err(Error::RustError("socks5 proxy returned an invalid address type".to_string())),
        }

        Ok(())
    }

    async fn http_connect_handshake(
        socket: &mut Socket,
        dest_addr: &str,
        dest_port: u16,
        credentials: &Option<(String, String)>,
    ) -> Result<()> {
        let auth_header = match credentials {
            Some((user, pass)) => {
                let token = STANDARD.encode(format!("{}:{}", user, pass));
                format!("Proxy-Authorization: Basic {}\r\n", token)
            }
            None => String::new(),
        };

        let request = format!(
            "CONNECT {addr}:{port} HTTP/1.1\r\nHost: {addr}:{port}\r\n{auth}Proxy-Connection: Keep-Alive\r\n\r\n",
            addr = dest_addr,
            port = dest_port,
            auth = auth_header
        );

        socket
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;

        let mut header = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            let n = socket
                .read(&mut byte)
                .await
                .map_err(|e| Error::RustError(e.to_string()))?;
            if n == 0 {
                return Err(Error::RustError("http proxy closed the connection during CONNECT".to_string()));
            }
            header.push(byte[0]);
            if header.len() >= 4 && &header[header.len() - 4..] == b"\r\n\r\n" {
                break;
            }
            if header.len() > 8192 {
                return Err(Error::RustError("http proxy response header too large".to_string()));
            }
        }

        let status_line = String::from_utf8_lossy(&header);
        let ok = status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200");
        if !ok {
            let first_line = status_line.lines().next().unwrap_or("").to_string();
            return Err(Error::RustError(format!("http proxy CONNECT failed: {}", first_line)));
        }

        Ok(())
    }

    pub async fn handle_udp_outbound(&mut self) -> Result<()> {
        let mut buff = vec![0u8; 65535];

        let n = self.read(&mut buff).await?;
        buff.truncate(n);

        let response = crate::dns::doh(buff)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;

        self.write(&response).await?;
        Ok(())
    }
}

impl<'a> AsyncRead for ProxyStream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let mut this = self.project();

        loop {
            if !this.buffer.is_empty() {
                let size = std::cmp::min(this.buffer.len(), buf.remaining());
                buf.put_slice(&this.buffer.split_to(size));
                return Poll::Ready(Ok(()));
            }

            match this.events.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                    if let Some(data) = msg.bytes() {
                        if data.len() > MAX_WEBSOCKET_SIZE {
                            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "websocket buffer too long")))
                        }

                        if data.len() <= buf.remaining() {
                            buf.put_slice(&data);
                            return Poll::Ready(Ok(()));
                        }

                        if data.len() > MAX_BUFFER_SIZE {
                            console_log!("buffer full, applying backpressure");
                            return Poll::Pending;
                        }

                        this.buffer.put_slice(&data);
                    }
                }
                Poll::Pending => return Poll::Pending,
                _ => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<'a> AsyncWrite for ProxyStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        return Poll::Ready(
            self.ws
                .send_with_bytes(buf)
                .map(|_| buf.len())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        );
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        match self.ws.close(Some(1000), Some("shutdown".to_string())) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
}
