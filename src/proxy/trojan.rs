use super::ProxyStream;
use tokio::io::AsyncReadExt;
use crate::common::{parse_addr, parse_port};
use worker::*;

impl <'a> ProxyStream<'a> {
    pub async fn process_trojan(&mut self) -> Result<()> {
        // ignore user_id
        let mut _user_id = [0u8; 56];
        self.read_exact(&mut _user_id).await?;

        // remove crlf
        self.read_u16().await?;
        
        // read instruction
        let network_type = self.read_u8().await?;
        let is_tcp = network_type == 1;

        // read port and address
        let remote_addr = parse_addr(self).await?;
        let remote_port = parse_port(self).await?;

        // remove crlf
        self.read_u16().await?;

        if is_tcp {
            let addr_pool = [
                (remote_addr.clone(), remote_port),
                (self.config.proxy_addr.clone(), self.config.proxy_port)
            ];

            // send header
            for (target_addr, target_port) in addr_pool {
                if let Err(e) = self.handle_tcp_outbound(target_addr, target_port).await {
                    console_error!("error handling tcp: {}", e)
                }
            }
        } else {
            if let Err(e) = self.handle_udp_outbound().await {
                console_error!("error handling udp: {}", e)
            }
        }

        Ok(())
    }
}