use anyhow::{Result, bail};

use super::{AsyncReadWrite, Outbound};
use crate::protocol::TargetAddr;

pub struct RejectOutbound {
    name: String,
}

impl RejectOutbound {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Outbound for RejectOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_reject(&self) -> bool {
        true
    }

    fn tcp_connect<'a>(
        &'a self,
        target: &'a TargetAddr,
    ) -> super::BoxFuture<'a, Result<Box<dyn AsyncReadWrite>>> {
        let target_str = target.to_string();
        Box::pin(async move { bail!("Connection to {} rejected by ACL", target_str) })
    }
}
