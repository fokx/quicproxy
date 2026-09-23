pub mod salamander;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationConfig {
    #[serde(default)]
    pub enabled: bool,

    pub key: String,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key: String::new(),
        }
    }
}
