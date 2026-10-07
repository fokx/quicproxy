use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

pub const DEFAULT_GEOIP_FILENAME: &str = "geoip.dat";
pub const DEFAULT_GEOIP_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat";
pub const DEFAULT_GEOSITE_FILENAME: &str = "geosite.dat";
pub const DEFAULT_GEOSITE_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(7 * 24 * 3600); // 7 days

// Protobuf definitions matching v2geo.proto

#[derive(Clone, PartialEq, prost::Message)]
pub struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GeoIp {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub inverse_match: bool,
    #[prost(bytes = "vec", tag = "4")]
    pub resource_hash: Vec<u8>,
    #[prost(string, tag = "5")]
    pub code: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIp>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DomainAttribute {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(oneof = "domain_attribute::TypedValue", tags = "2, 3")]
    pub typed_value: Option<domain_attribute::TypedValue>,
}

pub mod domain_attribute {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum TypedValue {
        #[prost(bool, tag = "2")]
        BoolValue(bool),
        #[prost(int64, tag = "3")]
        IntValue(i64),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    Plain = 0,
    Regex = 1,
    RootDomain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(message, repeated, tag = "3")]
    pub attribute: Vec<DomainAttribute>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
    #[prost(bytes = "vec", tag = "3")]
    pub resource_hash: Vec<u8>,
    #[prost(string, tag = "4")]
    pub code: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoSite>,
}

pub fn load_geoip_from_bytes(data: &[u8]) -> Result<HashMap<String, GeoIp>> {
    use prost::Message;
    let list = GeoIpList::decode(data).context("Failed to decode GeoIPList protobuf")?;
    let mut map = HashMap::with_capacity(list.entry.len());
    for entry in list.entry {
        let key = if !entry.country_code.is_empty() {
            entry.country_code.to_ascii_lowercase()
        } else {
            entry.code.to_ascii_lowercase()
        };
        map.insert(key, entry);
    }
    Ok(map)
}

pub fn load_geosite_from_bytes(data: &[u8]) -> Result<HashMap<String, GeoSite>> {
    use prost::Message;
    let list = GeoSiteList::decode(data).context("Failed to decode GeoSiteList protobuf")?;
    let mut map = HashMap::with_capacity(list.entry.len());
    for entry in list.entry {
        let key = if !entry.country_code.is_empty() {
            entry.country_code.to_ascii_lowercase()
        } else {
            entry.code.to_ascii_lowercase()
        };
        map.insert(key, entry);
    }
    Ok(map)
}

pub fn load_geoip_file<P: AsRef<Path>>(path: P) -> Result<HashMap<String, GeoIp>> {
    let bs = fs::read(path.as_ref())
        .with_context(|| format!("Failed to read GeoIP file from {}", path.as_ref().display()))?;
    load_geoip_from_bytes(&bs)
}

pub fn load_geosite_file<P: AsRef<Path>>(path: P) -> Result<HashMap<String, GeoSite>> {
    let bs = fs::read(path.as_ref()).with_context(|| {
        format!(
            "Failed to read GeoSite file from {}",
            path.as_ref().display()
        )
    })?;
    load_geosite_from_bytes(&bs)
}

pub trait GeoLoader: Send + Sync {
    fn load_geoip<'a>(
        &'a self,
    ) -> crate::outbound::BoxFuture<'a, Result<Arc<HashMap<String, GeoIp>>>>;
    fn load_geosite<'a>(
        &'a self,
    ) -> crate::outbound::BoxFuture<'a, Result<Arc<HashMap<String, GeoSite>>>>;
}

pub struct DefaultGeoLoader {
    geoip_path: PathBuf,
    geosite_path: PathBuf,
    auto_dl_geoip: bool,
    auto_dl_geosite: bool,
    update_interval: Duration,
    geoip_cache: OnceLock<Arc<HashMap<String, GeoIp>>>,
    geosite_cache: OnceLock<Arc<HashMap<String, GeoSite>>>,
}

impl DefaultGeoLoader {
    pub fn new(
        geoip_path: Option<PathBuf>,
        geosite_path: Option<PathBuf>,
        update_interval: Option<Duration>,
    ) -> Self {
        let auto_dl_geoip = geoip_path.is_none();
        let auto_dl_geosite = geosite_path.is_none();
        Self {
            geoip_path: geoip_path.unwrap_or_else(|| PathBuf::from(DEFAULT_GEOIP_FILENAME)),
            geosite_path: geosite_path.unwrap_or_else(|| PathBuf::from(DEFAULT_GEOSITE_FILENAME)),
            auto_dl_geoip,
            auto_dl_geosite,
            update_interval: update_interval.unwrap_or(DEFAULT_UPDATE_INTERVAL),
            geoip_cache: OnceLock::new(),
            geosite_cache: OnceLock::new(),
        }
    }

    fn should_download(&self, path: &Path) -> bool {
        match fs::metadata(path) {
            Ok(meta) => {
                if meta.len() == 0 {
                    return true;
                }
                if let Ok(modified) = meta.modified() {
                    if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                        return elapsed > self.update_interval;
                    }
                }
                false
            }
            Err(_) => true,
        }
    }

    async fn ensure_file(&self, path: &Path, url: &str, is_geoip: bool) -> Result<()> {
        if !self.should_download(path) {
            return Ok(());
        }

        info!(
            "Downloading geo database from {} to {}",
            url,
            path.display()
        );

        let download_result = async {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .context("Failed to create HTTP client for geo download")?;

            let resp = client
                .get(url)
                .send()
                .await
                .context("HTTP download failed")?;
            if !resp.status().is_success() {
                bail!("HTTP download returned status {}", resp.status());
            }

            let bytes = resp.bytes().await.context("Failed to read response body")?;

            // Verify integrity by decoding before writing to target path
            if is_geoip {
                let _ = load_geoip_from_bytes(&bytes)
                    .context("Integrity check failed: invalid GeoIP protobuf data")?;
            } else {
                let _ = load_geosite_from_bytes(&bytes)
                    .context("Integrity check failed: invalid GeoSite protobuf data")?;
            }

            // Write to temp file then rename
            let temp_path = path.with_extension(format!("tmp.{}", rand::random::<u32>()));
            fs::write(&temp_path, &bytes)
                .with_context(|| format!("Failed to write to temp file {}", temp_path.display()))?;
            fs::rename(&temp_path, path)
                .with_context(|| format!("Failed to rename temp file to {}", path.display()))?;

            info!("Successfully saved geo database to {}", path.display());
            Ok::<(), anyhow::Error>(())
        }
        .await;

        if let Err(e) = download_result {
            warn!("Failed to download geo database from {}: {:#}", url, e);
            if path.exists() {
                warn!("Falling back to existing local file at {}", path.display());
                return Ok(());
            }
            return Err(e);
        }

        Ok(())
    }
}

impl GeoLoader for DefaultGeoLoader {
    fn load_geoip<'a>(
        &'a self,
    ) -> crate::outbound::BoxFuture<'a, Result<Arc<HashMap<String, GeoIp>>>> {
        Box::pin(async move {
            if let Some(cached) = self.geoip_cache.get() {
                return Ok(Arc::clone(cached));
            }

            if self.auto_dl_geoip {
                if !self.should_download(&self.geoip_path) {
                    if let Ok(map) = load_geoip_file(&self.geoip_path) {
                        let arc = Arc::new(map);
                        let _ = self.geoip_cache.set(Arc::clone(&arc));
                        return Ok(arc);
                    }
                }
                self.ensure_file(&self.geoip_path, DEFAULT_GEOIP_URL, true)
                    .await?;
            }

            let map = load_geoip_file(&self.geoip_path)?;
            let arc = Arc::new(map);
            let _ = self.geoip_cache.set(Arc::clone(&arc));
            Ok(arc)
        })
    }

    fn load_geosite<'a>(
        &'a self,
    ) -> crate::outbound::BoxFuture<'a, Result<Arc<HashMap<String, GeoSite>>>> {
        Box::pin(async move {
            if let Some(cached) = self.geosite_cache.get() {
                return Ok(Arc::clone(cached));
            }

            if self.auto_dl_geosite {
                if !self.should_download(&self.geosite_path) {
                    if let Ok(map) = load_geosite_file(&self.geosite_path) {
                        let arc = Arc::new(map);
                        let _ = self.geosite_cache.set(Arc::clone(&arc));
                        return Ok(arc);
                    }
                }
                self.ensure_file(&self.geosite_path, DEFAULT_GEOSITE_URL, false)
                    .await?;
            }

            let map = load_geosite_file(&self.geosite_path)?;
            let arc = Arc::new(map);
            let _ = self.geosite_cache.set(Arc::clone(&arc));
            Ok(arc)
        })
    }
}
