//! 配置文件的加载、校验与默认模板生成。
//!
//! 配置文件名固定为进程工作目录下的 `server-config.toml`。约定：
//!
//! * 文件不存在 → 写入一份带注释的默认模板并继续启动；
//! * 文件存在但无法解析 → 直接报错退出（绝不静默回退到默认口令，
//!   否则一次笔误就会让蜜罐用错误口令把友军也一起投毒）；
//! * 使用 `#[serde(default)]`，因此新增字段对旧配置文件保持向后兼容。

use serde::{Deserialize, Serialize};

/// 配置文件名（相对进程当前工作目录）。
pub const CONFIG_FILE: &str = "server-config.toml";

/// 默认友军暗号。若配置里仍在使用它，启动时会给出安全警告。
pub const DEFAULT_AUTH_TOKEN: &str = "my_secret_antimtm_token";

/// 服务端全部可调参数。
///
/// 字段平铺（不分子表）是为了兼容 0.7 及更早版本的配置文件。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// TLS 监听地址，例如 `0.0.0.0:8443`。
    pub bind_addr: String,
    /// 证书链（PEM）路径。
    pub cert_path: String,
    /// 私钥（PEM）路径。
    pub key_path: String,
    /// 友军暗号；请求头 `X-Probe-Token`、`Authorization: Bearer` 或
    /// 查询参数 `?token=` 任意一处匹配即放行。
    pub auth_token: String,
    /// SQLite 威胁情报库路径。
    pub db_path: String,
    /// 单次投毒的最小字节数。
    pub min_garbage_bytes: usize,
    /// 单次投毒的最大字节数。
    pub max_garbage_bytes: usize,
    /// 分块基准大小（实际每块会再加 0~2048 字节抖动）。
    pub chunk_size: usize,
    /// 读取 HTTP 请求头的超时（秒），防 Slowloris。
    pub header_timeout_secs: u64,
    /// TLS 握手超时（秒），防半开连接堆积。
    pub handshake_timeout_secs: u64,
    /// 单次投毒的最长持续时间（秒），`0` 表示不限制。
    pub poison_deadline_secs: u64,
    /// gzip 炸弹模式的出现概率（百分比，0~100）。`0` 表示关闭。
    ///
    /// 开启后按该概率发送"压缩很小、解压极大"的响应，把解压开销转移给探测方。
    pub gzip_bomb_ratio: u32,
    /// gzip 炸弹解压后的目标大小（MiB）。
    pub gzip_bomb_mib: u64,
    /// 单条连接最多处理几个请求（1 表示不复用连接）。
    pub keep_alive_max_requests: usize,
    /// 并发连接上限，超出后直接丢弃新连接以保护文件描述符。
    pub max_connections: usize,
    /// 单个来源 IP 的并发连接上限，`0` 表示不限制。
    ///
    /// 防止一个扫描器占用全部连接槽位并吃满出口带宽。
    pub max_conn_per_ip: usize,
    /// 同一来源 IP 的 AbuseIPDB 举报冷却时间（秒）。
    pub report_cooldown_secs: u64,
    /// AbuseIPDB API Key；留空则关闭自动举报。
    pub abuseipdb_api_key: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8443".to_string(),
            cert_path: "cert.pem".to_string(),
            key_path: "key.pem".to_string(),
            auth_token: DEFAULT_AUTH_TOKEN.to_string(),
            db_path: "mitm_intel.db".to_string(),
            min_garbage_bytes: 1_500_000,
            max_garbage_bytes: 8_000_000,
            chunk_size: 8192,
            header_timeout_secs: 8,
            handshake_timeout_secs: 10,
            poison_deadline_secs: 600,
            gzip_bomb_ratio: 0,
            gzip_bomb_mib: 256,
            keep_alive_max_requests: 1,
            max_connections: 512,
            max_conn_per_ip: 32,
            report_cooldown_secs: 3600,
            abuseipdb_api_key: None,
        }
    }
}

impl AppConfig {
    /// 加载配置；文件缺失时生成模板。解析或校验失败时返回可读错误。
    pub fn load_or_create() -> Result<Self, String> {
        match std::fs::read_to_string(CONFIG_FILE) {
            Ok(text) => {
                let config: AppConfig = toml::from_str(&text)
                    .map_err(|e| format!("配置文件 {CONFIG_FILE} 解析失败: {e}"))?;
                config.validate()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let config = AppConfig::default();
                config.write_template()?;
                Ok(config)
            }
            Err(e) => Err(format!("无法读取配置文件 {CONFIG_FILE}: {e}")),
        }
    }

    /// 只读取已存在的配置，不生成模板。
    ///
    /// 供 `--check` 与 SIGHUP 热加载使用：配置缺失时应当报错，而不是悄悄写一份默认值。
    pub fn load_existing() -> Result<Self, String> {
        let text = std::fs::read_to_string(CONFIG_FILE)
            .map_err(|e| format!("无法读取配置文件 {CONFIG_FILE}: {e}"))?;
        let config: AppConfig =
            toml::from_str(&text).map_err(|e| format!("配置文件 {CONFIG_FILE} 解析失败: {e}"))?;
        config.validate()
    }

    /// 校验并就地修正不合理取值，避免运行期出现除零、空块等怪异行为。
    fn validate(mut self) -> Result<Self, String> {
        self.auth_token = self.auth_token.trim().to_string();
        if self.auth_token.is_empty() {
            return Err("auth_token 不能为空".to_string());
        }

        if self.min_garbage_bytes == 0 {
            return Err("min_garbage_bytes 必须大于 0".to_string());
        }
        if self.min_garbage_bytes > self.max_garbage_bytes {
            return Err(format!(
                "min_garbage_bytes({}) 不能大于 max_garbage_bytes({})",
                self.min_garbage_bytes, self.max_garbage_bytes
            ));
        }
        if !(512..=1_048_576).contains(&self.chunk_size) {
            return Err("chunk_size 必须落在 512..=1048576 之间".to_string());
        }
        if self.max_connections == 0 {
            return Err("max_connections 必须大于 0".to_string());
        }
        if self.header_timeout_secs == 0 {
            return Err("header_timeout_secs 必须大于 0".to_string());
        }
        if self.handshake_timeout_secs == 0 {
            return Err("handshake_timeout_secs 必须大于 0".to_string());
        }
        if self.keep_alive_max_requests == 0 {
            return Err("keep_alive_max_requests 必须大于等于 1".to_string());
        }
        if self.gzip_bomb_ratio > 100 {
            return Err("gzip_bomb_ratio 必须落在 0..=100 之间".to_string());
        }
        if self.gzip_bomb_ratio > 0 && !(1..=4096).contains(&self.gzip_bomb_mib) {
            return Err("gzip_bomb_mib 必须落在 1..=4096 之间".to_string());
        }

        if self.auth_token == DEFAULT_AUTH_TOKEN {
            warn!("auth_token 仍是默认值，请尽快改成只有自己知道的暗号");
        }
        Ok(self)
    }

    /// 写出默认配置模板（带注释，方便手工编辑）。
    fn write_template(&self) -> Result<(), String> {
        let body = r#"# mitm-test-server 配置文件
# 改完后重启进程生效。本文件默认被 .gitignore 忽略，不要提交真实口令。

# TLS 监听地址
bind_addr = "0.0.0.0:8443"
cert_path = "cert.pem"
key_path = "key.pem"

# 友军暗号：请求头 X-Probe-Token / Authorization: Bearer / ?token= 三选一命中即放行
auth_token = "replace_me_with_a_long_random_secret"

# 威胁情报库
db_path = "mitm_intel.db"

# 投毒规模与节奏
min_garbage_bytes = 1500000
max_garbage_bytes = 8000000
chunk_size = 8192
poison_deadline_secs = 600

# gzip 炸弹：按百分比概率发送"小体积、大解压"的响应（0 = 关闭，100 = 每次都用）
# 注意：会连带消耗中间代理/客户端的 CPU 与内存，请自行评估影响范围
gzip_bomb_ratio = 0
gzip_bomb_mib = 256

# 单连接最多处理几个请求（1 = 不复用连接；>1 时同一连接会被反复投毒）
keep_alive_max_requests = 1

# 连接与超时保护
max_connections = 512
max_conn_per_ip = 32
header_timeout_secs = 8
handshake_timeout_secs = 10

# 自动反向举报（留空则关闭）
abuseipdb_api_key = ""
report_cooldown_secs = 3600
"#;
        std::fs::write(CONFIG_FILE, body)
            .map_err(|e| format!("写入默认配置模板 {CONFIG_FILE} 失败: {e}"))?;
        Ok(())
    }
}
