//! AbuseIPDB 自动反向举报。
//!
//! 三条原则：
//!
//! 1. **绝不阻塞投毒**：举报在独立任务里跑，失败只记日志；
//! 2. **别把配额浪费在同一个 IP 上**：AbuseIPDB 对同一 IP 有 15 分钟
//!    的重复举报限制，这里用冷却表做去重（默认 1 小时）；
//! 3. **只举报未授权流量**：友军探针不举报。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const REPORT_ENDPOINT: &str = "https://api.abuseipdb.com/api/v2/report";
/// AbuseIPDB 对 comment 字段的长度限制是 1024 字符。
const MAX_COMMENT_CHARS: usize = 1024;

/// 线程安全的举报器，可自由跨任务克隆。
#[derive(Clone)]
pub struct Reporter {
    client: reqwest::Client,
    api_key: Option<String>,
    cooldown: Duration,
    /// 最近一次举报时间，用于按 IP 去重。
    recent: Arc<Mutex<HashMap<IpAddr, Instant>>>,
}

impl Reporter {
    /// 创建举报器。`api_key` 为空或全空白时自动视为关闭。
    pub fn new(api_key: Option<String>, cooldown: Duration) -> Self {
        let api_key = api_key.filter(|key| !key.trim().is_empty());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("mitm-test-server/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();

        Self {
            client,
            api_key,
            cooldown,
            recent: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 是否配置了 API Key。
    pub fn enabled(&self) -> bool {
        self.api_key.is_some()
    }

    /// 后台异步举报。命中冷却、未配置 Key 或已关闭时直接返回。
    pub fn report_later(&self, ip: IpAddr, detail: String) {
        let Some(api_key) = self.api_key.clone() else {
            return;
        };
        if !self.claim(ip) {
            return;
        }

        let client = self.client.clone();
        tokio::spawn(async move {
            if let Err(e) = send_report(&client, &api_key, ip, &detail).await {
                warn!("向 AbuseIPDB 举报 {ip} 失败: {e}");
            }
        });
    }

    /// 抢占某 IP 的举报名额；冷却期内重复触发返回 `false`。
    fn claim(&self, ip: IpAddr) -> bool {
        let mut recent = match self.recent.lock() {
            Ok(guard) => guard,
            // 某个持锁任务 panic 不应让举报功能整体失效。
            Err(poisoned) => poisoned.into_inner(),
        };

        let now = Instant::now();
        if let Some(last) = recent.get(&ip)
            && now.duration_since(*last) < self.cooldown
        {
            return false;
        }

        // 表过大时清理过期条目，避免长时间运行后内存缓慢增长。
        if recent.len() > 4096 {
            recent.retain(|_, seen| now.duration_since(*seen) < self.cooldown);
        }

        recent.insert(ip, now);
        true
    }
}

/// 实际发送举报请求。
async fn send_report(
    client: &reqwest::Client,
    api_key: &str,
    ip: IpAddr,
    detail: &str,
) -> Result<(), String> {
    let ip = ip.to_string();
    let comment: String = format!(
        "Unauthorized TLS probe / MITM honeypot trigger. {}",
        truncate_chars(detail, MAX_COMMENT_CHARS - 64)
    );

    let response = client
        .post(REPORT_ENDPOINT)
        .header("Key", api_key)
        .header("Accept", "application/json")
        // 14 = Port Scan, 21 = Web App Attack
        .form(&[
            ("ip", ip.as_str()),
            ("categories", "14,21"),
            ("comment", comment.as_str()),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    match response.status().as_u16() {
        200 => {
            success!("已将 {ip} 举报至 AbuseIPDB");
            Ok(())
        }
        429 => Err("请求过于频繁（HTTP 429），已触发 AbuseIPDB 速率限制".to_string()),
        status => Err(format!("HTTP {status}")),
    }
}

/// 按字符（而非字节）截断，避免把 UTF-8 切成半个字符。
fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut truncated: String = text.chars().take(max_chars).collect();
    truncated.push('…');
    truncated
}
