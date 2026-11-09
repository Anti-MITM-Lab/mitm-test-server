//! mitm-test-server —— 反中间人探测蜜罐服务端。
//!
//! 思路：对外伪装成一个普通的 HTTPS 站点。不带暗号就来的连接（扫描器、
//! 中间人代理、爬虫）会被灌入数 MB 无意义数据；带正确暗号的友军探针则拿到
//! 一个干净的 200 响应，用来验证链路上是否存在 TLS 中间人。
//!
//! 模块划分：
//!
//! | 模块 | 职责 |
//! |------|------|
//! | `config` | 配置加载、校验与默认模板 |
//! | `server` | 监听、握手、鉴权、投毒主流程 |
//! | `http` | 极简 HTTP/1.x 请求头解析与常量时间比较 |
//! | `payload` | 诱饵响应（指纹、正文、节奏） |
//! | `db` | SQLite 威胁情报落库 |
//! | `report` | AbuseIPDB 自动举报 |
//! | `logging` | 日志输出 |
//!
//! 使用方式见 `README.md`。

// 日志宏通过 `#[macro_use]` 引入，后续模块可直接使用 `info!` / `warn!` 等。
#[macro_use]
mod logging;

mod config;
mod db;
mod http;
mod payload;
mod report;
mod server;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use crate::db::Database;
use crate::report::Reporter;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("启动失败: {e}");
            ExitCode::FAILURE
        }
    }
}

/// 组装各组件并进入服务循环。
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load_or_create()?;
    info!("配置就绪，监听目标 {}", config.bind_addr);

    let database = Database::open(&config.db_path)?;
    info!("威胁情报库已就绪: {}", config.db_path);

    if config
        .abuseipdb_api_key
        .as_deref()
        .is_some_and(|key| !key.trim().is_empty())
    {
        info!("已配置 AbuseIPDB API Key，未授权流量将自动举报");
    } else {
        warn!("未配置 abuseipdb_api_key，自动举报功能关闭");
    }

    let reporter = Reporter::new(
        config.abuseipdb_api_key.clone(),
        Duration::from_secs(config.report_cooldown_secs),
    );

    server::run(Arc::new(config), database, reporter).await
}
