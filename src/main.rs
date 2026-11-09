//! mitm-test-server —— 反中间人探测蜜罐服务端。
//!
//! 思路：对外伪装成一个普通的 HTTPS 站点。不带暗号就来的连接（扫描器、
//! 中间人代理、爬虫）会被灌入数 MB 无意义数据；带正确暗号的友军探针则拿到
//! 一个干净的 200 响应，用来验证链路上是否存在 TLS 中间人。
//!
//! 命令行：
//!
//! ```text
//! mitm-test-server            正常启动服务
//! mitm-test-server --check    只校验配置/证书/数据库，不监听端口
//! mitm-test-server --version  打印版本
//! mitm-test-server --help     帮助
//! ```
//!
//! 模块划分：
//!
//! | 模块 | 职责 |
//! |------|------|
//! | `config` | 配置加载、校验与默认模板 |
//! | `server` | 监听、握手、鉴权、投毒主流程 |
//! | `http` | 极简 HTTP/1.x 请求头解析与常量时间比较 |
//! | `payload` | 诱饵响应（指纹、正文、节奏、gzip 炸弹） |
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

/// 进程启动后要做的事。
enum Command {
    Serve,
    Check,
    Version,
    Help,
}

#[tokio::main]
async fn main() -> ExitCode {
    let command = match parse_args() {
        Ok(command) => command,
        Err(message) => {
            eprintln!("[-] {message}");
            eprintln!("用法: mitm-test-server [--check|--version|--help]");
            return ExitCode::from(2);
        }
    };

    match command {
        Command::Version => {
            println!("mitm-test-server {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Help => {
            print_help();
            ExitCode::SUCCESS
        }
        Command::Check => match check().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!("自检失败: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Serve => match run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                error!("启动失败: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

/// 解析命令行参数。默认行为是启动服务，保持与 systemd 单元兼容。
fn parse_args() -> Result<Command, String> {
    let mut command = Command::Serve;
    for arg in std::env::args().skip(1) {
        command = match arg.as_str() {
            "--version" | "-V" => Command::Version,
            "--check" => Command::Check,
            "--help" | "-h" => Command::Help,
            other => return Err(format!("未知参数: {other}")),
        };
    }
    Ok(command)
}

fn print_help() {
    println!(
        "mitm-test-server {}\n\
         \n\
         用法: mitm-test-server [选项]\n\
         \n\
         选项:\n\
           (无参数)      启动服务（读取当前目录的 server-config.toml）\n\
           --check       校验配置、证书/私钥与数据库路径后退出，不监听端口\n\
           --version     打印版本\n\
           --help        显示本帮助\n\
         \n\
         运行期信号:\n\
           SIGINT/SIGTERM  优雅退出\n\
           SIGHUP          重新读取 server-config.toml（暗号、阈值等热生效）",
        env!("CARGO_PKG_VERSION")
    );
}

/// 自检：把服务启动前会做的事都做一遍，但不绑定端口。
///
/// 适合改完配置或换证书后先跑一次，避免 systemd 里反复重启才发现问题。
async fn check() -> Result<(), Box<dyn std::error::Error>> {
    info!("配置文件: {}", config::CONFIG_FILE);
    let config = AppConfig::load_existing()?;
    info!("监听地址: {}（仅校验，不实际绑定）", config.bind_addr);
    info!(
        "友军暗号: 已设置（{} 字符）",
        config.auth_token.chars().count()
    );

    server::load_tls_acceptor(&config)?;
    info!("证书与私钥: 可加载（{}）", config.cert_path);

    let database = Database::open(&config.db_path)?;
    info!("数据库: {} 可打开", config.db_path);
    drop(database);

    if config.gzip_bomb_ratio > 0 {
        info!(
            "gzip 炸弹: 启用，解压后约 {} MiB（启动时生成）",
            config.gzip_bomb_mib
        );
    } else {
        info!("gzip 炸弹: 关闭");
    }
    info!(
        "keep-alive: 单连接最多 {} 个请求",
        config.keep_alive_max_requests
    );
    info!("自检通过");
    Ok(())
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
