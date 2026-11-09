//! 连接处理：TLS 握手 → 读取请求头 → 鉴权 → 放行或投毒。
//!
//! 鉴权与投毒之间没有共享状态，每条连接完全独立；并发上限由 `Semaphore`
//! 控制，防止被海量连接耗尽文件描述符。

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::AppConfig;
use crate::db::{Database, ProbeEvent};
use crate::http::{self, MAX_HEAD_BYTES, RequestHead};
use crate::payload::{self, Plan};
use crate::report::Reporter;

/// 单次写入的超时：对方若长时间不读，说明连接已死或在做流控，直接放弃。
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// 启动服务，直到收到 Ctrl-C / SIGTERM。
pub async fn run(
    config: Arc<AppConfig>,
    db: Database,
    reporter: Reporter,
) -> Result<(), Box<dyn std::error::Error>> {
    let acceptor = load_tls_acceptor(&config)?;
    let listener = TcpListener::bind(&config.bind_addr).await?;
    let local_address = listener.local_addr()?;
    print_banner(&config, local_address, &reporter);

    let permits = Arc::new(Semaphore::new(config.max_connections));
    let active = Arc::new(AtomicU64::new(0));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("收到退出信号，停止接收新连接……");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        // 单次 accept 失败（如瞬时文件描述符不足）不应拖垮整个服务。
                        warn!("accept 失败: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };

                // 用 try_acquire 而不是排队：宁可丢弃新连接，也不让监听队列阻塞。
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!("并发连接已达上限 {}，丢弃来自 {peer} 的连接", config.max_connections);
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                let config = Arc::clone(&config);
                let db = db.clone();
                let reporter = reporter.clone();
                let active = Arc::clone(&active);

                tokio::spawn(async move {
                    active.fetch_add(1, Ordering::Relaxed);
                    handle_connection(stream, peer, &acceptor, &config, &db, &reporter).await;
                    active.fetch_sub(1, Ordering::Relaxed);
                    drop(permit);
                });
            }
        }
    }

    // 给正在投毒的连接最多 5 秒收尾时间。
    for _ in 0..50 {
        if active.load(Ordering::Relaxed) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    info!("服务已退出");
    Ok(())
}

/// 单条连接的完整生命周期。
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: &TlsAcceptor,
    config: &AppConfig,
    db: &Database,
    reporter: &Reporter,
) {
    // 关闭 Nagle：小分块也能立刻发出，节奏更接近真实服务器。
    let _ = stream.set_nodelay(true);

    let mut tls = match tokio::time::timeout(
        Duration::from_secs(config.handshake_timeout_secs),
        acceptor.accept(stream),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            // 明文扫描、错误 SNI、旧版 TLS……都属于正常噪声，仅调试级别记录。
            debug!("{peer} TLS 握手失败（可能是明文/协议不匹配）: {e}");
            return;
        }
        Err(_) => {
            warn!("{peer} TLS 握手超时，已断开（疑似 Slowloris）");
            return;
        }
    };

    let head = match http::read_head(
        &mut tls,
        Duration::from_secs(config.header_timeout_secs),
        MAX_HEAD_BYTES,
    )
    .await
    {
        Ok(head) => head,
        Err(e) => {
            debug!("{peer} 未取得有效请求头: {e}");
            return;
        }
    };

    if head.is_http2_preface() {
        debug!("{peer} 直接发送了 HTTP/2 前言（未走 ALPN），按未授权处理");
    }

    let user_agent = head.user_agent().map(str::to_string);
    let target = Some(head.target.clone());
    let ua_display = user_agent.clone().unwrap_or_else(|| "-".to_string());

    if is_authorized(&head, &config.auth_token) {
        success!("验证通过：{peer} 是友军探针（UA: {ua_display}）");
        let response = authorized_response();
        let _ = tls.write_all(response.as_bytes()).await;
        let _ = tls.shutdown().await;
        db.record(ProbeEvent {
            ip: peer.ip().to_string(),
            port: peer.port(),
            authorized: true,
            action: "Authorized: peaceful pass".to_string(),
            user_agent,
            target,
            payload_kind: Some("none".to_string()),
            bytes_sent: response.len() as u64,
        });
        return;
    }

    warn!(
        "捕获未授权探测节点 {peer}（{} {}，UA: {ua_display}），开始投毒",
        head.method, head.target
    );

    if reporter.enabled() {
        reporter.report_later(
            peer.ip(),
            format!("{peer} {} {} UA={ua_display}", head.method, head.target),
        );
    }

    let plan = payload::plan(config);
    let started = Instant::now();
    let (sent, reason) = poison(&mut tls, &plan, config).await;
    let elapsed = started.elapsed().as_secs_f64();

    info!(
        "投毒结束 {peer} → 已发送 {}（模式 {}，耗时 {elapsed:.1}s，结束原因 {reason}）",
        human_bytes(sent),
        plan.kind.label()
    );

    db.record(ProbeEvent {
        ip: peer.ip().to_string(),
        port: peer.port(),
        authorized: false,
        action: format!("Poisoned with {sent} bytes ({reason})"),
        user_agent,
        target,
        payload_kind: Some(plan.kind.label().to_string()),
        bytes_sent: sent,
    });
}

/// 向未授权连接持续投喂垃圾数据，返回（已发送字节数，结束原因）。
async fn poison<S>(stream: &mut S, plan: &Plan, config: &AppConfig) -> (u64, &'static str)
where
    S: AsyncWrite + Unpin,
{
    if write_all_timeout(stream, plan.head.as_bytes())
        .await
        .is_err()
    {
        return (0, "对方已断开");
    }

    // 单连接硬性时限，避免一条半死连接长期占着投毒任务。
    let deadline = (config.poison_deadline_secs > 0)
        .then(|| tokio::time::Instant::now() + Duration::from_secs(config.poison_deadline_secs));

    let mut sent: u64 = 0;
    let mut first_chunk = true;
    let mut reason = "已完成";

    loop {
        if let Some(deadline) = deadline
            && tokio::time::Instant::now() >= deadline
        {
            reason = "达到时限";
            break;
        }
        if plan.terminate && sent as usize >= plan.body_bytes {
            break;
        }

        let remaining = plan.terminate.then(|| plan.body_bytes - sent as usize);
        let length = payload::next_chunk_len(config, remaining);
        if length == 0 {
            break;
        }

        let body = payload::chunk(plan.kind, length, first_chunk);
        first_chunk = false;

        // 一个分块 = 十六进制长度行 + 正文 + CRLF，三段落任一失败即视为断连。
        let header = format!("{length:x}\r\n");
        let failed = write_all_timeout(stream, header.as_bytes()).await.is_err()
            || write_all_timeout(stream, &body).await.is_err()
            || write_all_timeout(stream, b"\r\n").await.is_err();

        if failed {
            reason = "对方已断开";
            break;
        }
        sent += length as u64;

        tokio::time::sleep(payload::next_delay()).await;
    }

    // 只有正常结束才补终止块；Endless 模式故意不发，让对方一直等下去。
    if plan.terminate {
        let _ = write_all_timeout(stream, b"0\r\n\r\n").await;
    }
    let _ = stream.shutdown().await;
    (sent, reason)
}

/// 带超时的整块写入包装。
async fn write_all_timeout<S>(stream: &mut S, data: &[u8]) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(data)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "写入超时",
        )),
    }
}

/// 判断请求是否携带正确暗号。
///
/// 支持三种传递方式，且全部使用常量时间比较：
/// `X-Probe-Token: <token>`、`Authorization: Bearer <token>`、`?token=<token>`。
fn is_authorized(head: &RequestHead, token: &str) -> bool {
    let expected = token.as_bytes();

    let header_match = head
        .header("x-probe-token")
        .is_some_and(|value| http::constant_time_eq(unquote(value).as_bytes(), expected));
    let query_match = head
        .query_param("token")
        .is_some_and(|value| http::constant_time_eq(value.as_bytes(), expected));
    let bearer_match = head
        .bearer_token()
        .is_some_and(|value| http::constant_time_eq(value.as_bytes(), expected));

    header_match || query_match || bearer_match
}

/// 去掉暗号两侧的空白与可选引号，兼容 `X-Probe-Token: "abc"` 这类写法。
fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').to_string()
}

/// 友军探针收到的响应：短小、可解析，且与投毒响应明显不同。
fn authorized_response() -> String {
    let body = format!(
        "{{\"status\":\"authorized\",\"probe\":\"mitm-test-server\",\"version\":\"{}\"}}",
        env!("CARGO_PKG_VERSION")
    );
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json; charset=UTF-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         X-Probe-Result: authorized\r\n\r\n{}",
        body.len(),
        body
    )
}

/// 加载证书与私钥，构建 TLS acceptor。
fn load_tls_acceptor(config: &AppConfig) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    for path in [&config.cert_path, &config.key_path] {
        if !std::path::Path::new(path).exists() {
            return Err(format!(
                "找不到文件 {path}，请先准备证书/私钥（见 README 的证书生成一节）"
            )
            .into());
        }
    }

    // 显式安装加密后端；重复调用会返回错误，忽略即可。
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert_file = &mut BufReader::new(File::open(&config.cert_path)?);
    let key_file = &mut BufReader::new(File::open(&config.key_path)?);

    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(cert_file).collect::<Result<Vec<_>, _>>()?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(key_file)?.ok_or("私钥文件中没有可用私钥")?;

    let mut tls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    // 只声明 HTTP/1.1：旧版本声明了 h2 却没有实现，会让 h2 客户端卡死。
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// 启动横幅（不打印暗号本身，避免日志泄露口令）。
fn print_banner(config: &AppConfig, local: SocketAddr, reporter: &Reporter) {
    info!(
        "mitm-test-server v{} 已启动，TLS 监听 {local}",
        env!("CARGO_PKG_VERSION")
    );
    info!("友军暗号：X-Probe-Token / Authorization: Bearer / ?token=");
    info!(
        "投毒规模：{} ~ {}，分块基准 {}，单连接时限 {} 秒，并发上限 {}",
        human_bytes(config.min_garbage_bytes as u64),
        human_bytes(config.max_garbage_bytes as u64),
        human_bytes(config.chunk_size as u64),
        config.poison_deadline_secs,
        config.max_connections
    );
    if reporter.enabled() {
        info!(
            "AbuseIPDB 自动举报：已启用（同 IP 冷却 {} 秒）",
            config.report_cooldown_secs
        );
    } else {
        info!("AbuseIPDB 自动举报：未配置 API Key，已关闭");
    }
}

/// 字节数转人类可读形式。
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// 等待 Ctrl-C 或 SIGTERM，用于优雅退出。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
