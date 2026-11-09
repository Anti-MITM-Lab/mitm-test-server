//! 连接处理：TLS 握手 → 读取请求头 → 鉴权 → 放行或投毒。
//!
//! 鉴权与投毒之间没有共享状态，每条连接完全独立；并发上限由 `Semaphore`
//! 控制，防止被海量连接耗尽文件描述符。

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::AppConfig;
use crate::db::{Database, ProbeEvent};
use crate::http::{self, HeadError, MAX_HEAD_BYTES, RequestHead};
use crate::payload::{self, GzipBomb, Plan};
use crate::report::Reporter;

/// 单次写入的超时：对方若长时间不读，说明连接已死或在做流控，直接放弃。
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// 单 IP 并发连接计数器。
///
/// 全局 `Semaphore` 只能防止总量失控；单个 IP 仍可以占满全部槽位、吃光出口带宽。
/// 这里按来源 IP 再限一层，超出直接丢弃连接（连 TLS 握手都不做）。
struct IpLimiter {
    limit: AtomicUsize,
    active: std::sync::Mutex<HashMap<IpAddr, usize>>,
}

impl IpLimiter {
    fn new(limit: usize) -> Self {
        Self {
            limit: AtomicUsize::new(limit),
            active: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// SIGHUP 热加载时调整配额；已在连的连接不受影响，新连接立即生效。
    fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    /// 申请一个名额；超过上限返回 `None`。
    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<IpGuard> {
        let limit = self.limit.load(Ordering::Relaxed);
        let mut active = match self.active.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if limit > 0 {
            let count = active.entry(ip).or_insert(0);
            if *count >= limit {
                return None;
            }
            *count += 1;
        }

        Some(IpGuard {
            limiter: Arc::clone(self),
            ip,
            counted: limit > 0,
        })
    }
}

/// 连接结束时自动归还名额。
struct IpGuard {
    limiter: Arc<IpLimiter>,
    ip: IpAddr,
    counted: bool,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let mut active = match self.limiter.active.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let should_remove = match active.get_mut(&self.ip) {
            Some(count) => {
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => false,
        };
        if should_remove {
            active.remove(&self.ip);
        }
    }
}

/// 运行期可热替换的共享状态（SIGHUP 时更新）。
struct SharedState {
    config: RwLock<Arc<AppConfig>>,
    bomb: RwLock<Option<Arc<GzipBomb>>>,
}

impl SharedState {
    fn new(config: Arc<AppConfig>, bomb: Option<Arc<GzipBomb>>) -> Self {
        Self {
            config: RwLock::new(config),
            bomb: RwLock::new(bomb),
        }
    }

    fn config(&self) -> Arc<AppConfig> {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_config(&self, config: AppConfig) {
        *self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(config);
    }

    fn bomb(&self) -> Option<Arc<GzipBomb>> {
        self.bomb
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_bomb(&self, bomb: Option<Arc<GzipBomb>>) {
        *self
            .bomb
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = bomb;
    }
}

/// 启动服务，直到收到 Ctrl-C / SIGTERM。
pub async fn run(
    config: Arc<AppConfig>,
    db: Database,
    mut reporter: Reporter,
) -> Result<(), Box<dyn std::error::Error>> {
    let acceptor = load_tls_acceptor(&config)?;
    let listener = TcpListener::bind(&config.bind_addr).await?;
    let local_address = listener.local_addr()?;

    let mut bomb = None;
    if config.gzip_bomb_ratio > 0 {
        info!(
            "正在生成 gzip 炸弹（解压后约 {} MiB）……",
            config.gzip_bomb_mib
        );
        match build_bomb(config.gzip_bomb_mib).await {
            Some(built) => {
                info!("gzip 炸弹就绪：压缩后 {} KiB", built.data.len() / 1024);
                bomb = Some(Arc::new(built));
            }
            None => warn!("gzip 炸弹生成失败，本次运行不会使用该模式"),
        }
    }

    let state = Arc::new(SharedState::new(Arc::clone(&config), bomb));
    print_banner(&state, &config, local_address, &reporter);

    let permits = Arc::new(Semaphore::new(config.max_connections));
    let per_ip = Arc::new(IpLimiter::new(config.max_conn_per_ip));
    let active = Arc::new(AtomicU64::new(0));

    // SIGHUP → 配置热加载（信号处理任务常驻，避免信号在无处理者时终止进程）。
    let (reload_tx, mut reload_rx) = mpsc::channel::<()>(4);
    spawn_reload_listener(reload_tx);

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("收到退出信号，停止接收新连接……");
                break;
            }
            // 收到 None 表示信号任务已退出，该分支自动失效（不会空转）。
            Some(()) = reload_rx.recv() => {
                reload_config(&state, &per_ip, &mut reporter).await;
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

                // 先看单 IP 配额，再看全局配额：单 IP 超限时连握手都不做。
                let ip_guard = match per_ip.try_acquire(peer.ip()) {
                    Some(guard) => guard,
                    None => {
                        warn!(
                            "单 IP 并发连接已达上限 {}，丢弃来自 {peer} 的连接",
                            config.max_conn_per_ip
                        );
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
                let state = Arc::clone(&state);
                let db = db.clone();
                let reporter = reporter.clone();
                let active = Arc::clone(&active);

                tokio::spawn(async move {
                    active.fetch_add(1, Ordering::Relaxed);
                    handle_connection(stream, peer, &acceptor, &state, &db, &reporter).await;
                    active.fetch_sub(1, Ordering::Relaxed);
                    drop(ip_guard);
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

/// 在阻塞线程池里生成 gzip 炸弹，避免卡住 reactor。
async fn build_bomb(mib: u64) -> Option<GzipBomb> {
    match tokio::task::spawn_blocking(move || payload::build_gzip_bomb(mib)).await {
        Ok(Ok(bomb)) => Some(bomb),
        Ok(Err(e)) => {
            warn!("生成 gzip 炸弹失败: {e}");
            None
        }
        Err(e) => {
            warn!("生成 gzip 炸弹的任务失败: {e}");
            None
        }
    }
}

/// 注册 SIGHUP 监听，转为 channel 消息。
fn spawn_reload_listener(tx: mpsc::Sender<()>) {
    #[cfg(unix)]
    {
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let Ok(mut hangup) = signal(SignalKind::hangup()) else {
                warn!("注册 SIGHUP 失败，热加载不可用");
                return;
            };
            while hangup.recv().await.is_some() {
                if tx.send(()).await.is_err() {
                    break;
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        // Windows 没有 SIGHUP：持有 sender 让接收端永远 pending。
        tokio::spawn(async move {
            let _keep = tx;
            std::future::pending::<()>().await;
        });
    }
}

/// 重新读取配置并应用可热加载的部分；失败时保持旧配置继续服务。
async fn reload_config(
    state: &Arc<SharedState>,
    limiter: &Arc<IpLimiter>,
    reporter: &mut Reporter,
) {
    let new_config = match AppConfig::load_existing() {
        Ok(config) => config,
        Err(e) => {
            error!("配置重载失败，继续使用旧配置: {e}");
            return;
        }
    };
    let old = state.config();

    // 这些字段依赖监听 socket / 证书 / 数据库句柄，只能重启生效。
    for (name, changed) in [
        ("bind_addr", old.bind_addr != new_config.bind_addr),
        ("cert_path", old.cert_path != new_config.cert_path),
        ("key_path", old.key_path != new_config.key_path),
        ("db_path", old.db_path != new_config.db_path),
        (
            "max_connections",
            old.max_connections != new_config.max_connections,
        ),
    ] {
        if changed {
            warn!("{name} 已变更，需要重启服务才能生效");
        }
    }

    let token_changed = old.auth_token != new_config.auth_token;
    let gzip_mib = new_config.gzip_bomb_mib;
    let gzip_enabled = new_config.gzip_bomb_ratio > 0;

    limiter.set_limit(new_config.max_conn_per_ip);
    *reporter = Reporter::new(
        new_config.abuseipdb_api_key.clone(),
        Duration::from_secs(new_config.report_cooldown_secs),
    );
    state.set_config(new_config);

    if gzip_enabled {
        let needs_rebuild = state
            .bomb()
            .map(|bomb| bomb.mib != gzip_mib)
            .unwrap_or(true);
        if needs_rebuild {
            info!("重新生成 gzip 炸弹（解压后约 {gzip_mib} MiB）……");
            state.set_bomb(build_bomb(gzip_mib).await.map(Arc::new));
        }
    } else {
        state.set_bomb(None);
    }

    info!(
        "配置已热加载（暗号{}更新）",
        if token_changed { "已" } else { "未" }
    );
}

/// 单条连接的完整生命周期。
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: &TlsAcceptor,
    state: &Arc<SharedState>,
    db: &Database,
    reporter: &Reporter,
) {
    // 关闭 Nagle：小分块也能立刻发出，节奏更接近真实服务器。
    let _ = stream.set_nodelay(true);

    let boot_config = state.config();
    let mut tls = match tokio::time::timeout(
        Duration::from_secs(boot_config.handshake_timeout_secs),
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

    // keep-alive：同一连接最多处理 `keep_alive_max_requests` 个请求（默认 1）。
    let mut served: usize = 0;
    loop {
        let config = state.config();
        let first_request = served == 0;

        // 解析失败同样投毒：不少扫描器会先发一段非 HTTP 数据探活，或者干脆
        // 发超长/畸形请求头；以前直接关连接等于白送它一次探测机会。
        let head = match http::read_head(
            &mut tls,
            Duration::from_secs(config.header_timeout_secs),
            MAX_HEAD_BYTES,
        )
        .await
        {
            Ok(head) => Some(head),
            Err(e @ HeadError::Eof) => {
                debug!("{peer} 未发送请求就断开: {e}");
                return;
            }
            Err(e) => {
                if !first_request {
                    debug!("{peer} 后续请求读取失败（{e}），结束连接");
                    return;
                }
                debug!("{peer} 请求头无效（{e}），转为直接投毒");
                None
            }
        };

        if let Some(head) = &head
            && head.is_http2_preface()
        {
            debug!("{peer} 直接发送了 HTTP/2 前言（未走 ALPN），按未授权处理");
        }

        let user_agent = head
            .as_ref()
            .and_then(|head| head.user_agent())
            .map(str::to_string);
        let ua_display = user_agent.clone().unwrap_or_else(|| "-".to_string());
        // 落库/上报/日志统一用脱敏后的目标，避免把 `?token=` 里的暗号写进磁盘或第三方。
        let target = head.as_ref().map(|head| http::redact_target(&head.target));
        let target_display = target.clone().unwrap_or_else(|| "-".to_string());
        let method = head
            .as_ref()
            .map(|head| head.method.as_str())
            .unwrap_or("-");

        if head
            .as_ref()
            .is_some_and(|head| is_authorized(head, &config.auth_token))
        {
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

        if head.is_none() {
            warn!("捕获未完成 HTTP 请求的探测节点 {peer}（UA: {ua_display}），直接投毒");
        } else {
            warn!(
                "捕获未授权探测节点 {peer}（{method} {target_display}，UA: {ua_display}），开始投毒"
            );
        }

        if reporter.enabled() {
            reporter.report_later(
                peer.ip(),
                format!("{peer} {method} {target_display} UA={ua_display}"),
            );
        }

        let plan = payload::plan(&config, state.bomb().as_deref());
        let started = Instant::now();
        let (sent, reason) = poison(&mut tls, &plan, &config).await;
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

        served += 1;
        // 无限流模式没有终止块，连接无法复用；其余模式可继续读下一个请求。
        if !plan.terminate || served >= config.keep_alive_max_requests {
            let _ = tls.shutdown().await;
            return;
        }
    }
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

        // gzip 炸弹直接切片发送预压缩数据；其余模式现场生成。
        let body: Vec<u8> = match &plan.precompressed {
            Some(data) => {
                let start = sent as usize;
                let end = (start + length).min(data.len());
                data[start..end].to_vec()
            }
            None => payload::chunk(plan.kind, length, first_chunk),
        };
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
    // 注意：这里不能 shutdown——启用 keep-alive 时调用方还要复用这条连接。
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
///
/// 同时供 `--check` 自检使用，因此对 crate 内可见。
pub(crate) fn load_tls_acceptor(
    config: &AppConfig,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
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
fn print_banner(state: &SharedState, config: &AppConfig, local: SocketAddr, reporter: &Reporter) {
    info!(
        "mitm-test-server v{} 已启动，TLS 监听 {local}",
        env!("CARGO_PKG_VERSION")
    );
    info!("友军暗号：X-Probe-Token / Authorization: Bearer / ?token=");
    info!(
        "投毒规模：{} ~ {}，分块基准 {}，单连接时限 {} 秒，并发上限 {}（单 IP {}）",
        human_bytes(config.min_garbage_bytes as u64),
        human_bytes(config.max_garbage_bytes as u64),
        human_bytes(config.chunk_size as u64),
        config.poison_deadline_secs,
        config.max_connections,
        if config.max_conn_per_ip == 0 {
            "不限".to_string()
        } else {
            config.max_conn_per_ip.to_string()
        }
    );
    if config.gzip_bomb_ratio > 0 {
        let ready = if state.bomb().is_some() {
            "已就绪"
        } else {
            "未就绪"
        };
        info!(
            "gzip 炸弹：{}%（解压后约 {} MiB，{}）",
            config.gzip_bomb_ratio, config.gzip_bomb_mib, ready
        );
    } else {
        info!("gzip 炸弹：已关闭（gzip_bomb_ratio = 0）");
    }
    info!(
        "单连接请求数上限：{}（1 表示不复用 keep-alive）",
        config.keep_alive_max_requests
    );
    if reporter.enabled() {
        info!(
            "AbuseIPDB 自动举报：已启用（同 IP 冷却 {} 秒）",
            config.report_cooldown_secs
        );
    } else {
        info!("AbuseIPDB 自动举报：未配置 API Key，已关闭");
    }
    info!("热加载：kill -HUP <pid> 重新读取配置（监听地址/证书/数据库需重启）");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 单 IP 配额：到上限后拒绝，连接结束后名额归还、表项清理。
    #[test]
    fn per_ip_limit_is_enforced_and_released() {
        let limiter = Arc::new(IpLimiter::new(2));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        let first = limiter.try_acquire(ip).expect("第一个名额");
        let second = limiter.try_acquire(ip).expect("第二个名额");
        assert!(limiter.try_acquire(ip).is_none(), "超过上限应被拒绝");
        assert_eq!(limiter.active.lock().unwrap().get(&ip), Some(&2));

        drop(first);
        assert_eq!(limiter.active.lock().unwrap().get(&ip), Some(&1));

        drop(second);
        assert!(
            limiter.active.lock().unwrap().is_empty(),
            "归零后应清理表项"
        );
    }

    /// 0 表示不限制。
    #[test]
    fn zero_means_unlimited() {
        let limiter = Arc::new(IpLimiter::new(0));
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        let guards: Vec<_> = (0..100).filter_map(|_| limiter.try_acquire(ip)).collect();
        assert_eq!(guards.len(), 100);
    }

    /// 不同 IP 之间互不影响。
    #[test]
    fn limits_are_per_ip() {
        let limiter = Arc::new(IpLimiter::new(1));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();

        let _guard_a = limiter.try_acquire(a).expect("a 的首个名额");
        assert!(limiter.try_acquire(a).is_none());
        assert!(limiter.try_acquire(b).is_some(), "b 不应受 a 影响");
    }
}
