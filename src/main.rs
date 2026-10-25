use chrono::{Duration, Utc};
use rand::RngExt;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

// ==================== 1. 配置文件结构 ====================
#[derive(Serialize, Deserialize, Debug, Clone)]
struct AppConfig {
    #[serde(default = "default_bind_addr")]
    bind_addr: String,
    #[serde(default = "default_cert_path")]
    cert_path: String,
    #[serde(default = "default_key_path")]
    key_path: String,
    #[serde(default = "default_min_garbage")]
    min_garbage_bytes: usize,
    #[serde(default = "default_max_garbage")]
    max_garbage_bytes: usize,
    #[serde(default = "default_chunk_size")]
    chunk_size: usize,
    // 新增：友军暗号，默认为空（空则不启用暗号）
    #[serde(default = "default_auth_token")]
    auth_token: String,
}

fn default_bind_addr() -> String {
    "0.0.0.0:8443".to_string()
}
fn default_cert_path() -> String {
    "cert.pem".to_string()
}
fn default_key_path() -> String {
    "key.pem".to_string()
}
fn default_min_garbage() -> usize {
    1_500_000
}
fn default_max_garbage() -> usize {
    8_000_000
}
fn default_chunk_size() -> usize {
    8192
}
fn default_auth_token() -> String {
    "my_secret_antimtm_token".to_string()
}

impl AppConfig {
    fn load_or_create() -> Self {
        let config_path = "server-config.toml";
        if let Ok(content) = fs::read_to_string(config_path) {
            if let Ok(cfg) = toml::from_str::<AppConfig>(&content) {
                println!("[+] 已加载配置文件: {}", config_path);
                return cfg;
            }
        }
        let default_cfg = AppConfig {
            bind_addr: default_bind_addr(),
            cert_path: default_cert_path(),
            key_path: default_key_path(),
            min_garbage_bytes: default_min_garbage(),
            max_garbage_bytes: default_max_garbage(),
            chunk_size: default_chunk_size(),
            auth_token: default_auth_token(),
        };
        if let Ok(toml_str) = toml::to_string_pretty(&default_cfg) {
            let _ = fs::write(config_path, toml_str);
            println!("[+] 已生成默认配置文件模板: {}", config_path);
        }
        default_cfg
    }
}

// ==================== 2. 数据库初始化与记录 ====================
fn init_db() -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open("mitm_intel.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS probe_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            probe_time TEXT NOT NULL,
            is_authorized INTEGER NOT NULL,
            action_taken TEXT
        )",
        [],
    )?;
    Ok(conn)
}

fn log_to_db(ip: String, port: u16, is_auth: bool, action: &str) {
    let time_str = Utc::now().to_rfc3339();
    let auth_val = if is_auth { 1 } else { 0 };
    let action_str = action.to_string();

    // 扔进阻塞线程池，绝不卡住 Tokio 的高并发主线程
    tokio::task::spawn_blocking(move || {
        if let Ok(conn) = Connection::open("mitm_intel.db") {
            let _ = conn.execute(
                "INSERT INTO probe_logs (ip, port, probe_time, is_authorized, action_taken)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ip, port, time_str, auth_val, action_str],
            );
        }
    });
}

// ==================== 3. 高仿数据生成器 ====================
fn generate_fake_web_data(size: usize, is_first_chunk: bool) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);

    if is_first_chunk {
        let head = b"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<title>Secure Gateway | Session</title>\n<style>\nbody { font-family: sans-serif; background: #f4f4f4; }\n";
        data.extend_from_slice(head);
    }

    let templates: &[&str] = &[
        ".cls-{n} {{ display: block; margin: 0 auto; padding: 10px; }}\n",
        "function init() {{ let a = {n}; var b = document.getElementById('item_{n}'); return a + b; }}\n",
        "<!-- generated content {n} -->\n<div class=\"item\">Data chunk {n}</div>\n",
        ".box-{n} {{ width: {n}px; height: {n}px; background: #ccc; }}\n",
        "const user_{n} = {{ id: {n}, token: 'a1b2c3d4e5f6{n}' }};\n",
    ];

    {
        let mut rng = rand::rng();
        while data.len() < size {
            let tpl = templates[rng.random_range(0..templates.len())];
            let num = rng.random_range(1000..99999);
            let line = tpl.replace("{n}", &num.to_string());
            data.extend_from_slice(line.as_bytes());
        }
    }

    data.truncate(size);
    data
}

// ==================== 4. 主函数 ====================
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load_or_create();

    if !Path::new(&config.cert_path).exists() {
        eprintln!("[!] 找不到证书文件: {}", config.cert_path);
        return Ok(());
    }
    if !Path::new(&config.key_path).exists() {
        eprintln!("[!] 找不到私钥文件: {}", config.key_path);
        return Ok(());
    }

    // 初始化本地 SQLite 情报库
    if let Err(e) = init_db() {
        eprintln!("[!] 数据库初始化失败: {}", e);
    } else {
        println!("[+] SQLite 威胁情报库 mitm_intel.db 已就绪");
    }

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let cert_file = &mut BufReader::new(File::open(&config.cert_path)?);
    let key_file = &mut BufReader::new(File::open(&config.key_path)?);

    let cert_chain: Vec<CertificateDer> =
        rustls_pemfile::certs(cert_file).collect::<Result<Vec<_>, _>>()?;
    let key: PrivateKeyDer =
        rustls_pemfile::private_key(key_file)?.ok_or("No private key found")?;

    let mut tls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(&config.bind_addr).await?;
    println!("[+] 终极折磨版诱饵服务端已启动，监听: {}", config.bind_addr);
    println!("[+] 友军暗号路径前缀: /_probe_{}", config.auth_token);

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let cfg = config.clone();

        tokio::spawn(async move {
            let client_ip = addr.ip();
            let client_port = addr.port();

            match acceptor.accept(stream).await {
                Ok(mut tls_stream) => {
                    // 1. 读取前 1024 个字节，校验暗号
                    let mut buf = [0; 1024];
                    let mut is_authorized = false;

                    // 设置 2 秒超时，防止 Slowloris 攻击卡住服务端
                    let read_timeout = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        tls_stream.read(&mut buf),
                    )
                    .await;

                    if let Ok(Ok(n)) = read_timeout {
                        if n > 0 {
                            let req_str = String::from_utf8_lossy(&buf[..n]);
                            // 如果请求路径中包含了约定的暗号
                            if req_str.contains(&format!("/_probe_{}", cfg.auth_token)) {
                                is_authorized = true;
                            }
                        }
                    }

                    // 2. 根据暗号验证结果分流
                    if is_authorized {
                        // 【友军放行】
                        println!(
                            "\n[✓] 验证通过！{} (端口: {}) 是友军探针。",
                            client_ip, client_port
                        );
                        let _ = tls_stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK").await;
                        let _ = tls_stream.shutdown().await;

                        // 记录到 SQLite（标记为友军放行）
                        let ip_str = client_ip.to_string();
                        log_to_db(ip_str, client_port, true, "Authorized: Peaceful Pass");
                    } else {
                        // 【敌军重拳】
                        println!(
                            "\n🚨 [捕获探测节点] IP: {} (端口: {}) - 无暗号，开始投喂诱饵...",
                            client_ip, client_port
                        );

                        let (total_size, header) = {
                            let mut rng = rand::rng();
                            let size =
                                rng.random_range(cfg.min_garbage_bytes..=cfg.max_garbage_bytes);
                            let offset = Duration::seconds(rng.random_range(-3..=3));
                            let now = Utc::now() + offset;
                            let http_date = now.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
                            let session_id = format!("{:x}", rng.random_range(10000000..99999999));
                            let etag = format!("W/\"{:x}\"", rng.random_range(10000000..99999999));

                            let header = format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Server: nginx/1.24.0 (Ubuntu)\r\n\
                                 Date: {}\r\n\
                                 Content-Type: text/html; charset=utf-8\r\n\
                                 Transfer-Encoding: chunked\r\n\
                                 Set-Cookie: session={}; Path=/; HttpOnly\r\n\
                                 ETag: {}\r\n\
                                 X-Cache: HIT from Cloudflare\r\n\
                                 X-Content-Type-Options: nosniff\r\n\r\n",
                                http_date, session_id, etag
                            );
                            (size, header)
                        };

                        if tls_stream.write_all(header.as_bytes()).await.is_err() {
                            return;
                        }

                        let mut sent = 0;
                        let mut is_first = true;

                        while sent < total_size {
                            let current_chunk = {
                                let mut rng = rand::rng();
                                std::cmp::min(
                                    cfg.chunk_size + rng.random_range(0..2048),
                                    total_size - sent,
                                )
                            };

                            let garbage = generate_fake_web_data(current_chunk, is_first);
                            is_first = false;

                            let chunk_header = format!("{:x}\r\n", current_chunk);
                            if tls_stream.write_all(chunk_header.as_bytes()).await.is_err() {
                                return;
                            }
                            if tls_stream.write_all(&garbage).await.is_err() {
                                return;
                            }
                            if tls_stream.write_all(b"\r\n").await.is_err() {
                                return;
                            }

                            sent += current_chunk;

                            let sleep_ms = {
                                let mut rng = rand::rng();
                                if rng.random_bool(0.05) {
                                    rng.random_range(200..500)
                                } else if rng.random_bool(0.2) {
                                    rng.random_range(20..100)
                                } else {
                                    rng.random_range(1..5)
                                }
                            };
                            tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
                        }

                        let _ = tls_stream.write_all(b"0\r\n\r\n").await;
                        let _ = tls_stream.shutdown().await;

                        println!("[+] 向节点 {} 投喂完毕，共发送 {} 字节。", client_ip, sent);

                        // 记录到 SQLite（标记为敌军投毒）
                        let ip_str = client_ip.to_string();
                        let action_msg = format!("Poisoned with {} bytes", sent);
                        log_to_db(ip_str, client_port, false, &action_msg);
                    }
                }
                Err(_) => {}
            }
        });
    }
}
