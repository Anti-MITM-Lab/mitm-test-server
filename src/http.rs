//! 极简 HTTP/1.x 请求头读取与解析。
//!
//! 蜜罐只需要看清请求行和少数几个头（暗号、User-Agent），因此不引入
//! hyper 之类的完整实现，手写一个"读到 `\r\n\r\n` 为止"的解析器即可。
//!
//! 设计要点：
//!
//! * 上限保护：请求头最多读 `max_bytes`，防止恶意超长头吃内存；
//! * 整体超时：读取放在 `timeout` 里，天然免疫 Slowloris；
//! * 大小写不敏感的头名匹配，避免攻击者用 `x-probe-token` 绕过判断；
//! * 常量时间比较暗号，避免通过响应时间逐字节猜口令。

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// 单个请求头允许的最大字节数（含请求行与所有头部）。
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// 请求头解析结果。
#[derive(Debug, Default, Clone)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl RequestHead {
    /// 按名字取头部（大小写不敏感），返回首个匹配值。
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// 仅当暗号通过 URL 查询参数（`?token=...`）传递时使用。
    pub fn query_param(&self, name: &str) -> Option<&str> {
        let query = self.target.split_once('?')?.1;
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then_some(value)
        })
    }

    /// `Authorization` 头里的 Bearer 口令。
    pub fn bearer_token(&self) -> Option<&str> {
        let value = self.header("authorization")?;
        let mut parts = value.split_whitespace();
        let scheme = parts.next()?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        parts.next()
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.header("user-agent")
    }

    /// 客户端是否跳过了 ALPN 直接发送 HTTP/2 连接前言。
    ///
    /// 这种情况说明对端（或中间代理）硬编码了 h2；本服务只实现 HTTP/1.1，
    /// 此时仍按"未授权"处理——反正都会收到一坨无意义的数据。
    pub fn is_http2_preface(&self) -> bool {
        self.method == "PRI" && self.target == "*" && self.version.starts_with("HTTP/2")
    }
}

/// 读取请求头时可能出现的失败。
#[derive(Debug)]
pub enum HeadError {
    /// 对端在发送任何数据前就关闭了连接。
    Eof,
    /// 超时（Slowloris 或纯 TCP 探测）。
    Timeout,
    /// 请求头超过上限。
    TooLarge(usize),
    /// 内容不是合法的 HTTP 请求行。
    Malformed(String),
    /// 底层 I/O 错误。
    Io(std::io::Error),
}

impl std::fmt::Display for HeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeadError::Eof => write!(f, "对端在发送请求前关闭连接"),
            HeadError::Timeout => write!(f, "读取请求头超时"),
            HeadError::TooLarge(limit) => write!(f, "请求头超过 {limit} 字节上限"),
            HeadError::Malformed(reason) => write!(f, "请求头格式非法: {reason}"),
            HeadError::Io(e) => write!(f, "读取请求头失败: {e}"),
        }
    }
}

/// 读取并解析一个 HTTP 请求头（直到空行为止）。
pub async fn read_head<S>(
    stream: &mut S,
    timeout: Duration,
    max_bytes: usize,
) -> Result<RequestHead, HeadError>
where
    S: AsyncRead + Unpin,
{
    let read_all = async {
        let mut buffer: Vec<u8> = Vec::with_capacity(1024);
        let mut scratch = [0u8; 1024];

        loop {
            if let Some(end) = terminator_position(&buffer) {
                return parse(&buffer[..end]);
            }
            if buffer.len() >= max_bytes {
                return Err(HeadError::TooLarge(max_bytes));
            }

            let read = stream.read(&mut scratch).await.map_err(HeadError::Io)?;
            if read == 0 {
                return if buffer.is_empty() {
                    Err(HeadError::Eof)
                } else {
                    Err(HeadError::Malformed("连接在空行之前关闭".to_string()))
                };
            }
            buffer.extend_from_slice(&scratch[..read]);
        }
    };

    match tokio::time::timeout(timeout, read_all).await {
        Ok(result) => result,
        Err(_) => Err(HeadError::Timeout),
    }
}

/// 定位 `\r\n\r\n`，返回请求头的结束偏移。
fn terminator_position(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// 解析请求行与头部字段。
fn parse(head: &[u8]) -> Result<RequestHead, HeadError> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");

    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || target.is_empty() {
        return Err(HeadError::Malformed("请求行不完整".to_string()));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        // 头部值里允许出现冒号（如 Location、Date），因此只切第一个。
        let Some((name, value)) = line.split_once(':') else {
            return Err(HeadError::Malformed(format!("头部缺少冒号: {line}")));
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    Ok(RequestHead {
        method: method.to_string(),
        target: target.to_string(),
        version: if version.is_empty() {
            "HTTP/1.1".to_string()
        } else {
            version.to_string()
        },
        headers,
    })
}

/// 常量时间字节比较：耗时只与长度有关，不会因为前缀相同而提前返回。
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

/// 判断查询参数是否可能承载凭据（比较时忽略大小写）。
fn is_sensitive_param(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "token"
            | "access_token"
            | "auth"
            | "authorization"
            | "apikey"
            | "api_key"
            | "key"
            | "sig"
            | "signature"
            | "password"
            | "passwd"
            | "pwd"
    )
}

/// 落库 / 打日志前对请求目标脱敏：保留路径，把敏感查询参数的值替换成 `***`。
///
/// 友军探针可以用 `?token=<暗号>` 鉴权，如果原样记录，暗号就会出现在 SQLite
/// 和 journald 里，甚至被带进 AbuseIPDB 的举报备注——那等于自己泄露口令。
pub fn redact_target(target: &str) -> String {
    let Some((path, query)) = target.split_once('?') else {
        return target.to_string();
    };
    let masked = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) if is_sensitive_param(name) => format!("{name}=***"),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{masked}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 解析一份典型请求，并验证大小写不敏感的头名匹配。
    #[test]
    fn parses_headers_case_insensitively() {
        let raw = b"GET /index.html?token=abc HTTP/1.1\r\nHost: ex\r\nX-Probe-Token: s3cret\r\nUser-Agent: curl/8\r\n";
        let req = parse(raw).expect("应能解析");
        assert_eq!(req.method, "GET");
        assert_eq!(req.target, "/index.html?token=abc");
        assert_eq!(req.header("x-probe-token"), Some("s3cret"));
        assert_eq!(req.query_param("token"), Some("abc"));
        assert_eq!(req.user_agent(), Some("curl/8"));
    }

    /// 头部值中的冒号不应被误当作分隔符。
    #[test]
    fn keeps_colons_in_header_values() {
        let raw = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n";
        let req = parse(raw).expect("应能解析");
        assert_eq!(req.header("host"), Some("127.0.0.1:8443"));
    }

    /// 暗号比较必须是常量时间且长度不同直接判否。
    #[test]
    fn constant_time_equality() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"toke"));
        assert!(!constant_time_eq(b"token", b"tokem"));
    }

    /// 落库/日志用的目标必须把暗号抹掉，但不影响其他参数与路径。
    #[test]
    fn redacts_sensitive_query_values() {
        assert_eq!(redact_target("/?token=abc123"), "/?token=***");
        assert_eq!(
            redact_target("/admin?next=%2F&Token=abc&x=1"),
            "/admin?next=%2F&Token=***&x=1"
        );
        assert_eq!(redact_target("/index.html"), "/index.html");
        assert_eq!(redact_target("/?a=1&b=2"), "/?a=1&b=2");
        assert_eq!(redact_target("/?flag"), "/?flag");
    }
}
