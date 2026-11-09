//! 诱饵生成器：伪装指纹、分块正文与投毒节奏。
//!
//! 目标是让"无暗号"的探测者付出最大代价，同时不给对方任何可用的指纹：
//!
//! | 模式 | 作用 |
//! |------|------|
//! | `Html` | 数 MB 的伪 HTML/CSS/JS，浏览器/解析器必须完整读取 |
//! | `Binary` | 不可压缩的随机字节，吃满带宽、拖垮文本解析 |
//! | `Endless` | 不发送终止块，连接一直"还有数据"，客户端只能干等或超时 |
//! | `Redirect` | 302 指向随机路径，诱导爬虫无限跟随 |
//! | `Error` | 500 错误页 + 巨型注释填充 |
//!
//! 此外每个响应都会随机化 `Server`、`Date`、`ETag`、Cookie 等字段，
//! 并让页面里引用若干随机静态资源，诱使对方继续发起请求。

use std::time::Duration;

use rand::RngExt;

use crate::config::AppConfig;

/// 一次投毒使用的响应形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Html,
    Binary,
    Endless,
    Redirect,
    Error,
}

impl Kind {
    /// 落库/日志里使用的短标签。
    pub fn label(self) -> &'static str {
        match self {
            Kind::Html => "html",
            Kind::Binary => "binary",
            Kind::Endless => "endless",
            Kind::Redirect => "redirect",
            Kind::Error => "error",
        }
    }

    /// 按权重抽签：大头仍是"大页面"，少量极端模式增加不可预测性。
    fn pick() -> Self {
        match rand::rng().random_range(0..100u32) {
            0..=49 => Kind::Html,
            50..=71 => Kind::Binary,
            72..=83 => Kind::Endless,
            84..=93 => Kind::Redirect,
            _ => Kind::Error,
        }
    }
}

/// 一次投毒的完整计划。
pub struct Plan {
    pub kind: Kind,
    /// 已拼装好的状态行 + 全部响应头（以空行结尾）。
    pub head: String,
    /// 计划发送的正文字节数；`Endless` 模式下仅作参考。
    pub body_bytes: usize,
    /// 是否发送分块终止符（`Endless` 模式故意不发）。
    pub terminate: bool,
}

/// 生成一次投毒计划。
pub fn plan(config: &AppConfig) -> Plan {
    let mut rng = rand::rng();
    let kind = Kind::pick();
    let persona = Persona::pick();

    // 只有 302 的正文为 0，其余都按配置规模投毒。
    let body_bytes = if kind == Kind::Redirect {
        0
    } else {
        rng.random_range(config.min_garbage_bytes..=config.max_garbage_bytes)
    };

    // Date 随机偏移几秒：让依赖时间缓存的中间件（代理、CDN）行为异常。
    let skew = rng.random_range(-3..=3i64);
    let now = chrono::Utc::now() + chrono::Duration::seconds(skew);
    let http_date = now.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let last_modified = (now - chrono::Duration::hours(rng.random_range(1..=720i64)))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();

    let status = match kind {
        Kind::Error => "500 Internal Server Error",
        Kind::Redirect => "302 Found",
        _ => "200 OK",
    };
    let content_type = match kind {
        Kind::Binary => "application/octet-stream",
        _ => "text/html; charset=UTF-8",
    };

    let session = random_hex(32);
    let etag = format!("W/\"{}-{}\"", random_hex(8), random_hex(8));
    let request_id = random_hex(16);
    let last_segment = random_hex(4);

    let mut head = String::with_capacity(1024);
    head.push_str("HTTP/1.1 ");
    head.push_str(status);
    head.push_str("\r\n");
    push_header(&mut head, "Date", &http_date);
    push_header(&mut head, "Server", persona.server);
    if let Some(powered_by) = persona.powered_by {
        push_header(&mut head, "X-Powered-By", powered_by);
    }
    push_header(&mut head, "Content-Type", content_type);

    if kind == Kind::Redirect {
        // 302：正文为空，Location 指向随机路径，爬虫会一直跟下去。
        push_header(
            &mut head,
            "Location",
            &format!("/portal/login?next=/{last_segment}&sid={}", random_hex(8)),
        );
        push_header(&mut head, "Refresh", "0; url=/portal/login");
        push_header(&mut head, "Content-Length", "0");
    } else {
        // 没有 Content-Length，靠 chunked 边算边发，客户端无法提前拒绝。
        push_header(&mut head, "Transfer-Encoding", "chunked");
    }

    push_header(&mut head, "Connection", "keep-alive");
    push_header(
        &mut head,
        "Cache-Control",
        "private, no-cache, no-store, max-age=0",
    );
    push_header(&mut head, "Pragma", "no-cache");
    push_header(&mut head, "ETag", &etag);
    push_header(&mut head, "Last-Modified", &last_modified);
    push_header(&mut head, "Vary", "Accept-Encoding, Cookie");
    push_header(&mut head, "X-Request-Id", &request_id);
    push_header(&mut head, "X-Content-Type-Options", "nosniff");
    push_header(&mut head, "X-Frame-Options", "SAMEORIGIN");
    push_header(
        &mut head,
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
    );
    push_header(
        &mut head,
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
    );
    push_header(
        &mut head,
        "Set-Cookie",
        &format!(
            "{}={}; Path=/; Secure; HttpOnly; SameSite=Lax",
            persona.cookie_name, session
        ),
    );
    if let Some(cdn_header) = persona.cdn_header {
        push_header(&mut head, cdn_header, &random_hex(16));
    }
    head.push_str("\r\n");

    Plan {
        kind,
        head,
        body_bytes,
        terminate: kind != Kind::Endless,
    }
}

/// 生成一块正文（长度严格等于 `len`）。
pub fn chunk(kind: Kind, len: usize, first: bool) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    match kind {
        Kind::Binary => noise(len),
        Kind::Redirect => redirect_body(len),
        Kind::Error => text_body(len, first, Kind::Error),
        Kind::Html | Kind::Endless => text_body(len, first, kind),
    }
}

/// 计算下一块正文的长度：基准值 + 0~2048 字节抖动，并受剩余预算约束。
///
/// `remaining` 为 `None` 表示无限流（`Endless`），不需要收敛。
pub fn next_chunk_len(config: &AppConfig, remaining: Option<usize>) -> usize {
    let jitter = rand::rng().random_range(0..2048usize);
    let wanted = config.chunk_size.saturating_add(jitter);
    match remaining {
        Some(left) => wanted.min(left),
        None => wanted,
    }
}

/// 两块数据之间的间隔，制造"真实网络"的抖动并顺带消耗对方超时预算。
pub fn next_delay() -> Duration {
    let mut rng = rand::rng();
    if rng.random_bool(0.02) {
        // 偶发长停顿：逼客户端在超时与重试之间反复挣扎。
        Duration::from_millis(rng.random_range(800..=2000))
    } else if rng.random_bool(0.06) {
        Duration::from_millis(rng.random_range(150..=500))
    } else if rng.random_bool(0.2) {
        Duration::from_millis(rng.random_range(20..=100))
    } else {
        Duration::from_millis(rng.random_range(1..=5))
    }
}

// ==================== 内部实现 ====================

/// 伪装成某一款常见的 Web 服务器，保证响应头之间不自相矛盾。
struct Persona {
    server: &'static str,
    powered_by: Option<&'static str>,
    cookie_name: &'static str,
    /// 云厂商特有的响应头（如 `CF-RAY`）。
    cdn_header: Option<&'static str>,
}

impl Persona {
    fn pick() -> Self {
        match rand::rng().random_range(0..4u32) {
            0 => Self {
                server: "nginx/1.24.0 (Ubuntu)",
                powered_by: None,
                cookie_name: "sessionid",
                cdn_header: None,
            },
            1 => Self {
                server: "cloudflare",
                powered_by: None,
                cookie_name: "__cf_bm",
                cdn_header: Some("CF-RAY"),
            },
            2 => Self {
                server: "Apache/2.4.57 (Debian)",
                powered_by: Some("PHP/8.2.13"),
                cookie_name: "PHPSESSID",
                cdn_header: None,
            },
            _ => Self {
                server: "Microsoft-IIS/10.0",
                powered_by: Some("ASP.NET"),
                cookie_name: "ASPSESSIONID",
                cdn_header: None,
            },
        }
    }
}

fn push_header(head: &mut String, name: &str, value: &str) {
    head.push_str(name);
    head.push_str(": ");
    head.push_str(value);
    head.push_str("\r\n");
}

/// 生成 `len` 个十六进制字符。
fn random_hex(len: usize) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut rng = rand::rng();
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        out.push(DIGITS[rng.random_range(0..16usize)] as char);
    }
    out
}

/// 不可压缩的随机字节。用 `fill` 批量生成，避免逐字节抽样。
fn noise(len: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; len];
    rand::rng().fill(&mut buffer[..]);
    buffer
}

/// 302 的极小正文，模仿真实登录门户的跳转提示。
fn redirect_body(len: usize) -> Vec<u8> {
    let body = b"<html>\r\n<head><title>302 Found</title></head>\r\n<body>\r\n\
                 <center><h1>302 Found</h1></center>\r\n</body>\r\n</html>\r\n";
    body[..len.min(body.len())].to_vec()
}

/// 错误页与 HTML 页共用的文本填充逻辑。
fn text_body(len: usize, first: bool, kind: Kind) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut out = Vec::with_capacity(len + 512);

    if first {
        match kind {
            Kind::Error => out.extend_from_slice(ERROR_HEAD.as_bytes()),
            _ => out.extend_from_slice(PAGE_HEAD.as_bytes()),
        }
    }

    while out.len() < len {
        let template = TEMPLATES[rng.random_range(0..TEMPLATES.len())];
        let number = rng.random_range(100..=99_999u32);
        let hex = random_hex(8);

        let mut line = template.replace("{n}", &number.to_string());
        if line.contains("{hex}") {
            line = line.replace("{hex}", &hex);
        }
        out.extend_from_slice(line.as_bytes());
    }

    // 分块长度必须精确，截断在标签中间也无所谓——对方只会拿到一份坏页面。
    out.truncate(len);
    out
}

/// 页面开头：看起来像一个真实的后台会话页面。
const PAGE_HEAD: &str = concat!(
    "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n",
    "<meta charset=\"utf-8\">\n",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
    "<title>Secure Gateway · Session</title>\n",
    "<style>\n",
    "body{margin:0;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#f6f7f9;color:#1f2328}\n",
    ".wrap{max-width:1120px;margin:0 auto;padding:24px}\n",
    ".card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:20px;margin-bottom:16px}\n",
    ".row{display:flex;gap:12px;padding:6px 0;border-bottom:1px solid #f1f2f4}\n",
    "</style>\n",
    "</head>\n<body>\n<div class=\"wrap\">\n",
);

/// 500 页面开头，模仿 nginx 默认错误页。
const ERROR_HEAD: &str = concat!(
    "<html>\r\n<head><title>500 Internal Server Error</title></head>\r\n<body>\r\n",
    "<center><h1>500 Internal Server Error</h1></center>\r\n",
    "<hr><center>nginx</center>\r\n",
);

/// 正文模板。`{n}` 替换为随机数字，`{hex}` 替换为随机十六进制串。
const TEMPLATES: &[&str] = &[
    "<div class=\"card row\" data-id=\"{n}\"><span class=\"k\">field_{n}</span><span class=\"v\">{hex}</span></div>\n",
    "<script>window.__STATE__=window.__STATE__||{};window.__STATE__.item_{n}=\"{hex}\";</script>\n",
    "<style>.col-{n}{grid-column:span {n};opacity:.{n};transition:all .2s ease-in-out}</style>\n",
    "/* module {n} */ .m-{n}{{margin:{n}px;padding:{n}px;line-height:1.4}}\n",
    "<img loading=\"lazy\" src=\"/static/hero-{n}.png\" width=\"1\" height=\"1\" alt=\"\">\n",
    "function compute_{n}(a,b){{return a*{n}+b-{n}/2}};var r_{n}=compute_{n}({n},{n});\n",
    "<!-- slot {n} rendered at {hex} -->\n<section class=\"card\" id=\"s{n}\"><h2>Dataset {n}</h2></section>\n",
    "const payload_{n}=\"data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7\";\n",
    "<li class=\"item\" data-hash=\"{hex}\" data-seq=\"{n}\"><a href=\"/resource/{n}?v={hex}\">item {n}</a></li>\n",
    "/* {\"id\":{n},\"hash\":\"{hex}\",\"state\":\"active\",\"ts\":{n}000} */\n",
    "<script type=\"application/json\" id=\"cfg-{n}\">{{\"id\":{n},\"nonce\":\"{hex}\",\"flags\":[{n},1,0]}}</script>\n",
];
