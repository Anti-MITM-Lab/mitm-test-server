//! 极简结构化日志。
//!
//! 为什么不用 `log`/`tracing`：本服务的日志量可控（每条连接至多两三行），
//! 引入日志框架只会增加编译时间与依赖面，因此这里用几个宏 + 一个输出函数
//! 统一时间戳、级别前缀和输出流（警告/错误走 stderr，便于 systemd 分流）。
//!
//! 调试信息默认关闭，可通过环境变量 `MITM_TEST_VERBOSE=1` 打开。

use std::io::Write;
use std::sync::OnceLock;

/// 日志级别。`Debug` 仅在开启 verbose 时才会真正输出。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Debug,
    Info,
    Success,
    Warn,
    Error,
}

/// 是否输出 `debug!` 级别日志（进程内只读取一次环境变量）。
fn verbose() -> bool {
    static VERBOSE: OnceLock<bool> = OnceLock::new();
    *VERBOSE.get_or_init(|| {
        matches!(
            std::env::var("MITM_TEST_VERBOSE").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    })
}

/// 统一输出入口，供各模块的日志宏调用。
///
/// 格式：`[HH:MM:SS] [标记] 消息`，其中 `+` 表示成功事件，`!` 警告，
/// `-` 错误，`.` 调试。时间戳使用本地时区，方便与服务器 `journalctl` 对齐。
pub fn emit(level: Level, message: &str) {
    if level == Level::Debug && !verbose() {
        return;
    }

    let stamp = chrono::Local::now().format("%H:%M:%S");
    let marker = match level {
        Level::Debug => '.',
        Level::Info => ' ',
        Level::Success => '+',
        Level::Warn => '!',
        Level::Error => '-',
    };
    let line = format!("[{stamp}] [{marker}] {message}\n");

    // 一次 write_all 写出整行，避免多线程下日志被截断或交错。
    match level {
        Level::Warn | Level::Error => {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
        _ => {
            let _ = std::io::stdout().write_all(line.as_bytes());
        }
    }
}

macro_rules! info {
    ($($arg:tt)*) => {
        $crate::logging::emit($crate::logging::Level::Info, &format!($($arg)*))
    };
}

macro_rules! success {
    ($($arg:tt)*) => {
        $crate::logging::emit($crate::logging::Level::Success, &format!($($arg)*))
    };
}

macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::logging::emit($crate::logging::Level::Warn, &format!($($arg)*))
    };
}

macro_rules! error {
    ($($arg:tt)*) => {
        $crate::logging::emit($crate::logging::Level::Error, &format!($($arg)*))
    };
}

macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::logging::emit($crate::logging::Level::Debug, &format!($($arg)*))
    };
}
