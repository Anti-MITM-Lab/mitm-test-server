//! 威胁情报落库。
//!
//! SQLite 是同步 API，直接在异步任务里调用会阻塞 reactor，因此这里采用
//! "发消息 + 单写线程"模型：连接处理逻辑把事件丢进无界 channel，后台任务
//! 持有唯一 `Connection` 串行写入。好处是：
//!
//! * 投毒流程永远不会被磁盘 I/O 卡住；
//! * 无需连接池，也没有跨任务锁竞争；
//! * 崩溃只会丢掉最后排队的一小批事件，对情报采集影响可忽略。

use std::path::PathBuf;
use std::time::Duration;

use rusqlite::{Connection, params};
use tokio::sync::mpsc;

/// 事件写入语句；各列与 [`ProbeEvent`] 字段一一对应。
const INSERT_SQL: &str = "INSERT INTO probe_logs
     (ip, port, probe_time, is_authorized, action_taken, user_agent, request_target, payload_kind, bytes_sent)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

/// 一条探测事件。
#[derive(Debug, Clone)]
pub struct ProbeEvent {
    /// 来源 IP。
    pub ip: String,
    /// 来源端口。
    pub port: u16,
    /// 是否携带正确暗号。
    pub authorized: bool,
    /// 处置动作描述，例如 `Poisoned with 3.2 MiB`。
    pub action: String,
    /// 客户端 User-Agent（可用于识别扫描器家族）。
    pub user_agent: Option<String>,
    /// 请求目标（URL 路径）。
    pub target: Option<String>,
    /// 本次投毒使用的诱饵类型。
    pub payload_kind: Option<String>,
    /// 实际发出的字节数。
    pub bytes_sent: u64,
}

/// 数据库句柄。克隆成本极低，可自由跨任务传递。
#[derive(Clone)]
pub struct Database {
    sender: mpsc::UnboundedSender<ProbeEvent>,
}

impl Database {
    /// 打开（或创建）数据库并启动后台写线程。
    ///
    /// 必须在 Tokio 运行时内调用。
    pub fn open(path: impl Into<PathBuf>) -> rusqlite::Result<Self> {
        let path = path.into();
        let connection = Connection::open(&path)?;
        // WAL 让写入不阻塞读；NORMAL 在蜜罐场景下足够安全。
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;",
        )?;
        init_schema(&connection)?;

        let (sender, mut receiver) = mpsc::unbounded_channel::<ProbeEvent>();
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                let probe_time = chrono::Utc::now().to_rfc3339();
                // 注意：rusqlite 的 `Statement` 不是 `Send`，不能跨 `await` 持有。
                // 蜜罐每秒最多几条事件，这里直接 `execute`（内部自行编译）足够。
                if let Err(e) = connection.execute(
                    INSERT_SQL,
                    params![
                        event.ip,
                        event.port,
                        probe_time,
                        event.authorized as i64,
                        event.action,
                        event.user_agent,
                        event.target,
                        event.payload_kind,
                        event.bytes_sent as i64,
                    ],
                ) {
                    warn!("写入威胁情报失败: {e}");
                }
            }
        });

        Ok(Self { sender })
    }

    /// 非阻塞记录。写入失败（例如接收端已退出）时静默忽略。
    pub fn record(&self, event: ProbeEvent) {
        let _ = self.sender.send(event);
    }
}

/// 建表 + 兼容 0.7 及更早版本留下的表结构。
fn init_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS probe_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            probe_time TEXT NOT NULL,
            is_authorized INTEGER NOT NULL,
            action_taken TEXT,
            user_agent TEXT,
            request_target TEXT,
            payload_kind TEXT,
            bytes_sent INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_probe_logs_ip ON probe_logs (ip);
        CREATE INDEX IF NOT EXISTS idx_probe_logs_time ON probe_logs (probe_time);",
    )?;

    // 旧库可能只有前 6 列，逐列补齐（SQLite 的 ADD COLUMN 是常数开销）。
    for (column, declaration) in [
        ("user_agent", "TEXT"),
        ("request_target", "TEXT"),
        ("payload_kind", "TEXT"),
        ("bytes_sent", "INTEGER NOT NULL DEFAULT 0"),
    ] {
        ensure_column(connection, "probe_logs", column, declaration);
    }

    connection.busy_timeout(Duration::from_secs(5))?;
    Ok(())
}

/// 表里没有该列时补上；已存在则什么都不做。
fn ensure_column(connection: &Connection, table: &str, column: &str, declaration: &str) {
    let exists = connection
        .query_row(
            &format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"),
            [column],
            |_| Ok(()),
        )
        .is_ok();
    if !exists {
        let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {declaration}");
        if let Err(e) = connection.execute_batch(&sql) {
            warn!("为表 {table} 添加列 {column} 失败: {e}");
        }
    }
}
