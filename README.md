# mitm-test-server

反中间人（anti-MITM）探测蜜罐服务端。对外伪装成一个普通的 HTTPS 站点：

- **不带暗号**就来的连接（扫描器、中间人代理、爬虫）会被灌入数 MB 无意义数据；
- **带正确暗号**的友军探针会拿到一个干净的 `200`，用来验证链路上是否存在 TLS 中间人；
- 所有探测都会写入 SQLite 情报库，可选自动举报到 AbuseIPDB。

> 仅用于自查链路、研究蜜罐与对抗扫描。请只部署在你拥有或获得授权的网络与主机上。

## 快速开始

```bash
# 1. 自签一张证书（或换成你自己的正式证书）
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=mitm-test.local"

# 2. 编译并运行（首次运行会自动生成 server-config.toml）
cargo run --release

# 3. 验证友军放行
curl -k -H "X-Probe-Token: <你的暗号>" https://127.0.0.1:8443/
# {"status":"authorized","probe":"mitm-test-server","version":"0.8.0"}

# 4. 观察投毒（会收到一大堆无意义的 HTML/二进制数据）
curl -k https://127.0.0.1:8443/
```

交叉编译静态二进制（部署到 Linux VPS）：

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

## 配置

配置文件为工作目录下的 `server-config.toml`（已被 `.gitignore` 忽略）。文件不存在时
会自动生成带注释的模板；文件存在但解析失败会**直接报错退出**，避免误用默认口令。

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `bind_addr` | `0.0.0.0:8443` | TLS 监听地址 |
| `cert_path` / `key_path` | `cert.pem` / `key.pem` | 证书链与私钥（PEM） |
| `auth_token` | 内置占位值 | 友军暗号，**务必改成随机长串** |
| `db_path` | `mitm_intel.db` | SQLite 情报库 |
| `min_garbage_bytes` / `max_garbage_bytes` | 1.5 MB / 8 MB | 单次投毒规模区间 |
| `chunk_size` | `8192` | 分块基准大小（实际再加 0~2048 抖动） |
| `poison_deadline_secs` | `600` | 单连接投毒时限，`0` 为不限 |
| `handshake_timeout_secs` / `header_timeout_secs` | 10 / 8 | 握手与读头超时，防 Slowloris |
| `max_connections` | `512` | 并发上限，超出直接丢弃 |
| `abuseipdb_api_key` | 空 | 留空则关闭自动举报 |
| `report_cooldown_secs` | `3600` | 同一 IP 举报冷却时间 |

## 暗号传递方式

三种写法等价，全部使用常量时间比较：

```bash
curl -k -H "X-Probe-Token: $TOKEN" https://host:8443/
curl -k -H "Authorization: Bearer $TOKEN" https://host:8443/
curl -k "https://host:8443/?token=$TOKEN"
```

未授权的请求会走投毒流程，响应形态在五种模式中按权重随机：

| 模式 | 行为 |
|------|------|
| `html` | 数 MB 伪 HTML/CSS/JS，页面里引用随机静态资源，诱导对方继续请求 |
| `binary` | 不可压缩随机字节，拖垮文本解析与缓存 |
| `endless` | 分块流**不发送终止块**，客户端只能干等或超时 |
| `redirect` | `302` 指向随机路径，诱导爬虫无限跟随 |
| `error` | `500` 错误页 + 巨型注释填充 |

同时会随机化 `Server`、`Date`（±3 秒偏移）、`ETag`、Cookie 与 CDN 头，并在分块之间
插入抖动与偶发长停顿（tarpit），让对方在"超时"和"重试"之间反复消耗。

## 情报库

事件经无锁 channel 交给单写线程落库（WAL 模式），不会阻塞投毒。表结构：

```sql
CREATE TABLE probe_logs (
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
```

旧版本（0.7 及以前）的库会在启动时自动补齐新增列。常用查询：

```sql
-- 最近 20 条未授权探测
SELECT probe_time, ip, request_target, user_agent, bytes_sent
FROM probe_logs WHERE is_authorized = 0
ORDER BY id DESC LIMIT 20;

-- 按 IP 聚合的"投毒收益"
SELECT ip, COUNT(*) AS hits, SUM(bytes_sent) AS bytes
FROM probe_logs WHERE is_authorized = 0
GROUP BY ip ORDER BY bytes DESC LIMIT 20;
```

## 代码结构

```
src/
├── main.rs     入口：装配各组件、处理退出码
├── config.rs   server-config.toml 的加载、校验与模板
├── server.rs   监听、TLS 握手、鉴权、投毒主循环
├── http.rs     HTTP/1.x 请求头解析、常量时间比较
├── payload.rs  诱饵响应（指纹、正文、节奏）
├── db.rs       SQLite 情报库（单写线程）
├── report.rs   AbuseIPDB 自动举报（按 IP 冷却）
└── logging.rs  日志宏
```

调试时设置 `MITM_TEST_VERBOSE=1` 可看到握手失败、空请求等噪声日志。

## 变更记录

### 0.8.0

- 拆分单文件为 8 个模块，补齐文档注释，`cargo fmt` / `cargo clippy` 干净。
- 投毒升级：五种响应形态、随机指纹、随机资源引用、分块抖动与长停顿。
- 修复：ALPN 曾声明 `h2` 却只实现了 HTTP/1.1，导致 h2 客户端卡死；现只声明 `http/1.1`。
- 修复：暗号匹配改为大小写不敏感 + 常量时间比较，并支持 `Bearer` 与 `?token=`。
- 新增：握手/读头/写入超时、并发上限、优雅退出、配置校验。
- 新增：情报库记录 UA、请求路径、诱饵类型与实际发送字节数，并自动迁移旧库。
- 新增：AbuseIPDB 按 IP 冷却去重，避免重复举报浪费配额。
