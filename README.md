# mitm-test-server

反中间人（anti-MITM）探测蜜罐服务端。对外伪装成一个普通的 HTTPS 站点：

- **不带暗号**就来的连接（扫描器、中间人代理、爬虫）会被灌入数 MB 无意义数据；
- **带正确暗号**的友军探针会拿到一个干净的 `200`，用来验证链路上是否存在 TLS 中间人；
- 所有探测都会写入 SQLite 情报库，可选自动举报到 AbuseIPDB。

> 仅用于自查链路、研究蜜罐与对抗扫描。请只部署在你拥有或获得授权的网络与主机上。

## 安装（Linux）

一条命令安装（需要 root，脚本会创建系统用户、生成配置与自签证书、注册 systemd 服务）：

```bash
curl -fsSL https://raw.githubusercontent.com/Anti-MITM-Lab/mitm-test-server/main/install.sh | sudo bash
```

国内网络可加 GitHub 加速前缀：

```bash
curl -fsSL https://raw.githubusercontent.com/Anti-MITM-Lab/mitm-test-server/main/install.sh \
  | sudo bash -s -- --mirror https://ghfast.top/
```

安装脚本做的事：

| 项目 | 默认位置 |
|------|----------|
| 二进制 | `/usr/local/bin/mitm-test-server` |
| 配置（含随机友军暗号） | `/etc/mitm-test/server-config.toml` |
| 证书 / 私钥 | `/etc/mitm-test/cert.pem`、`key.pem` |
| 情报库 | `/var/lib/mitm-test/mitm_intel.db` |
| systemd 单元 | `mitm-test-server.service` |

常用参数（完整列表见 `install.sh --help`）：

```bash
# 安装指定版本
... | sudo bash -s -- --version 0.8.3

# 指定监听地址与暗号
... | sudo bash -s -- --bind 0.0.0.0:8443 --token "$(openssl rand -hex 32)"

# 只改端口；端口被占用时自动顺延到空闲端口
... | sudo bash -s -- --port 9443 --auto-port

# 显式指定 / 跳过防火墙配置
... | sudo bash -s -- --firewall ufw
... | sudo bash -s -- --no-firewall

# 离线安装：使用本机已编译好的二进制
sudo bash install.sh --binary ./target/x86_64-unknown-linux-musl/release/mitm-test-server

# 已有正式证书，跳过自签
... | sudo bash -s -- --no-cert

# 卸载（保留配置与数据）/ 彻底删除
sudo bash install.sh --uninstall
sudo bash install.sh --uninstall --purge
```

升级只需重跑安装脚本：会先停掉旧服务释放端口，配置、证书与友军暗号都会保留，只有二进制被替换。

### 端口与防火墙

- **端口检测**：安装前用 `ss`（缺失时退化为 `netstat` 或 `/dev/tcp` 探测）检查端口是否被占用。
  占用时打印占用进程并退出，提示改用 `--port` / `--bind`，或加 `--auto-port` 自动向上找空闲端口。
  已有配置存在时以其 `bind_addr` 为准（要改写需加 `--force-config`）。
- **自动放行**：识别 ufw、firewalld、iptables、nftables 并放行监听端口；已有规则不会重复添加。
  只对**处于启用状态**的防火墙动手，脚本不会自行启用防火墙，也不会改动无法识别的防火墙。
- iptables / nftables 的规则默认不持久化（重启后失效），脚本会给出提示；生产环境建议用 ufw 或 firewalld。
- 云服务器还需要在安全组里单独放行该 TCP 端口，脚本无法代劳。

安装完成后：

```bash
systemctl status mitm-test-server
journalctl -u mitm-test-server -f

# 友军放行（应返回 authorized JSON）
curl -k -H "X-Probe-Token: <安装脚本打印的暗号>" https://127.0.0.1:8443/
# {"status":"authorized","probe":"mitm-test-server","version":"0.8.3"}
```

## 从源码构建

```bash
# 本机运行（首次运行会在工作目录生成 server-config.toml）
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=mitm-test.local"
cargo run --release

# 静态二进制（部署到任意 Linux，无需 glibc）
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
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
| `max_conn_per_ip` | `32` | 单 IP 并发上限，`0` 为不限制 |
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
.github/workflows/
├── ci.yml      格式 / Clippy / 测试
└── release.yml 构建 musl 二进制、打 tag、发布 Release
```

调试时设置 `MITM_TEST_VERBOSE=1` 可看到握手失败、空请求等噪声日志。

## 发布流程

版本号以 `Cargo.toml` 的 `version` 为唯一来源，Release 由 GitHub Actions 自动完成：

1. 改 `Cargo.toml` 的 `version`；
2. **在 [CHANGELOG.md](CHANGELOG.md) 新增同名 `## [x.y.z]` 段落**，写清新增 / 修复 /
   行为变化（缺这段，发版会直接失败）；
3. 提交并推送到 `main`。

随后 `Release` 工作流会：解析版本号 → 若 `vx.y.z` 标签不存在则构建
`x86_64` / `aarch64` 的 musl 静态二进制（带 Cargo 与目标目录缓存）→ 打包并生成
SHA-256 → 创建并推送 `vx.y.z` 标签 → 把 CHANGELOG 段落作为 Release 说明发布。

也就是说：**每次服务端更新，都必须把更新内容写进 CHANGELOG，最终会原样出现在
Release 页面**。同一版本重复推送不会重复发版。

## 变更记录

见 [CHANGELOG.md](CHANGELOG.md)，历史版本见
[Releases](https://github.com/Anti-MITM-Lab/mitm-test-server/releases)。
