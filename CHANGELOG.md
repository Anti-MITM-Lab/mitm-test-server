# 更新日志

本项目所有值得注意的变更都记录在这里。格式参考
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

> **发版规则**：修改 `Cargo.toml` 里的版本号时，必须同时在本文件新增对应的
> `## [x.y.z]` 段落。Release 工作流会用它生成 GitHub Release 的说明；
> 缺少该段落会导致发版直接失败。升级类改动请写清"行为变化"，避免用户升级后踩坑。

## [Unreleased]

## [0.8.0] - 2026-11-09

### 新增

- 一键安装脚本 `install.sh`：自动下载 musl 静态二进制、创建系统用户、生成配置与
  自签证书、注册 systemd 服务；支持 `--version` / `--mirror` / `--binary`（离线）
  与 `--uninstall [--purge]`，升级时保留原有配置与友军暗号。
- GitHub Actions：`CI` 工作流做格式、Clippy、测试与构建校验；`Release` 工作流按
  `Cargo.toml` 版本号自动打 tag 并发布多架构二进制（x86_64 / aarch64，musl 静态）。
- 投毒形态扩展为五种：`html`、`binary`、`endless`（不发送分块终止符）、
  `redirect`（302 循环）、`error`，并按权重随机。
- 响应指纹随机化：`Server` / `X-Powered-By` / `Date`（±3 秒）/ `ETag` / Cookie /
  CDN 头，四套 persona 保证头之间自洽；页面内引用随机静态资源诱导后续请求。
- 投毒节奏控制：分块长度抖动，2% 概率插入 0.8~2 秒长停顿（tarpit）。
- 威胁情报库新增 `user_agent`、`request_target`、`payload_kind`、`bytes_sent` 列，
  并在启动时自动迁移 0.7 及更早版本的旧表。
- 并发上限（`max_connections`）、TLS 握手超时、读头超时、写入超时与
  Ctrl-C / SIGTERM 优雅退出。
- 配置校验：非法值（空暗号、`min > max`、`chunk_size` 越界等）在启动时直接报错。

### 修复

- 修复 ALPN 声明 `h2` 却未实现 HTTP/2，导致 h2 客户端连接卡死的问题；现在只声明
  `http/1.1`。**行为变化**：不再协商 HTTP/2。
- 修复暗号匹配大小写敏感、只读取请求头前 1024 字节、`X-Probe-Token: `<token>``
  含空格时匹配失败等问题；改为读取完整请求头（上限 16 KiB）并做常量时间比较。
- 修复配置文件解析失败时静默回退默认值、可能用错误暗号把友军一起投毒的问题；
  现在解析失败直接退出。
- 修复每次入库都新建 SQLite 连接、可能阻塞异步任务的问题；改为单写线程
  + 无锁 channel（WAL 模式）。

### 变更

- `src/main.rs` 拆分为 `config` / `server` / `http` / `payload` / `db` / `report` /
  `logging` 七个模块，补齐模块级与关键逻辑注释，统一 `cargo fmt` 风格。
- 友军探针的响应由 2 字节 `OK` 改为 JSON：`{"status":"authorized",...}`，
  并附带 `X-Probe-Result: authorized` 头。
- 暗号支持三种传递方式：`X-Probe-Token`、`Authorization: Bearer`、`?token=`。
- AbuseIPDB 举报按来源 IP 冷却去重（默认 1 小时），避免重复举报浪费配额；
  举报内容带上请求方法与路径，便于复核。
- 版本号升至 0.8.0，新增 release 构建配置（LTO、`codegen-units=1`、strip）。
