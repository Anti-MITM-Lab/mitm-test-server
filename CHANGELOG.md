# 更新日志

本项目所有值得注意的变更都记录在这里。格式参考
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

> **发版规则**：修改 `Cargo.toml` 里的版本号时，必须同时在本文件新增对应的
> `## [x.y.z]` 段落。Release 工作流会用它生成 GitHub Release 的说明；
> 缺少该段落会导致发版直接失败。升级类改动请写清"行为变化"，避免用户升级后踩坑。

## [Unreleased]

## [0.8.3] - 2026-11-09

### 修复

- 修复 systemd 启动失败 `status=200/CHDIR`（`Changing to the requested working
  directory failed: Permission denied`）：配置目录 `/etc/mitm-test` 原来被建成
  `root:root 0750`，服务用户 `mitm-test` 既不是属主也不在属组，无法进入该目录。
  现在目录创建时即设为 `root:mitm-test 0750`，数据目录设为 `mitm-test:mitm-test`，
  并对已存在的目录显式校正权限与属组（升级安装即可修好旧实例）。
- 服务启动失败不再只打印一行警告就宣称"安装完成"：现在会给出排查建议
  （目录权限 / 端口占用 / 证书路径）并以非零状态退出，便于脚本与自动化发现失败。
- 下载前提示可用 `--mirror` 加速，减少国内网络下等待时误以为卡死的情况。

## [0.8.2] - 2026-11-09

### 修复

- 修复安装脚本在 `set -o pipefail` 下，`ufw status | head -n 1 | grep -q` 因上游被
  SIGPIPE 杀掉而误判"防火墙未启用"的问题：现在先取回命令输出再匹配。该问题会导致
  **卸载时检测不到已添加的 ufw 规则、规则残留**，以及重复安装时可能重复添加放行规则。
- 同类问题一并修正：`ss`/`netstat` 的端口占用判断、`nft` 规则检查、服务启动后的
  监听确认、以及版本/暗号解析中的 `sed | head` 管道。

## [0.8.1] - 2026-11-09

### 新增

- 安装脚本支持端口检测：安装前检查监听端口是否被占用，被占用时打印占用进程并给出
  可执行建议（`--port` / `--bind` / `--auto-port`）。
- `--auto-port`：端口被占用时自动向上寻找空闲端口（最多尝试 200 个），并把实际
  端口写入配置与安装摘要。
- 安装脚本自动配置防火墙：识别 ufw、firewalld、iptables、nftables，放行监听端口；
  规则已存在时不会重复添加。仅对**处于启用状态**的防火墙动手，不会自行启用防火墙。
- `--firewall <auto|ufw|firewalld|iptables|nft|none>` 与 `--no-firewall`，可显式指定
  或跳过防火墙配置。
- 服务启动后确认端口确实进入监听状态，失败时提示查看 `journalctl`。
- 卸载时自动移除按端口添加的防火墙放行规则（nftables 因缺少稳定句柄仅提示手动删除）。

### 变更

- 升级安装会先停止旧服务以释放端口，安装完成后再启动；配置、证书与暗号仍然保留。
- `--port` 可只改端口而保留 `--bind` 的主机部分；已有配置存在时以其 `bind_addr`
  为准，并提示用 `--force-config` 才能改写。

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
