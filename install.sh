#!/usr/bin/env bash
# mitm-test-server 一键安装 / 升级 / 卸载脚本（面向 Linux）
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/Anti-MITM-Lab/mitm-test-server/main/install.sh | sudo bash
#   sudo bash install.sh --version 0.8.0 --bind 0.0.0.0:8443
#   sudo bash install.sh --uninstall          # 卸载（保留配置与数据）
#   sudo bash install.sh --uninstall --purge  # 彻底删除
#
# 行为说明：
#   * 二进制装到 /usr/local/bin，配置 /etc/mitm-test，数据 /var/lib/mitm-test
#   * 首次安装生成随机友军暗号与自签证书；升级时保留已有配置与暗号
#   * 默认注册并启动 systemd 服务；容器等无 systemd 环境可用 --no-systemd
#   * 下载地址可用 --mirror 指定 GitHub 加速前缀（如 --mirror https://ghfast.top/）
#
# 只应部署在自己拥有或已获授权的机器上。

set -euo pipefail

# ==================== 常量与默认值 ====================

REPO="${MITM_TEST_REPO:-Anti-MITM-Lab/mitm-test-server}"
BIN_NAME="mitm-test-server"
SERVICE_NAME="mitm-test-server"
SVC_USER="mitm-test"

PREFIX="/usr/local"
CONFIG_DIR="/etc/mitm-test"
DATA_DIR="/var/lib/mitm-test"
UNIT_PATH="" # 由 CONFIG_DIR 之外单独决定，见下

VERSION="latest"
BIND_ADDR="0.0.0.0:8443"
TOKEN=""
MIRROR=""
LOCAL_BINARY=""

INSTALL_SERVICE=1
GEN_CERT=1
FORCE_CONFIG=0
PURGE=0
UNINSTALL=0
DRY_RUN=0

# ==================== 输出辅助 ====================

if [ -t 1 ] && [ -t 2 ]; then
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
else
    C_GREEN=""; C_YELLOW=""; C_RED=""; C_BOLD=""; C_RESET=""
fi

log()  { printf '%s[+]%s %s\n'  "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n'  "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%s[-]%s %s\n'  "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
mitm-test-server 安装脚本

用法：
  sudo bash install.sh [选项]

选项：
  --version <ver>    安装指定版本（如 0.8.0 或 v0.8.0），默认 latest
  --bind <addr>      监听地址，默认 0.0.0.0:8443
  --token <token>    指定友军暗号；默认随机生成（升级时沿用旧值）
  --prefix <dir>     安装前缀，默认 /usr/local
  --mirror <url>     GitHub 下载加速前缀，如 https://ghfast.top/
  --binary <path>    使用本地已编译好的二进制（离线安装），跳过下载
  --force-config     覆盖已有 server-config.toml（默认保留）
  --no-cert          不生成自签证书（已有正式证书时使用）
  --no-systemd       不安装 systemd 服务，仅放置二进制与配置
  --uninstall        卸载服务与二进制
  --purge            与 --uninstall 一起用：同时删除配置与数据
  --dry-run          只打印将要执行的动作
  -h, --help         显示本帮助

卸载：
  sudo bash install.sh --uninstall
  sudo bash install.sh --uninstall --purge

安装完成后：
  systemctl status mitm-test-server
  journalctl -u mitm-test-server -f
EOF
}

# ==================== 参数解析 ====================

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)      VERSION="${2:?--version 需要一个值}"; shift 2 ;;
            --version=*)    VERSION="${1#*=}"; shift ;;
            --bind)         BIND_ADDR="${2:?--bind 需要一个值}"; shift 2 ;;
            --bind=*)       BIND_ADDR="${1#*=}"; shift ;;
            --token)        TOKEN="${2:?--token 需要一个值}"; shift 2 ;;
            --token=*)      TOKEN="${1#*=}"; shift ;;
            --prefix)       PREFIX="${2:?--prefix 需要一个值}"; shift 2 ;;
            --prefix=*)     PREFIX="${1#*=}"; shift ;;
            --mirror)       MIRROR="${2:?--mirror 需要一个值}"; shift 2 ;;
            --mirror=*)     MIRROR="${1#*=}"; shift ;;
            --binary)       LOCAL_BINARY="${2:?--binary 需要一个值}"; shift 2 ;;
            --binary=*)     LOCAL_BINARY="${1#*=}"; shift ;;
            --force-config) FORCE_CONFIG=1; shift ;;
            --no-cert)      GEN_CERT=0; shift ;;
            --no-systemd)   INSTALL_SERVICE=0; shift ;;
            --uninstall)    UNINSTALL=1; shift ;;
            --purge)        PURGE=1; shift ;;
            --dry-run)      DRY_RUN=1; shift ;;
            -h|--help)      usage; exit 0 ;;
            *)              die "未知参数: $1（用 --help 查看用法）" ;;
        esac
    done
}

# ==================== 基础工具 ====================

require_root() {
    [ "$(id -u)" -eq 0 ] || die "需要 root 权限，请用 sudo 运行"
}

require_linux() {
    case "$(uname -s)" in
        Linux) : ;;
        *) warn "当前系统不是 Linux（$(uname -s)），安装后可能无法运行" ;;
    esac
}

# 下载文件到指定路径。
fetch() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url"
    else
        die "需要 curl 或 wget 才能下载"
    fi
}

# 下载并输出到 stdout。
fetch_stdout() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 "$url"
    else
        wget -qO- "$url"
    fi
}

# 根据 uname -m 选择 release 里的目标三元组。
detect_target() {
    case "$(uname -m)" in
        x86_64|amd64)   TARGET="x86_64-unknown-linux-musl" ;;
        aarch64|arm64)  TARGET="aarch64-unknown-linux-musl" ;;
        *) die "暂不支持该架构: $(uname -m)（可自行编译后用 --binary 安装）" ;;
    esac
}

# 解析要安装的 release tag（形如 v0.8.0）。
resolve_tag() {
    if [ "$VERSION" = "latest" ]; then
        log "查询最新版本……" >&2
        local json tag
        json="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null)" \
            || die "查询最新版本失败；请用 --version 指定版本，或用 --mirror 指定加速地址"
        tag="$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
        [ -n "$tag" ] || die "无法从 GitHub API 解析最新版本号，请用 --version 指定"
        TAG="$tag"
    else
        case "$VERSION" in
            v*) TAG="$VERSION" ;;
            *)  TAG="v$VERSION" ;;
        esac
    fi
}

gen_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
    fi
}

# 安全地重写文本文件。
write_file() {
    local path="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] 将写入 ${path}"
        cat >/dev/null
        return 0
    fi
    cat >"$path"
}

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] $*"
    else
        "$@"
    fi
}

# ==================== 安装步骤 ====================

ensure_paths() {
    case "$CONFIG_DIR" in /*) : ;; *) die "CONFIG_DIR 必须是绝对路径" ;; esac
    case "$DATA_DIR" in /*) : ;; *) die "DATA_DIR 必须是绝对路径" ;; esac
    case "$PREFIX" in /*) : ;; *) die "PREFIX 必须是绝对路径" ;; esac
    UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

    run install -d -m 0755 "$PREFIX/bin"
    run install -d -m 0750 "$CONFIG_DIR"
    run install -d -m 0750 "$DATA_DIR"
}

ensure_user() {
    if id -u "$SVC_USER" >/dev/null 2>&1; then
        return 0
    fi
    command -v useradd >/dev/null 2>&1 || { warn "未找到 useradd，将以 root 运行服务"; SVC_USER="root"; return 0; }
    log "创建系统用户 ${SVC_USER}"
    run useradd --system --home-dir "$DATA_DIR" --shell "$(command -v nologin || echo /usr/sbin/nologin)" \
        --user-group "$SVC_USER"
}

install_binary() {
    local tmpdir=""
    if [ -n "$LOCAL_BINARY" ]; then
        [ -f "$LOCAL_BINARY" ] || die "本地二进制不存在: $LOCAL_BINARY"
        log "使用本地二进制: $LOCAL_BINARY"
        run install -m 0755 "$LOCAL_BINARY" "$PREFIX/bin/${BIN_NAME}"
        return 0
    fi

    local asset="${BIN_NAME}-${TAG}-${TARGET}.tar.gz"
    local url="${MIRROR}https://github.com/${REPO}/releases/download/${TAG}/${asset}"
    tmpdir="$(mktemp -d)"
    # shellcheck disable=SC2064  # 这里就是要用当前值立即展开
    trap "rm -rf '$tmpdir'" EXIT

    log "下载 ${asset}"
    fetch "$url" "$tmpdir/$asset"

    if fetch "$url.sha256" "$tmpdir/$asset.sha256" 2>/dev/null; then
        if command -v sha256sum >/dev/null 2>&1; then
            log "校验 SHA-256"
            ( cd "$tmpdir" && sha256sum -c "$asset.sha256" ) || die "校验失败，下载内容可能被篡改"
        else
            warn "系统缺少 sha256sum，跳过校验"
        fi
    else
        warn "未找到校验文件 ${asset}.sha256，跳过校验"
    fi

    tar -xzf "$tmpdir/$asset" -C "$tmpdir" || die "解压失败: $asset"
    [ -f "$tmpdir/$BIN_NAME" ] || die "压缩包内未找到 $BIN_NAME"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] 将安装 $tmpdir/$BIN_NAME -> $PREFIX/bin/$BIN_NAME"
    else
        install -m 0755 "$tmpdir/$BIN_NAME" "$PREFIX/bin/${BIN_NAME}"
    fi
}

# 升级时沿用旧暗号，避免所有探针突然失效。
resolve_token() {
    local cfg="$CONFIG_DIR/server-config.toml"
    if [ -n "$TOKEN" ]; then
        return 0
    fi
    if [ -f "$cfg" ]; then
        TOKEN="$(sed -n 's/^[[:space:]]*auth_token[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$cfg" | head -n 1)"
    fi
    if [ -z "${TOKEN}" ]; then
        TOKEN="$(gen_token)"
        log "已生成新的友军暗号"
    else
        log "沿用已有友军暗号"
    fi
}

write_config() {
    local cfg="$CONFIG_DIR/server-config.toml"
    if [ -f "$cfg" ] && [ "$FORCE_CONFIG" -ne 1 ]; then
        log "保留已有配置: ${cfg}（如需重写加 --force-config）"
        return 0
    fi

    log "写入配置: ${cfg}"
    write_file "$cfg" <<EOF
# 由 install.sh 生成。修改后需 systemctl restart ${SERVICE_NAME}
bind_addr = "${BIND_ADDR}"
cert_path = "${CONFIG_DIR}/cert.pem"
key_path = "${CONFIG_DIR}/key.pem"

# 友军暗号：X-Probe-Token / Authorization: Bearer / ?token= 三选一
auth_token = "${TOKEN}"

db_path = "${DATA_DIR}/mitm_intel.db"

# 单次投毒规模与节奏
min_garbage_bytes = 1500000
max_garbage_bytes = 8000000
chunk_size = 8192
poison_deadline_secs = 600

# 连接与超时保护
max_connections = 512
header_timeout_secs = 8
handshake_timeout_secs = 10

# 自动反向举报（留空关闭）。填了 Key 后请 systemctl restart
abuseipdb_api_key = ""
report_cooldown_secs = 3600
EOF

    if [ "$DRY_RUN" -eq 0 ]; then
        chmod 0640 "$cfg"
        chown "root:${SVC_USER}" "$cfg" 2>/dev/null || true
    fi
}

ensure_cert() {
    local cert="$CONFIG_DIR/cert.pem" key="$CONFIG_DIR/key.pem"
    if [ "$GEN_CERT" -ne 1 ]; then
        return 0
    fi
    if [ -s "$cert" ] && [ -s "$key" ]; then
        log "保留已有证书: ${cert}"
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        warn "未安装 openssl，跳过证书生成；请手动放置 ${cert} 与 ${key}"
        return 0
    fi

    local cn san
    cn="${MITM_TEST_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"
    san="DNS:${cn},DNS:localhost,IP:127.0.0.1"

    log "生成自签证书（CN=${cn}，3650 天）"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] 将生成 ${cert} / ${key}"
        return 0
    fi

    if ! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$key" -out "$cert" -subj "/CN=${cn}" \
        -addext "subjectAltName=${san}" >/dev/null 2>&1; then
        warn "带 SAN 的自签失败，回退到基础自签（老版本 openssl 无 -addext）"
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout "$key" -out "$cert" -subj "/CN=${cn}" >/dev/null 2>&1 \
            || { warn "证书生成失败，请手动放置 ${cert} 与 ${key}"; return 0; }
    fi

    chmod 0644 "$cert"
    chmod 0640 "$key"
    chown "root:${SVC_USER}" "$cert" "$key" 2>/dev/null || true
}

install_service() {
    if [ "$INSTALL_SERVICE" -ne 1 ]; then
        warn "按要求跳过 systemd 服务；可手动运行: cd ${CONFIG_DIR} && ${PREFIX}/bin/${BIN_NAME}"
        return 0
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "未检测到 systemd，跳过服务安装；可手动运行: cd ${CONFIG_DIR} && ${PREFIX}/bin/${BIN_NAME}"
        return 0
    fi

    log "写入 systemd 单元: ${UNIT_PATH}"
    write_file "$UNIT_PATH" <<EOF
[Unit]
Description=mitm-test-server anti-MITM honeypot
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
WorkingDirectory=${CONFIG_DIR}
ExecStart=${PREFIX}/bin/${BIN_NAME}
Restart=on-failure
RestartSec=3s
LimitNOFILE=65535
StateDirectory=${DATA_DIR#/var/lib/}
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF

    run systemctl daemon-reload
    if ! run systemctl enable --now "$SERVICE_NAME" 2>/dev/null; then
        warn "systemctl enable/start 失败（容器环境常见），可手动运行: cd ${CONFIG_DIR} && ${PREFIX}/bin/${BIN_NAME}"
        return 0
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi

    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "服务已启动"
    else
        warn "服务未能启动，最近日志："
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null || true
    fi
}

do_uninstall() {
    log "开始卸载 ${SERVICE_NAME}"
    if command -v systemctl >/dev/null 2>&1; then
        run systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        run systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    fi
    if [ -f "$UNIT_PATH" ]; then
        run rm -f "$UNIT_PATH"
        command -v systemctl >/dev/null 2>&1 && run systemctl daemon-reload || true
    fi
    run rm -f "$PREFIX/bin/${BIN_NAME}"

    if [ "$PURGE" -eq 1 ]; then
        warn "删除配置与数据: ${CONFIG_DIR} ${DATA_DIR}"
        run rm -rf "$CONFIG_DIR" "$DATA_DIR"
        if id -u "$SVC_USER" >/dev/null 2>&1; then
            run userdel "$SVC_USER" 2>/dev/null || true
        fi
    else
        log "已保留配置 ${CONFIG_DIR} 与数据 ${DATA_DIR}（彻底删除加 --purge）"
    fi
    log "卸载完成"
}

print_summary() {
    local cfg="$CONFIG_DIR/server-config.toml"
    cat <<EOF

${C_BOLD}安装完成${C_RESET}
  版本       ${TAG}
  二进制     ${PREFIX}/bin/${BIN_NAME}
  配置       ${cfg}
  数据       ${DATA_DIR}/mitm_intel.db
  监听       ${BIND_ADDR}
  友军暗号   ${TOKEN}

常用命令：
  systemctl status ${SERVICE_NAME}
  journalctl -u ${SERVICE_NAME} -f
  systemctl restart ${SERVICE_NAME}

验证放行（应返回 authorized JSON）：
  curl -k -H "X-Probe-Token: ${TOKEN}" https://127.0.0.1:${BIND_ADDR##*:}/

验证投毒（会收到数 MB 垃圾数据，注意流量）：
  curl -k -o /dev/null -w '%{size_download} bytes\\n' https://127.0.0.1:${BIND_ADDR##*:}/

提示：
  * 公网部署请把 ${cfg} 里的 cert_path/key_path 换成正式证书
  * 更新日志：https://github.com/${REPO}/releases
  * 升级只需重新运行本脚本，配置与暗号会保留
EOF
}

main() {
    parse_args "$@"
    require_root

    # 统一把 mirror 规范成"带结尾斜杠"的前缀，便于直接拼在 URL 前面。
    MIRROR="${MIRROR%/}"
    [ -z "$MIRROR" ] || MIRROR="${MIRROR}/"

    if [ "$UNINSTALL" -eq 1 ]; then
        UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
        do_uninstall
        exit 0
    fi

    require_linux
    detect_target
    if [ -n "$LOCAL_BINARY" ]; then
        TAG="${VERSION}"
        case "$TAG" in latest|v*) : ;; *) TAG="v${TAG}" ;; esac
    else
        resolve_tag
    fi

    log "目标平台 ${TARGET}，版本 ${TAG}"

    ensure_paths
    ensure_user
    install_binary
    resolve_token
    write_config
    ensure_cert
    install_service
    print_summary
}

main "$@"
