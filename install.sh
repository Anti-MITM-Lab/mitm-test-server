#!/usr/bin/env bash
# mitm-test-server 一键安装 / 升级 / 卸载脚本（面向 Linux）
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/Anti-MITM-Lab/mitm-test-server/main/install.sh | sudo bash
#   sudo bash install.sh --version 0.9.0 --bind 0.0.0.0:8443
#   sudo bash install.sh --auto-port            # 端口被占用时自动顺延
#   sudo bash install.sh --uninstall            # 卸载（保留配置与数据）
#   sudo bash install.sh --uninstall --purge    # 彻底删除
#
# 行为说明：
#   * 二进制装到 /usr/local/bin，配置 /etc/mitm-test，数据 /var/lib/mitm-test
#   * 安装前检测端口占用；占用时默认报错退出，加 --auto-port 则自动挑选空闲端口
#   * 自动识别并配置 ufw / firewalld / iptables / nftables，放行监听端口
#     （未启用防火墙或无法识别时只提示，不会改动系统）
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
UNIT_PATH=""

VERSION="latest"
BIND_ADDR="0.0.0.0:8443"
BIND_HOST="0.0.0.0"
BIND_PORT="8443"
TOKEN=""
MIRROR=""
LOCAL_BINARY=""

INSTALL_SERVICE=1
GEN_CERT=1
FORCE_CONFIG=0
PURGE=0
UNINSTALL=0
DRY_RUN=0

# 端口被占用时是否自动顺延
AUTO_PORT=0

# 防火墙：auto 自动识别；none 表示跳过
FIREWALL="auto"
ENABLE_FIREWALL=1
FIREWALL_BACKEND=""
FIREWALL_RESULT="未处理"

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

基本选项：
  --version <ver>    安装指定版本（如 0.9.0 或 v0.9.0），默认 latest
  --bind <addr>      监听地址，默认 0.0.0.0:8443
  --port <port>      只改端口，保留 --bind 的主机部分
  --auto-port        端口被占用时自动顺延到下一个空闲端口
  --token <token>    指定友军暗号；默认随机生成（升级时沿用旧值）
  --prefix <dir>     安装前缀，默认 /usr/local
  --mirror <url>     GitHub 下载加速前缀，如 https://ghfast.top/
  --binary <path>    使用本地已编译好的二进制（离线安装），跳过下载

防火墙：
  --firewall <backend>  auto | ufw | firewalld | iptables | nft | none，默认 auto
  --no-firewall         跳过防火墙放行（等价 --firewall none）

其他：
  --force-config     覆盖已有 server-config.toml（默认保留）
  --no-cert          不生成自签证书（已有正式证书时使用）
  --no-systemd       不安装 systemd 服务，仅放置二进制与配置
  --uninstall        卸载服务、二进制与已添加的防火墙规则
  --purge            与 --uninstall 一起用：同时删除配置与数据
  --dry-run          只打印将要执行的动作
  -h, --help         显示本帮助

说明：
  仅当防火墙处于启用状态时才会写入放行规则；脚本不会启用或重载未知防火墙。
  iptables / nftables 的规则默认不持久化，重启后可能失效（脚本会提示）。

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
            --port)         set_bind_port "${2:?--port 需要一个值}"; shift 2 ;;
            --port=*)       set_bind_port "${1#*=}"; shift ;;
            --auto-port)    AUTO_PORT=1; shift ;;
            --token)        TOKEN="${2:?--token 需要一个值}"; shift 2 ;;
            --token=*)      TOKEN="${1#*=}"; shift ;;
            --prefix)       PREFIX="${2:?--prefix 需要一个值}"; shift 2 ;;
            --prefix=*)     PREFIX="${1#*=}"; shift ;;
            --mirror)       MIRROR="${2:?--mirror 需要一个值}"; shift 2 ;;
            --mirror=*)     MIRROR="${1#*=}"; shift ;;
            --binary)       LOCAL_BINARY="${2:?--binary 需要一个值}"; shift 2 ;;
            --binary=*)     LOCAL_BINARY="${1#*=}"; shift ;;
            --firewall)     FIREWALL="${2:?--firewall 需要一个值}"; shift 2 ;;
            --firewall=*)   FIREWALL="${1#*=}"; shift ;;
            --no-firewall)  ENABLE_FIREWALL=0; FIREWALL="none"; shift ;;
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

set_bind_port() {
    local port="$1"
    validate_port "$port"
    BIND_ADDR="${BIND_ADDR%:*}:${port}"
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

validate_port() {
    case "$1" in
        ''|*[!0-9]*) die "端口必须是数字: $1" ;;
    esac
    if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        die "端口超出范围 1-65535: $1"
    fi
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

# 解析要安装的 release tag（形如 v0.9.0）。
resolve_tag() {
    if [ "$VERSION" = "latest" ]; then
        log "查询最新版本……" >&2
        local json tag
        json="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null)" \
            || die "查询最新版本失败；请用 --version 指定版本，或用 --mirror 指定加速地址"
        tag="$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1 || true)"
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

# 安全地重写文本文件（dry-run 时只消费输入）。
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

# ==================== 端口检测 ====================

# 从 bind_addr 拆出主机与端口，并做基本校验。
split_bind() {
    local port="${BIND_ADDR##*:}"
    BIND_HOST="${BIND_ADDR%:*}"
    [ "$BIND_HOST" = "$BIND_ADDR" ] && [ -n "$port" ] && BIND_HOST="0.0.0.0"
    [ -n "$BIND_HOST" ] || BIND_HOST="0.0.0.0"
    validate_port "$port"
    BIND_PORT="$port"
    BIND_ADDR="${BIND_HOST}:${BIND_PORT}"
}

# 端口是否已有监听。
port_in_use() {
    local port="$1" output=""

    if command -v ss >/dev/null 2>&1; then
        # 先取输出再判断，避免 `| grep -q` 在 pipefail 下被 SIGPIPE 误伤。
        output="$(ss -H -l -n -t "sport = :${port}" 2>/dev/null || true)"
        [ -n "$output" ] && return 0
        return 1
    fi

    if command -v netstat >/dev/null 2>&1; then
        output="$(netstat -lnt 2>/dev/null || true)"
        grep -qE "[:.]${port}[[:space:]]" <<< "$output" && return 0
        return 1
    fi

    # 兜底：用 bash 的 /dev/tcp 试着连一下本机端口。
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
        return 0
    fi

    warn "缺少 ss/netstat，无法检测端口 ${port} 是否被占用"
    return 1
}

# 打印占用端口的进程信息（尽力而为）。
port_owner() {
    local port="$1" line=""
    if command -v ss >/dev/null 2>&1; then
        line="$(ss -H -l -n -t -p "sport = :${port}" 2>/dev/null | head -n 1 || true)"
    fi
    if [ -z "$line" ] && command -v lsof >/dev/null 2>&1; then
        line="$(lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | awk 'NR == 2 { print $1" (pid "$2")" }' || true)"
    fi
    printf '%s\n' "${line:-未知进程}"
}

# 从 start 往上找空闲端口（最多试 200 个）。
find_free_port() {
    local start="$1"
    # 注意：不能写在同一条 local 里，$((start + 1)) 会在 local 生效前展开。
    local candidate=$((start + 1))
    local limit=$((start + 200))
    while [ "$candidate" -le 65535 ] && [ "$candidate" -le "$limit" ]; do
        if ! port_in_use "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
        candidate=$((candidate + 1))
    done
    return 1
}

# 已有配置时以配置里的监听地址为准（除非 --force-config）。
resolve_bind() {
    local cfg="$CONFIG_DIR/server-config.toml"
    if [ -f "$cfg" ] && [ "$FORCE_CONFIG" -ne 1 ]; then
        local saved
        saved="$(sed -n 's/^[[:space:]]*bind_addr[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$cfg" | head -n 1 || true)"
        if [ -n "$saved" ]; then
            if [ "$saved" != "$BIND_ADDR" ]; then
                warn "已有配置监听 ${saved}，本次保留；如需改为 ${BIND_ADDR} 请加 --force-config"
            fi
            BIND_ADDR="$saved"
            log "沿用已有监听地址: ${BIND_ADDR}"
        fi
    fi
    split_bind
}

# 升级场景下旧服务可能还占着端口，先停掉再检测。
stop_running_service() {
    [ "$INSTALL_SERVICE" -eq 1 ] || return 0
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null || return 0

    log "检测到 ${SERVICE_NAME} 正在运行，先停止以释放端口"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] systemctl stop ${SERVICE_NAME}"
        return 0
    fi
    systemctl stop "$SERVICE_NAME" || warn "停止旧服务失败，端口检测可能不准"

    # 等端口真正释放（最多 3 秒）。
    local i=0
    while [ "$i" -lt 10 ] && port_in_use "$BIND_PORT"; do
        sleep 0.3
        i=$((i + 1))
    done
}

# 确保端口可用；占用时按 --auto-port 决定顺延还是报错。
ensure_port_free() {
    if ! port_in_use "$BIND_PORT"; then
        log "端口 ${BIND_PORT}/tcp 可用"
        return 0
    fi

    local owner
    owner="$(port_owner "$BIND_PORT")"

    if [ "$AUTO_PORT" -eq 1 ]; then
        local next
        next="$(find_free_port "$BIND_PORT")" \
            || die "端口 ${BIND_PORT} 被占用（${owner}），且从该端口往上 200 个端口内未找到空闲端口"
        warn "端口 ${BIND_PORT} 已被占用（${owner}），自动改用 ${next}"
        BIND_PORT="$next"
        BIND_ADDR="${BIND_HOST}:${BIND_PORT}"
    else
        die "端口 ${BIND_PORT} 已被占用（${owner}）。可改用其他端口：--bind ${BIND_HOST}:<端口> 或 --port <端口>，也可加 --auto-port 自动顺延"
    fi
}

# ==================== 防火墙 ====================

# 识别当前启用的防火墙；只有确实启用的才自动加规则。
detect_firewall() {
    if [ "$ENABLE_FIREWALL" -eq 0 ]; then
        FIREWALL_BACKEND="none"
        return 0
    fi
    if [ "$FIREWALL" != "auto" ]; then
        case "$FIREWALL" in
            ufw|firewalld|iptables|nft|none) FIREWALL_BACKEND="$FIREWALL" ;;
            *) die "未知防火墙类型: $FIREWALL（可选 auto|ufw|firewalld|iptables|nft|none）" ;;
        esac
        return 0
    fi

    local ufw_state="" iptables_rules=""

    # 先一次性取回输出再匹配：避免 `cmd | head | grep -q` 在 pipefail 下
    # 因上游被 SIGPIPE 杀掉而误判（真实 ufw status 会输出多行）。
    if command -v ufw >/dev/null 2>&1; then
        ufw_state="$(ufw status 2>/dev/null || true)"
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables_rules="$(iptables -S INPUT 2>/dev/null || true)"
    fi

    if [ -n "$ufw_state" ] && grep -qi "Status: active" <<< "$ufw_state"; then
        FIREWALL_BACKEND="ufw"
    elif command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null || true)" = "running" ]; then
        FIREWALL_BACKEND="firewalld"
    elif command -v nft >/dev/null 2>&1 && nft list chain inet filter input >/dev/null 2>&1; then
        FIREWALL_BACKEND="nft"
    elif [ -n "$iptables_rules" ] && grep -qE '^(-A INPUT |-P INPUT (DROP|REJECT))' <<< "$iptables_rules"; then
        FIREWALL_BACKEND="iptables"
    else
        FIREWALL_BACKEND="none"
    fi
}

open_firewall_port() {
    detect_firewall

    case "$FIREWALL_BACKEND" in
        none)
            FIREWALL_RESULT="未检测到启用中的防火墙（已跳过）"
            log "未检测到启用中的防火墙，跳过放行；若使用云厂商安全组，请手动放行 ${BIND_PORT}/tcp"
            ;;
        ufw)
            local ufw_rules
            ufw_rules="$(ufw status 2>/dev/null || true)"
            if grep -qE "^${BIND_PORT}/tcp[[:space:]]+ALLOW" <<< "$ufw_rules"; then
                FIREWALL_RESULT="ufw 已放行 ${BIND_PORT}/tcp（规则已存在）"
                log "ufw 中已有 ${BIND_PORT}/tcp 放行规则"
            else
                log "ufw 放行 ${BIND_PORT}/tcp"
                # 老版本 ufw 不支持 comment，失败则回退到不带注释的写法。
                run ufw allow "${BIND_PORT}/tcp" comment "mitm-test-server" 2>/dev/null \
                    || run ufw allow "${BIND_PORT}/tcp" \
                    || warn "ufw 放行失败，请手动执行: ufw allow ${BIND_PORT}/tcp"
                FIREWALL_RESULT="ufw 已放行 ${BIND_PORT}/tcp"
            fi
            ;;
        firewalld)
            if firewall-cmd --query-port="${BIND_PORT}/tcp" >/dev/null 2>&1; then
                FIREWALL_RESULT="firewalld 已放行 ${BIND_PORT}/tcp（规则已存在）"
                log "firewalld 中已有 ${BIND_PORT}/tcp 放行规则"
            else
                log "firewalld 放行 ${BIND_PORT}/tcp"
                if run firewall-cmd --permanent --add-port="${BIND_PORT}/tcp" >/dev/null 2>&1 \
                    && run firewall-cmd --reload >/dev/null 2>&1; then
                    FIREWALL_RESULT="firewalld 已放行 ${BIND_PORT}/tcp"
                else
                    warn "firewalld 放行失败，请手动执行: firewall-cmd --permanent --add-port=${BIND_PORT}/tcp && firewall-cmd --reload"
                    FIREWALL_RESULT="firewalld 放行失败"
                fi
            fi
            ;;
        iptables)
            if iptables -C INPUT -p tcp --dport "$BIND_PORT" -j ACCEPT >/dev/null 2>&1; then
                FIREWALL_RESULT="iptables 已放行 ${BIND_PORT}/tcp（规则已存在）"
                log "iptables 中已有 ${BIND_PORT}/tcp 放行规则"
            else
                log "iptables 放行 ${BIND_PORT}/tcp"
                run iptables -I INPUT -p tcp --dport "$BIND_PORT" -j ACCEPT \
                    || warn "iptables 放行失败，请手动执行: iptables -I INPUT -p tcp --dport ${BIND_PORT} -j ACCEPT"
                FIREWALL_RESULT="iptables 已放行 ${BIND_PORT}/tcp（重启后失效）"
                warn "iptables 规则默认不持久化，重启后需重新添加；建议改用 ufw/firewalld 或用 iptables-persistent 保存"
            fi
            ;;
        nft)
            local nft_rules
            nft_rules="$(nft list chain inet filter input 2>/dev/null || true)"
            if grep -q "tcp dport ${BIND_PORT} accept" <<< "$nft_rules"; then
                FIREWALL_RESULT="nftables 已放行 ${BIND_PORT}/tcp（规则已存在）"
                log "nftables 中已有 ${BIND_PORT}/tcp 放行规则"
            else
                log "nftables 放行 ${BIND_PORT}/tcp"
                run nft add rule inet filter input tcp dport "$BIND_PORT" accept \
                    || warn "nftables 放行失败，请手动执行: nft add rule inet filter input tcp dport ${BIND_PORT} accept"
                FIREWALL_RESULT="nftables 已放行 ${BIND_PORT}/tcp（重启后失效）"
                warn "nftables 规则未写入配置文件，重启后可能失效；可执行 nft list ruleset > /etc/nftables.conf 保存"
            fi
            ;;
    esac
}

# 卸载时移除之前添加的放行规则（只处理按端口能对应上的）。
close_firewall_port() {
    local port="$1"
    detect_firewall
    case "$FIREWALL_BACKEND" in
        none) return 0 ;;
        ufw)
            local ufw_rules
            ufw_rules="$(ufw status 2>/dev/null || true)"
            if grep -qE "^${port}/tcp[[:space:]]+ALLOW" <<< "$ufw_rules"; then
                log "ufw 移除 ${port}/tcp 放行规则"
                run ufw delete allow "${port}/tcp" >/dev/null 2>&1 \
                    || warn "ufw 规则移除失败，请手动执行: ufw delete allow ${port}/tcp"
            fi
            ;;
        firewalld)
            if firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
                log "firewalld 移除 ${port}/tcp 放行规则"
                run firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 \
                    && run firewall-cmd --reload >/dev/null 2>&1 \
                    || warn "firewalld 规则移除失败，请手动执行: firewall-cmd --permanent --remove-port=${port}/tcp && firewall-cmd --reload"
            fi
            ;;
        iptables)
            if iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
                log "iptables 移除 ${port}/tcp 放行规则"
                run iptables -D INPUT -p tcp --dport "$port" -j ACCEPT \
                    || warn "iptables 规则移除失败，请手动执行: iptables -D INPUT -p tcp --dport ${port} -j ACCEPT"
            fi
            ;;
        nft)
            warn "nftables 规则需手动删除：nft -a list chain inet filter input 找到 handle 后 nft delete rule inet filter input handle <n>"
            ;;
    esac
}

# ==================== 安装步骤 ====================

ensure_paths() {
    case "$CONFIG_DIR" in /*) : ;; *) die "CONFIG_DIR 必须是绝对路径" ;; esac
    case "$DATA_DIR" in /*) : ;; *) die "DATA_DIR 必须是绝对路径" ;; esac
    case "$PREFIX" in /*) : ;; *) die "PREFIX 必须是绝对路径" ;; esac
    UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

    run install -d -m 0755 "$PREFIX/bin"

    # 关键：配置目录必须让服务用户"可进入"（group 的 x 位）。
    # 否则 systemd 启动时会报 status=200/CHDIR（Working directory 无权访问）。
    run install -d -m 0750 -o root -g "$SVC_USER" "$CONFIG_DIR"
    run install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"

    # 对已存在的目录再显式校正一次权限与属组（修复旧版本装坏的实例）。
    if [ "$DRY_RUN" -eq 0 ]; then
        chown "root:${SVC_USER}" "$CONFIG_DIR" 2>/dev/null || true
        chmod 0750 "$CONFIG_DIR" 2>/dev/null || true
        chown "${SVC_USER}:${SVC_USER}" "$DATA_DIR" 2>/dev/null || true
        chmod 0750 "$DATA_DIR" 2>/dev/null || true
    fi
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
    # shellcheck disable=SC2064  # 立即展开 tmpdir
    trap "rm -rf '$tmpdir'" EXIT

    log "下载 ${asset}"
    if [ -z "$MIRROR" ]; then
        log "提示：若下载很慢，可 Ctrl-C 后重试并加 --mirror https://ghproxy.net/ 加速"
    fi
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
        TOKEN="$(sed -n 's/^[[:space:]]*auth_token[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$cfg" | head -n 1 || true)"
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

    log "写入配置: ${cfg}（监听 ${BIND_ADDR}）"
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

# gzip 炸弹：按百分比概率发送"小体积、大解压"的响应（0 = 关闭）
gzip_bomb_ratio = 0
gzip_bomb_mib = 256

# 单连接最多处理几个请求（1 = 不复用连接）
keep_alive_max_requests = 1

# 连接与超时保护
max_connections = 512
max_conn_per_ip = 32
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
# 配置错误时最多重试 5 次/分钟，避免无限重启刷 journal
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
WorkingDirectory=${CONFIG_DIR}
ExecStart=${PREFIX}/bin/${BIN_NAME}
ExecReload=/bin/kill -HUP $MAINPID
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
    # 清掉上一次失败计数，否则重启次数超限时 systemctl 会拒绝启动。
    run systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
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
        if command -v ss >/dev/null 2>&1; then
            local listening
            listening="$(ss -H -l -n -t "sport = :${BIND_PORT}" 2>/dev/null || true)"
            if [ -n "$listening" ]; then
                log "确认 ${BIND_ADDR} 已在监听"
            else
                warn "服务在运行，但未检测到 ${BIND_PORT} 端口监听，请检查 journalctl -u ${SERVICE_NAME}"
            fi
        fi
    else
        warn "服务未能启动，最近日志："
        journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null || true
        warn "排查建议："
        warn "  * 目录权限：ls -ld ${CONFIG_DIR} ${DATA_DIR}（服务用户 ${SVC_USER} 需能进入）"
        warn "  * 端口占用：ss -lntp | grep ${BIND_PORT}"
        warn "  * 证书路径：${CONFIG_DIR}/cert.pem、${CONFIG_DIR}/key.pem"
        warn "修复后执行: systemctl restart ${SERVICE_NAME}"
        return 1
    fi
}

# 卸载时从（可能已被删除的）配置里读端口，用于移除防火墙规则。
config_port() {
    local cfg="$CONFIG_DIR/server-config.toml" bind port
    bind="$(sed -n 's/^[[:space:]]*bind_addr[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$cfg" 2>/dev/null | head -n 1 || true)"
    if [ -z "$bind" ]; then
        printf '%s' "8443"
        return 0
    fi
    port="${bind##*:}"
    case "$port" in
        ''|*[!0-9]*) printf '%s' "8443" ;;
        *) printf '%s' "$port" ;;
    esac
}

do_uninstall() {
    local port
    port="$(config_port)"
    log "开始卸载 ${SERVICE_NAME}（监听端口 ${port}）"

    if command -v systemctl >/dev/null 2>&1; then
        run systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        run systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    fi

    close_firewall_port "$port"

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
  防火墙     ${FIREWALL_RESULT}
  友军暗号   ${TOKEN}

常用命令：
  systemctl status ${SERVICE_NAME}
  journalctl -u ${SERVICE_NAME} -f
  systemctl restart ${SERVICE_NAME}

验证放行（应返回 authorized JSON）：
  curl -k -H "X-Probe-Token: ${TOKEN}" https://127.0.0.1:${BIND_PORT}/

验证投毒（会收到数 MB 垃圾数据，注意流量）：
  curl -k -o /dev/null -w '%{size_download} bytes\\n' https://127.0.0.1:${BIND_PORT}/

提示：
  * 公网部署请把 ${cfg} 里的 cert_path/key_path 换成正式证书
  * 更新日志：https://github.com/${REPO}/releases
  * 升级只需重新运行本脚本，配置、证书与暗号会保留
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

    ensure_user
    ensure_paths

    # 端口：先看已有配置，再停旧服务，最后确认可用性。
    resolve_bind
    stop_running_service
    ensure_port_free

    install_binary
    resolve_token
    write_config
    ensure_cert
    install_service
    open_firewall_port
    print_summary
}

main "$@"
