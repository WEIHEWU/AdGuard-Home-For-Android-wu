#!/system/bin/sh
# ==============================================================================
# AdGuard Home GoGoGo - 轻量全自动软重启自愈守护服务 (service.sh)
# 特性：
# 1. 全局单例锁 (/dev/shm/agh_watchdog.pid + kill -0 + cmdline 校验 + 可选 flock)
# 2. 严格尊重手动停止与模块禁用状态 ($MODDIR/disable 及手动停止标记)
# 3. 30 秒低功耗无锁巡检（严禁申请 Wakelock，不阻断 Android Doze 深度休眠）
# 4. 核心存活时零干扰保留 24h 纯内存统计；netd 软重启清空规则后先幂等清理再重挂
# ==============================================================================

trap '' HUP

MODDIR="${0%/*}"
[ -d "$MODDIR" ] || MODDIR="/data/adb/modules/AdGuardHome"
ADGPATH="/data/adb/modules/AdGuardHome"
AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
MAIN_LOG="$AGH_DIR/agh.log"
PID_FILE="$BIN_DIR/AdGuardHome.pid"
CA_BUNDLE="$BIN_DIR/cacerts.pem"
MODULES_DIR="/data/adb/modules"
AGH_GID=23333
export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"

# 初始化内存级锁目录 (/dev/shm)，兼容 Android Bionic tmpfs；极端只读策略下回退至运行目录
mkdir -p /dev/shm 2>/dev/null
if ( : >> /dev/shm/.agh_probe ) 2>/dev/null; then
    rm -f /dev/shm/.agh_probe 2>/dev/null
    WATCHDOG_PID_FILE="/dev/shm/agh_watchdog.pid"
    WATCHDOG_LOCK_FILE="/dev/shm/agh_watchdog.lock"
    SESSION_STOP_FILE="/dev/shm/agh_manual_stop"
else
    mkdir -p "$AGH_DIR/run" 2>/dev/null
    WATCHDOG_PID_FILE="$AGH_DIR/run/agh_watchdog.pid"
    WATCHDOG_LOCK_FILE="$AGH_DIR/run/agh_watchdog.lock"
    SESSION_STOP_FILE="$AGH_DIR/run/agh_manual_stop"
fi

# 系统语言检测
locale=$(getprop persist.sys.locale 2>/dev/null)
[ -z "$locale" ] && locale="zh"
case "$locale" in zh*) lang=zh ;; *) lang=en ;; esac

log_msg() {
    echo "$(date '+%F %T') $1" >> "$MAIN_LOG" 2>/dev/null
    if [ -f "$MAIN_LOG" ] && [ "$(wc -c < "$MAIN_LOG" 2>/dev/null || echo 0)" -ge 102400 ]; then
        : > "$MAIN_LOG" 2>/dev/null
    fi
}

# 检测是否存在模块禁用标记或手动停止标记
is_manually_stopped() {
    [ -f "$MODDIR/disable" ] && return 0
    [ -f "$MODDIR/remove" ] && return 0
    [ -f "$ADGPATH/disable" ] && return 0
    [ -f "$ADGPATH/remove" ] && return 0
    [ -f "$SESSION_STOP_FILE" ] && return 0
    [ -f "$AGH_DIR/manual_stop" ] && return 0
    [ -f "$AGH_DIR/stopped" ] && return 0
    [ -f "$AGH_DIR/app_pause_active" ] && return 0
    if [ -f "$SCRIPT_DIR/config.prop" ] && grep -qE '^(STOPPED|MANUAL_STOP)=1$' "$SCRIPT_DIR/config.prop" 2>/dev/null; then
        return 0
    fi
    return 1
}

is_module_disabled() {
    [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ] || [ -f "$ADGPATH/disable" ] || [ -f "$ADGPATH/remove" ]
}

# 检测全局单例守护进程是否存活 (kill -0 + /proc/<pid>/cmdline 二重防复用校验)
watchdog_alive() {
    [ -f "$WATCHDOG_PID_FILE" ] || return 1
    old_pid=$(cat "$WATCHDOG_PID_FILE" 2>/dev/null)
    case "$old_pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$old_pid" = "$$" ] && return 1
    if kill -0 "$old_pid" 2>/dev/null; then
        cmdline=$(tr '\000' ' ' < "/proc/$old_pid/cmdline" 2>/dev/null)
        case "$cmdline" in
            *service.sh*--watchdog*) return 0 ;;
        esac
    fi
    rm -f "$WATCHDOG_PID_FILE" 2>/dev/null
    return 1
}

# 检测 AdGuardHome 核心进程是否存活 (O(1) 探测 + /proc/<pid>/comm 防 PID 复用)
agh_running() {
    if [ -f "$PID_FILE" ]; then
        agh_pid=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$agh_pid" ] && kill -0 "$agh_pid" 2>/dev/null; then
            if [ "$(cat "/proc/$agh_pid/comm" 2>/dev/null)" = "AdGuardHome" ]; then
                return 0
            fi
            rm -f "$PID_FILE" 2>/dev/null
        fi
    fi
    pidof AdGuardHome >/dev/null 2>&1
}

# 构建 Android 系统与 APEX Conscrypt 根证书合并包
build_ca_bundle() {
    temp="$CA_BUNDLE.tmp"
    if [ -s "$CA_BUNDLE" ]; then
        for cert_dir in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts /apex/com.android.conscrypt/etc/security/cacerts /data/misc/keychain/cacerts-added; do
            [ -d "$cert_dir" ] || continue
            bundle_mtime=$(stat -c %Y "$CA_BUNDLE" 2>/dev/null)
            source_mtime=$(stat -c %Y "$cert_dir" 2>/dev/null)
            if [ -n "$bundle_mtime" ] && [ -n "$source_mtime" ] && [ "$bundle_mtime" -ge "$source_mtime" ]; then
                return 0
            fi
        done
    fi
    rm -f "$temp" 2>/dev/null
    for cert_dir in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts /apex/com.android.conscrypt/etc/security/cacerts /data/misc/keychain/cacerts-added; do
        [ -d "$cert_dir" ] || continue
        for cert in "$cert_dir"/*; do
            [ -f "$cert" ] || continue
            grep -q '^-----BEGIN CERTIFICATE-----' "$cert" 2>/dev/null || continue
            cat "$cert" >> "$temp" 2>/dev/null
            echo "" >> "$temp"
        done
    done
    if [ -s "$temp" ]; then
        chmod 600 "$temp" 2>/dev/null
        mv -f "$temp" "$CA_BUNDLE" 2>/dev/null
    else
        rm -f "$temp" 2>/dev/null
    fi
}

# 检查指定十进制端口是否未被占用 (0=空闲可用, 1=已被占用)
port_is_free() {
    p_hex=$(printf '%04X' "$1" 2>/dev/null)
    [ -n "$p_hex" ] || return 1
    if [ "$2" = "udp" ]; then
        ! grep -qi ":${p_hex} " /proc/net/udp /proc/net/udp6 2>/dev/null
    else
        ! grep -qi ":${p_hex} " /proc/net/tcp /proc/net/tcp6 2>/dev/null
    fi
}

# 按当前激活模式 (overseas / cn) 拉起 AdGuardHome 核心（核心已存活时绝不重启）
ensure_agh_started() {
    agh_running && return 0

    [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
    case "${RUN_MODE:-overseas}" in
        cn|CN) active_mode="cn" ;;
        *)     active_mode="overseas" ;;
    esac

    # 若主配置文件缺失或意外损坏，自动根据当前激活模式 (overseas / cn) 恢复模板
    if [ ! -s "$BIN_DIR/AdGuardHome.yaml" ] || ! grep -q '^schema_version:' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null; then
        if [ -f "$SCRIPT_DIR/switch_mode.sh" ]; then
            sh "$SCRIPT_DIR/switch_mode.sh" "$active_mode" --no-restart >/dev/null 2>&1
        elif [ -s "$BIN_DIR/AdGuardHome_${active_mode}.yaml" ]; then
            cp -f "$BIN_DIR/AdGuardHome_${active_mode}.yaml" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
        fi
    fi

    build_ca_bundle

    # 优先复用当前配置端口或稳定默认端口 (DNS: 55453, HTTP: 43000)，避免软重启后端口漂移导致管理器失联
    cfg_dns=$(awk '/^dns:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/^[[:space:]]*port:[[:space:]]*[0-9]+/{sub(/.*port:[[:space:]]*/, ""); print; exit}' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null)
    cfg_http=$(sed -n 's/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
    [ -n "$cfg_dns" ] || cfg_dns=55453
    [ -n "$cfg_http" ] || cfg_http=43000

    MAX_TRIES=3
    try_count=0
    while [ "$try_count" -lt "$MAX_TRIES" ]; do
        try_count=$((try_count + 1))
        if [ "$try_count" -eq 1 ] && port_is_free "$cfg_dns" udp && port_is_free "$cfg_http" tcp; then
            R1="$cfg_dns"
            R2="$cfg_http"
        elif [ "$try_count" -eq 1 ] && port_is_free 55453 udp && port_is_free 43000 tcp; then
            R1=55453
            R2=43000
        else
            R1=$((30000 + RANDOM % 35536))
            R2=$((30000 + RANDOM % 35536))
        fi

        sed -i "/^dns:/,/^[^[:space:]]/ s/^\([[:space:]]*port:\) [0-9]*/\1 $R1/; s/^\([[:space:]]*address:\) 127\.0\.0\.1:[0-9]*/\1 127.0.0.1:$R2/" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
        sed -i "s/^redir_port=.*/redir_port=$R1/" "$SCRIPT_DIR/config.prop" 2>/dev/null

        if [ "${ENABLE_SNI:-0}" = "1" ]; then
            echo 0 > /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null
            for rpf in /proc/sys/net/ipv4/conf/*/rp_filter; do
                [ -w "$rpf" ] && echo 2 > "$rpf" 2>/dev/null
            done
        fi

        AGH_TZ="$(getprop persist.sys.timezone 2>/dev/null)"
        [ -n "$AGH_TZ" ] && export TZ="$AGH_TZ"
        export GOGC=50
        export GOMEMLIMIT=64MiB
        export SSL_CERT_DIR="/system/etc/security/cacerts/"
        [ -s "$CA_BUNDLE" ] && export SSL_CERT_FILE="$CA_BUNDLE"

        nsenter -G "$AGH_GID" -t 1 "$BIN_DIR/AdGuardHome" --no-check-update --no-etc-hosts --crash-log "$AGH_DIR/crash.log" --logfile discard 9>&- </dev/null >/dev/null 2>&1 &
        echo "$!" > "$PID_FILE"

        sleep 2
        if agh_running; then
            agh_real_pid=$(pidof AdGuardHome 2>/dev/null | awk '{print $1}')
            [ -n "$agh_real_pid" ] && echo "$agh_real_pid" > "$PID_FILE"
            if [ "$lang" = "zh" ]; then
                log_msg "[INFO] AdGuardHome 核心已就绪 (mode=$active_mode, PID=${agh_real_pid:-unknown}, GID=$AGH_GID, DNS=$R1, HTTP=$R2)"
            else
                log_msg "[INFO] AdGuardHome ready (mode=$active_mode, PID=${agh_real_pid:-unknown}, GID=$AGH_GID, DNS=$R1, HTTP=$R2)"
            fi
            return 0
        fi
    done

    if [ "$lang" = "zh" ]; then
        log_msg "[FATAL] AdGuardHome 连续启动失败 $MAX_TRIES 次，触发熔断保护！"
    else
        log_msg "[FATAL] AdGuardHome failed after $MAX_TRIES attempts, fuse triggered!"
    fi
    return 1
}

# 检查 iptables -t nat -S 中本模块的 DNS 转发链是否完整且无重复叠加
nat_rules_healthy() {
    [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
    redir_port=${redir_port:-55453}
    ENABLE_SNI=${ENABLE_SNI:-0}

    nat_dump=$(iptables -w 2 -t nat -S 2>/dev/null) || return 1
    # 1. OUTPUT 必须挂载唯一一条 -j ADGUARD（缺失或异常重复均视为不健康）
    jump_cnt=$(printf '%s\n' "$nat_dump" | grep -c -- '^-A OUTPUT -j ADGUARD$')
    [ "$jump_cnt" -eq 1 ] || return 1
    # 2. ADGUARD 链必须包含专属 GID 防回环规则与当前 redir_port 的 UDP 53 端口重定向
    printf '%s\n' "$nat_dump" | grep -q -- "--gid-owner $AGH_GID -j RETURN" || return 1
    printf '%s\n' "$nat_dump" | grep -qE -- "^-A ADGUARD .*-p udp .*--dport 53 -j REDIRECT --to-ports ${redir_port}([[:space:]]|\$)" || return 1
    # 3. filter 表 DoT/DoQ 防绕过链必须挂载
    iptables -w 2 -t filter -C OUTPUT -j ADGUARD_DOT >/dev/null 2>&1 || return 1
    # 4. 若开启了 SNI 模式，AGH_SNI 链也必须挂载
    if [ "$ENABLE_SNI" = "1" ]; then
        iptables -w 2 -t filter -C OUTPUT -j AGH_SNI >/dev/null 2>&1 || return 1
    fi
    return 0
}

# 先执行幂等清理，再调用 iptables.sh enable 重新挂载网络转发规则（绝不重复叠加）
remount_nat_rules() {
    reason="${1:-heal}"
    sh "$SCRIPT_DIR/iptables.sh" clean 9>&- >/dev/null 2>&1
    if sh "$SCRIPT_DIR/iptables.sh" enable 9>&- >/dev/null 2>&1; then
        [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
        log_msg "[WATCHDOG] 已完成防火墙规则幂等重挂 (reason=$reason, DNS=${redir_port:-55453})"
        return 0
    fi
    return 1
}

detect_vpn_iface() {
    for iface in /sys/class/net/tun* /sys/class/net/wg* /sys/class/net/ppp*; do
        if [ -d "$iface" ]; then
            echo "on"
            return 0
        fi
    done
    echo "off"
}

# ==============================================================================
# 子命令 1：独立后台单例巡检守护模式 (--watchdog)
# 每 30 秒低功耗巡检一次，严禁申请任何 Wakelock，不阻断息屏深度休眠
# ==============================================================================
if [ "$1" = "--watchdog" ]; then
    # 二次防并发：若内核支持 flock，同时持有非阻塞文件锁（子进程调用显式关闭 fd 9 防止继承）
    if command -v flock >/dev/null 2>&1; then
        exec 9>"$WATCHDOG_LOCK_FILE"
        flock -n 9 || exit 0
    fi
    if watchdog_alive; then
        exit 0
    fi
    echo "$$" > "$WATCHDOG_PID_FILE"
    trap '[ "$(cat "$WATCHDOG_PID_FILE" 2>/dev/null)" = "$$" ] && rm -f "$WATCHDOG_PID_FILE" 2>/dev/null' EXIT INT TERM

    vpn_last=$(detect_vpn_iface)
    cleaned_when_disabled=0

    while true; do
        sleep 30

        # 软重启过渡期间等待 Android 系统服务与 netd 初始化就绪
        [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] || continue

        # 1. 严格尊重手动停止或模块禁用状态：绝不擅自重启核心或挂载规则
        if is_manually_stopped; then
            if is_module_disabled && [ "$cleaned_when_disabled" -eq 0 ]; then
                sh "$SCRIPT_DIR/iptables.sh" clean 9>&- >/dev/null 2>&1
                killall -15 AdGuardHome 2>/dev/null
                sleep 1
                pidof AdGuardHome >/dev/null 2>&1 && killall -9 AdGuardHome 2>/dev/null
                cleaned_when_disabled=1
                log_msg "[WATCHDOG] 检测到模块已禁用 ($MODDIR/disable)，已清理规则并进入静默状态"
            fi
            continue
        fi
        cleaned_when_disabled=0

        # 2. 核心进程检查：仅当 AdGuardHome 不存在时按当前模式拉起；存活时零干预保留 24h 内存统计
        need_remount=0
        remount_reason="soft-reboot-nat"
        if ! agh_running; then
            log_msg "[WATCHDOG] 检测到 AdGuardHome 进程未运行，正在按当前模式恢复核心..."
            if ensure_agh_started; then
                need_remount=1
                remount_reason="core-recovered"
            else
                continue
            fi
        fi

        # 3. 网络规则幂等检查：若 netd 软重启清空了 nat 规则或 VPN 隧道状态变化，先清理再重挂
        vpn_now=$(detect_vpn_iface)
        if [ "$need_remount" -eq 1 ]; then
            remount_nat_rules "$remount_reason"
            vpn_last="$vpn_now"
        elif ! nat_rules_healthy; then
            remount_nat_rules "nat-missing"
            vpn_last="$vpn_now"
        elif [ "$vpn_now" != "$vpn_last" ]; then
            remount_nat_rules "vpn-$vpn_now"
            vpn_last="$vpn_now"
        fi

        # 4. 仅当用户配置了非空 PROXY_URL 订阅链接时，顺带执行单次无驻留同步
        if [ -f "$SCRIPT_DIR/config.prop" ]; then
            proxy_val=$(sed -n 's/^PROXY_URL=//p' "$SCRIPT_DIR/config.prop" 2>/dev/null | tr -d '"' | tr -d "'" | tr -d '[:space:]')
            if [ -n "$proxy_val" ] && [ -f "$SCRIPT_DIR/ProxyConfig.sh" ]; then
                sh "$SCRIPT_DIR/ProxyConfig.sh" --once 9>&- >/dev/null 2>&1
            fi
        fi
    done
    exit 0
fi

# ==============================================================================
# 子命令 2：手动显式停止 / 启动接口 (stop / start)
# ==============================================================================
if [ "$1" = "stop" ] || [ "$1" = "--stop" ]; then
    : > "$SESSION_STOP_FILE" 2>/dev/null
    sh "$SCRIPT_DIR/iptables.sh" clean >/dev/null 2>&1
    killall -15 AdGuardHome 2>/dev/null
    sleep 1
    pidof AdGuardHome >/dev/null 2>&1 && killall -9 AdGuardHome 2>/dev/null
    rm -f "$PID_FILE" 2>/dev/null
    ndc resolver flushenv >/dev/null 2>&1 || true
    log_msg "[INFO] 已收到手动停止指令，服务与防火墙规则已停止，守护进程保持静默"
    exit 0
fi

if [ "$1" = "start" ] || [ "$1" = "--start" ]; then
    rm -f "$SESSION_STOP_FILE" "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" "$AGH_DIR/app_pause_active" 2>/dev/null
fi

# ==============================================================================
# 默认启动入口（开机或软重启由 Magisk / KernelSU / APatch 触发）
# ==============================================================================
find "$ADGPATH" "$SCRIPT_DIR" -type f -name "*.sh" -exec chattr -i {} \; 2>/dev/null

# 检查冲突的 hosts 模块并中止启动
found_hosts=false
for module in "$MODULES_DIR"/*; do
    [ -d "$module" ] && [ -f "$module/system/etc/hosts" ] && {
        found_hosts=true
        touch "$module/remove"
    }
done
if [ "$found_hosts" = true ]; then
    if [ "$lang" = "zh" ]; then
        log_msg "[ERROR] 检测到 hosts 模块，AdGuardHome 启动已中止"
    else
        log_msg "[ERROR] Hosts module detected, AdGuardHome startup aborted"
    fi
    exit 1
fi

# 启动全局唯一后台自愈守护进程（若旧守护已存活则直接跳过拉起，杜绝多次软重启多开）
start_singleton_watchdog() {
    if watchdog_alive; then
        return 0
    fi
    /system/bin/sh "$MODDIR/service.sh" --watchdog </dev/null >/dev/null 2>&1 &
    wd_pid=$!
    [ -n "$wd_pid" ] && echo "$wd_pid" > "$WATCHDOG_PID_FILE" 2>/dev/null
}

# 若当前处于模块禁用或手动停止状态，仅确保单例守护在后台静默待命，不拉起服务
if is_manually_stopped; then
    start_singleton_watchdog
    exit 0
fi

# 1. 核心检查：仅当 AdGuardHome 未运行时才拉起；软重启后若核心仍存活则直接复用
if ! ensure_agh_started; then
    start_singleton_watchdog
    exit 1
fi

# 2. 网络规则检查：仅在规则未挂载或异常时先幂等清理再重挂
if ! nat_rules_healthy; then
    remount_nat_rules "startup"
fi

# 3. 单次执行附加清理与代理同步（无后台死循环）
"$SCRIPT_DIR/NoAdsService.sh" >/dev/null 2>&1 &
"$SCRIPT_DIR/ProxyConfig.sh" --once >/dev/null 2>&1 &

# 4. 确保全局唯一 30 秒低功耗守护循环在线
start_singleton_watchdog
exit 0
