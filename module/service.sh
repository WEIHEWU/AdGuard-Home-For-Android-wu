#!/system/bin/sh
# ==============================================================================
# AdGuard Home GoGoGo - 统一核心控制与软重启自愈守护引擎 (service.sh)
# 特性：
# 1. 全局内存单例锁 (/dev/shm/agh_watchdog.pid + kill -0 + cmdline 校验，兼容 Android mksh)
# 2. 脱离 App su -c 会话与 cgroup (escape_app_cgroup + setsid + nsenter -t 1 根命名空间)
# 3. 防断网安全阀：核心未存活或端口未监听时立即卸载 nat ADGUARD 规则，绝不死锁断网
# 4. 30 秒无锁低功耗巡检（0 Wakelock），核心存活零干扰保留 24h 内存统计
# ==============================================================================

trap '' HUP

ADGPATH="/data/adb/modules/AdGuardHome"
case "$0" in
    /*) MODDIR="${0%/*}" ;;
    *)  MODDIR="$ADGPATH" ;;
esac
[ -d "$MODDIR" ] || MODDIR="$ADGPATH"
SELF_SCRIPT="$MODDIR/service.sh"
[ -f "$SELF_SCRIPT" ] || SELF_SCRIPT="$0"

AGH_DIR="${AGH_DIR:-/data/adb/agh}"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
MAIN_LOG="$AGH_DIR/agh.log"
PID_FILE="$BIN_DIR/AdGuardHome.pid"
CA_BUNDLE="$BIN_DIR/cacerts.pem"
MODULES_DIR="/data/adb/modules"
AGH_GID=23333
export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"

SH_BIN="/system/bin/sh"
[ -x "$SH_BIN" ] || SH_BIN="/bin/sh"

# 探测 Magisk / KernelSU / APatch 内置完整 BusyBox（Android Toybox nsenter 不支持 -G 23333！）
find_busybox() {
    for bb in \
        /data/adb/ksu/bin/busybox \
        /data/adb/ap/bin/busybox \
        /data/adb/magisk/busybox \
        /debug_ramdisk/.magisk/busybox/busybox \
        /sbin/.magisk/busybox/busybox; do
        [ -x "$bb" ] && { echo "$bb"; return 0; }
    done
    command -v busybox 2>/dev/null && return 0
    return 1
}
BB_BIN="$(find_busybox)"
if [ -n "$BB_BIN" ]; then
    command -v awk >/dev/null 2>&1 || awk() { "$BB_BIN" awk "$@"; }
    command -v pidof >/dev/null 2>&1 || pidof() { "$BB_BIN" pidof "$@"; }
    command -v killall >/dev/null 2>&1 || killall() { "$BB_BIN" killall "$@"; }
fi

# 初始化内存级锁目录 (/dev/shm)，兼容 Android Bionic tmpfs
mkdir -p /dev/shm 2>/dev/null
if ( : >> /dev/shm/.agh_probe ) 2>/dev/null; then
    rm -f /dev/shm/.agh_probe 2>/dev/null
    WATCHDOG_PID_FILE="/dev/shm/agh_watchdog.pid"
    SESSION_STOP_FILE="/dev/shm/agh_manual_stop"
else
    mkdir -p "$AGH_DIR/run" 2>/dev/null
    WATCHDOG_PID_FILE="$AGH_DIR/run/agh_watchdog.pid"
    SESSION_STOP_FILE="$AGH_DIR/run/agh_manual_stop"
fi

# 脱离 Manager App su -c 派生的应用级 cgroup (uid_10xxx) 与 Freezer 冻结组，迁入根 cgroup
escape_app_cgroup() {
    target_pid="${1:-$$}"
    for cg in \
        /sys/fs/cgroup/cgroup.procs \
        /sys/fs/cgroup/freezer/cgroup.procs \
        /dev/freezer/cgroup.procs \
        /dev/cpuset/cgroup.procs \
        /dev/cpuset/tasks \
        /dev/cpuctl/cgroup.procs \
        /dev/cpuctl/tasks \
        /dev/stune/cgroup.procs \
        /dev/stune/tasks \
        /acct/cgroup.procs \
        /acct/tasks; do
        [ -w "$cg" ] && echo "$target_pid" > "$cg" 2>/dev/null
    done
}
escape_app_cgroup "$$"

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

# 主动清理所有手动停止锁标记（切换模式 / 网络刷新 / 一键修复 / 显式启动时第一时间调用）
clear_stop_locks() {
    rm -f /dev/shm/agh_manual_stop "$AGH_DIR/run/agh_manual_stop" \
          "$SESSION_STOP_FILE" "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" \
          "$AGH_DIR/app_pause_active" 2>/dev/null
    if [ -f "$SCRIPT_DIR/config.prop" ]; then
        sed -i '/^STOPPED=/d; /^MANUAL_STOP=/d' "$SCRIPT_DIR/config.prop" 2>/dev/null
    fi
}

# 检测是否存在模块禁用标记或显式手动停止标记
is_module_disabled() {
    [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ] || [ -f "$ADGPATH/disable" ] || [ -f "$ADGPATH/remove" ]
}

is_manually_stopped() {
    is_module_disabled && return 0
    [ -f "$SESSION_STOP_FILE" ] && return 0
    [ -f "$AGH_DIR/manual_stop" ] && return 0
    [ -f "$AGH_DIR/stopped" ] && return 0
    [ -f "$AGH_DIR/app_pause_active" ] && return 0
    if [ -f "$SCRIPT_DIR/config.prop" ] && grep -qE '^(STOPPED|MANUAL_STOP)=1$' "$SCRIPT_DIR/config.prop" 2>/dev/null; then
        return 0
    fi
    return 1
}

# 检测全局单例守护进程是否存活 (kill -0 + /proc/<pid>/cmdline 防 PID 复用，零外部 flock 依赖)
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

# 检测 AdGuardHome 核心进程是否存活
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

# 安全终止旧 AdGuardHome 进程并循环等待进程与套接字彻底释放（最多等 2 秒，未退则 kill -9）
stop_agh_wait() {
    if pidof AdGuardHome >/dev/null 2>&1; then
        killall -15 AdGuardHome 2>/dev/null || {
            for p in $(pidof AdGuardHome 2>/dev/null); do kill -15 "$p" 2>/dev/null; done
        }
        if sleep 0.1 2>/dev/null; then
            w=0
            while [ "$w" -lt 20 ]; do
                pidof AdGuardHome >/dev/null 2>&1 || break
                sleep 0.1 2>/dev/null
                w=$((w + 1))
            done
        else
            w=0
            while [ "$w" -lt 2 ]; do
                pidof AdGuardHome >/dev/null 2>&1 || break
                sleep 1
                w=$((w + 1))
            done
        fi
        if pidof AdGuardHome >/dev/null 2>&1; then
            killall -9 AdGuardHome 2>/dev/null || {
                for p in $(pidof AdGuardHome 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
            }
            sleep 0.3 2>/dev/null || sleep 1
        fi
    fi
    rm -f "$PID_FILE" 2>/dev/null
}

# 精准检查本机监听端口状态：仅匹配第 2 列 local_address，且 TCP 仅将 0A (LISTEN) 视为占用（忽略 TIME_WAIT）
udp_port_listening() {
    p_hex=$(printf '%04X' "$1" 2>/dev/null)
    [ -n "$p_hex" ] || return 1
    for f in /proc/net/udp /proc/net/udp6; do
        [ -r "$f" ] || continue
        if grep -qiE "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-Fa-f]+:${p_hex}[[:space:]]" "$f" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

port_is_free() {
    p_hex=$(printf '%04X' "$1" 2>/dev/null)
    [ -n "$p_hex" ] || return 1
    if [ "$2" = "udp" ]; then
        ! udp_port_listening "$1"
    else
        for f in /proc/net/tcp /proc/net/tcp6; do
            [ -r "$f" ] || continue
            if grep -qiE "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-Fa-f]+:${p_hex}[[:space:]]+[0-9A-Fa-f]+:[0-9A-Fa-f]+[[:space:]]+0A[[:space:]]" "$f" 2>/dev/null; then
                return 1
            fi
        done
        return 0
    fi
}

# 防断网安全阀：一旦核心未运行或端口未监听，立即卸下 iptables nat ADGUARD 转发规则，严禁将系统 DNS 导向死端口
disarm_nat_safety_valve() {
    [ -f "$SCRIPT_DIR/iptables.sh" ] && "$SH_BIN" "$SCRIPT_DIR/iptables.sh" clean >/dev/null 2>&1
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

# 以 setsid + BusyBox/util-linux nsenter 切入 PID 1 根命名空间与专属 GID 23333，关闭全部标准句柄独立拉起核心
spawn_agh_in_root_ns() {
    escape_app_cgroup "$$"
    TRUE_BIN="/system/bin/true"
    [ -x "$TRUE_BIN" ] || TRUE_BIN="true"

    SETSID_CMD=""
    if [ -n "$BB_BIN" ] && "$BB_BIN" setsid "$TRUE_BIN" >/dev/null 2>&1; then
        SETSID_CMD="$BB_BIN setsid"
    elif command -v setsid >/dev/null 2>&1; then
        SETSID_CMD="setsid"
    fi

    # 1. 优先使用 Magisk/KSU/APatch 内置 BusyBox nsenter（100% 支持 -G 23333，规避 Android Toybox nsenter 无 -G 报错）
    if [ -n "$BB_BIN" ]; then
        if "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 &
            SPAWN_PID=$!
            return 0
        elif "$BB_BIN" nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 &
            SPAWN_PID=$!
            return 0
        elif "$BB_BIN" nsenter -t 1 -m -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -n -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 &
            SPAWN_PID=$!
            return 0
        elif "$BB_BIN" nsenter -t 1 -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD "$BB_BIN" nsenter -t 1 -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 &
            SPAWN_PID=$!
            return 0
        fi
    fi

    # 2. 次选系统 util-linux nsenter（兼容标准 Linux ARM64 环境）
    if command -v nsenter >/dev/null 2>&1; then
        if nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 &
            SPAWN_PID=$!
            return 0
        elif nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 &
            SPAWN_PID=$!
            return 0
        elif nsenter -t 1 -m -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -t 1 -m -n -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 &
            SPAWN_PID=$!
            return 0
        elif nsenter -G "$AGH_GID" -t 1 "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -G "$AGH_GID" -t 1 "$@" </dev/null >/dev/null 2>&1 &
            SPAWN_PID=$!
            return 0
        elif command -v setpriv >/dev/null 2>&1 && \
             nsenter -t 1 -m -u -i -n setpriv --egid "$AGH_GID" --rgid "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -t 1 -m -u -i -n setpriv --egid "$AGH_GID" --rgid "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 &
            SPAWN_PID=$!
            return 0
        fi
    fi

    # 3. 极端非特权容器测试环境兜底
    $SETSID_CMD "$@" </dev/null >/dev/null 2>&1 &
    SPAWN_PID=$!
    return 0
}

# 按当前激活模式 (overseas / cn) 拉起核心并确认 UDP 端口真实就绪（核心已存活监听时绝不重启）
ensure_agh_started() {
    if agh_running; then
        [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
        if udp_port_listening "${redir_port:-55453}"; then
            return 0
        fi
    fi

    # 启动前先启动安全阀卸载劫持规则，并确保无残留僵尸进程占端口
    disarm_nat_safety_valve
    stop_agh_wait

    [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
    case "${RUN_MODE:-overseas}" in
        cn|CN) active_mode="cn" ;;
        *)     active_mode="overseas" ;;
    esac

    # 若主配置文件缺失或校验不通过，自动从当前模式模板恢复
    if [ ! -s "$BIN_DIR/AdGuardHome.yaml" ] || \
       ! "$BIN_DIR/AdGuardHome" --check-config -c "$BIN_DIR/AdGuardHome.yaml" -w "$BIN_DIR" >/dev/null 2>&1; then
        if [ -f "$SCRIPT_DIR/switch_mode.sh" ]; then
            "$SH_BIN" "$SCRIPT_DIR/switch_mode.sh" "$active_mode" --no-restart >/dev/null 2>&1
        elif [ -s "$BIN_DIR/AdGuardHome_${active_mode}.yaml" ]; then
            cp -f "$BIN_DIR/AdGuardHome_${active_mode}.yaml" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
        fi
    fi

    build_ca_bundle

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
            rand_seed=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
            [ -z "$rand_seed" ] && rand_seed="${RANDOM:-12345}"
            R1=$((30000 + (rand_seed % 25000)))
            R2=$((30000 + ((rand_seed + 7919) % 25000)))
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

        SPAWN_PID=""
        spawn_agh_in_root_ns "$BIN_DIR/AdGuardHome" \
            -c "$BIN_DIR/AdGuardHome.yaml" \
            -w "$BIN_DIR" \
            --no-check-update \
            --no-etc-hosts \
            --crash-log "$AGH_DIR/crash.log" \
            --logfile discard
        [ -n "$SPAWN_PID" ] && echo "$SPAWN_PID" > "$PID_FILE"

        # 轮询等待进程存活且本地 UDP 端口真实完成绑定监听（最快 0.2s 响应，最长等 8s）
        ready=0
        if sleep 0.2 2>/dev/null; then
            step=0
            while [ "$step" -lt 40 ]; do
                if agh_running && udp_port_listening "$R1"; then
                    ready=1
                    break
                fi
                sleep 0.2 2>/dev/null
                step=$((step + 1))
            done
        else
            step=0
            while [ "$step" -lt 8 ]; do
                if agh_running && udp_port_listening "$R1"; then
                    ready=1
                    break
                fi
                sleep 1
                step=$((step + 1))
            done
        fi

        if [ "$ready" -eq 1 ] && agh_running; then
            agh_real_pid=$(pidof AdGuardHome 2>/dev/null | awk '{print $1}')
            if [ -n "$agh_real_pid" ]; then
                echo "$agh_real_pid" > "$PID_FILE"
                escape_app_cgroup "$agh_real_pid"
            fi
            if [ "$lang" = "zh" ]; then
                log_msg "[INFO] AdGuardHome 核心已就绪 (mode=$active_mode, PID=${agh_real_pid:-unknown}, GID=$AGH_GID, DNS=$R1, HTTP=$R2)"
            else
                log_msg "[INFO] AdGuardHome ready (mode=$active_mode, PID=${agh_real_pid:-unknown}, GID=$AGH_GID, DNS=$R1, HTTP=$R2)"
            fi
            return 0
        fi

        stop_agh_wait
    done

    disarm_nat_safety_valve
    if [ "$lang" = "zh" ]; then
        log_msg "[FATAL] AdGuardHome 连续启动失败 $MAX_TRIES 次，已卸载防火墙规则确保原生网络畅通！"
    else
        log_msg "[FATAL] AdGuardHome failed after $MAX_TRIES attempts, NAT unmounted to keep internet alive!"
    fi
    return 1
}

# 检查 iptables -t nat -S 中本模块的 DNS 转发链是否完整且无重复叠加
nat_rules_healthy() {
    [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
    redir_port=${redir_port:-55453}
    ENABLE_SNI=${ENABLE_SNI:-0}

    nat_dump=$(iptables -w 2 -t nat -S 2>/dev/null) || return 1
    jump_cnt=$(printf '%s\n' "$nat_dump" | grep -c -- '^-A OUTPUT -j ADGUARD$')
    [ "$jump_cnt" -eq 1 ] || return 1
    printf '%s\n' "$nat_dump" | grep -q -- "--gid-owner $AGH_GID -j RETURN" || return 1
    printf '%s\n' "$nat_dump" | grep -qE -- "^-A ADGUARD .*-p udp .*--dport 53 -j REDIRECT --to-ports ${redir_port}([[:space:]]|\$)" || return 1
    iptables -w 2 -t filter -C OUTPUT -j ADGUARD_DOT >/dev/null 2>&1 || return 1
    if [ "$ENABLE_SNI" = "1" ]; then
        iptables -w 2 -t filter -C OUTPUT -j AGH_SNI >/dev/null 2>&1 || return 1
    fi
    return 0
}

# 幂等重挂网络转发规则（挂前严格确认核心存活且端口已监听，否则立即卸载防断网）
remount_nat_rules() {
    reason="${1:-heal}"
    [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
    if ! agh_running || ! udp_port_listening "${redir_port:-55453}"; then
        disarm_nat_safety_valve
        return 1
    fi
    "$SH_BIN" "$SCRIPT_DIR/iptables.sh" clean >/dev/null 2>&1
    if "$SH_BIN" "$SCRIPT_DIR/iptables.sh" enable >/dev/null 2>&1; then
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

# 在根命名空间与独立会话中确保全局唯一后台守护循环在线（由子进程自身原子写入真实 $$，避免 setsid 派生覆写竞争）
start_singleton_watchdog() {
    if watchdog_alive; then
        return 0
    fi
    escape_app_cgroup "$$"
    TRUE_BIN="/system/bin/true"
    [ -x "$TRUE_BIN" ] || TRUE_BIN="true"
    SETSID_CMD=""
    if [ -n "$BB_BIN" ] && "$BB_BIN" setsid "$TRUE_BIN" >/dev/null 2>&1; then
        SETSID_CMD="$BB_BIN setsid"
    elif command -v setsid >/dev/null 2>&1; then
        SETSID_CMD="setsid"
    fi
    if [ -n "$BB_BIN" ] && "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F "$TRUE_BIN" >/dev/null 2>&1; then
        $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F "$SH_BIN" "$SELF_SCRIPT" --watchdog </dev/null >/dev/null 2>&1 &
    elif [ -n "$BB_BIN" ] && "$BB_BIN" nsenter -t 1 -m -n "$TRUE_BIN" >/dev/null 2>&1; then
        $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -n "$SH_BIN" "$SELF_SCRIPT" --watchdog </dev/null >/dev/null 2>&1 &
    elif command -v nsenter >/dev/null 2>&1 && nsenter -t 1 -m -n "$TRUE_BIN" >/dev/null 2>&1; then
        $SETSID_CMD nsenter -t 1 -m -n "$SH_BIN" "$SELF_SCRIPT" --watchdog </dev/null >/dev/null 2>&1 &
    else
        $SETSID_CMD "$SH_BIN" "$SELF_SCRIPT" --watchdog </dev/null >/dev/null 2>&1 &
    fi
    sleep 0.1 2>/dev/null || true
}

# ==============================================================================
# 子命令 1：独立后台单例巡检守护模式 (--watchdog)
# 每 30 秒低功耗巡检一次，零 Wakelock，不阻断息屏 Doze 深度休眠
# ==============================================================================
if [ "$1" = "--watchdog" ]; then
    escape_app_cgroup "$$"
    if watchdog_alive; then
        exit 0
    fi
    echo "$$" > "$WATCHDOG_PID_FILE" 2>/dev/null
    trap '[ "$(cat "$WATCHDOG_PID_FILE" 2>/dev/null)" = "$$" ] && rm -f "$WATCHDOG_PID_FILE" 2>/dev/null' EXIT INT TERM

    vpn_last=$(detect_vpn_iface)
    cleaned_when_disabled=0

    while true; do
        sleep 30

        # 软重启过渡期间等待 Android 系统服务与 netd 初始化就绪
        boot_ok=$(getprop sys.boot_completed 2>/dev/null)
        [ -z "$boot_ok" ] || [ "$boot_ok" = "1" ] || continue

        # 1. 严格尊重手动停止或模块禁用状态：绝不擅自重启核心或挂载规则
        if is_manually_stopped; then
            if is_module_disabled && [ "$cleaned_when_disabled" -eq 0 ]; then
                disarm_nat_safety_valve
                stop_agh_wait
                cleaned_when_disabled=1
                log_msg "[WATCHDOG] 检测到模块已禁用 ($MODDIR/disable)，已清理规则并进入静默状态"
            fi
            continue
        fi
        cleaned_when_disabled=0

        # 2. 核心与端口健康检查：若未运行或端口异常，先卸规则防断网再自愈拉起；存活正常则零干预保留 24h 内存统计
        [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
        need_remount=0
        remount_reason="nat-missing"
        if ! agh_running || ! udp_port_listening "${redir_port:-55453}"; then
            disarm_nat_safety_valve
            log_msg "[WATCHDOG] 检测到 AdGuardHome 未运行或端口未监听，正在按当前模式恢复核心..."
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

        # 4. 仅当用户配置了非空 PROXY_URL 订阅链接时，执行单次同步
        if [ -f "$SCRIPT_DIR/config.prop" ]; then
            proxy_val=$(sed -n 's/^PROXY_URL=//p' "$SCRIPT_DIR/config.prop" 2>/dev/null | tr -d '"' | tr -d "'" | tr -d '[:space:]')
            if [ -n "$proxy_val" ] && [ -f "$SCRIPT_DIR/ProxyConfig.sh" ]; then
                "$SH_BIN" "$SCRIPT_DIR/ProxyConfig.sh" --once >/dev/null 2>&1
            fi
        fi
    done
    exit 0
fi

# ==============================================================================
# 子命令 2：热重启核心接口 (--restart，供 switch_mode.sh 模式切换统一复用)
# ==============================================================================
if [ "$1" = "restart" ] || [ "$1" = "--restart" ]; then
    clear_stop_locks
    # 先卸下 NAT 劫持规则防切换瞬间死锁断网，再干净等待旧进程释放端口
    disarm_nat_safety_valve
    stop_agh_wait
    start_singleton_watchdog
    if ensure_agh_started; then
        remount_nat_rules "mode-switch"
        ndc resolver flushenv >/dev/null 2>&1 || true
        ndc resolver flushdefaultif >/dev/null 2>&1 || true
        cmd netd resolver flushdefaultif >/dev/null 2>&1 || true
        exit 0
    fi
    disarm_nat_safety_valve
    exit 1
fi

# ==============================================================================
# 子命令 3：一键修复 / 网络刷新接口 (--repair，供 Manager App 网络刷新与一键修复统一调用)
# ==============================================================================
if [ "$1" = "repair" ] || [ "$1" = "--repair" ]; then
    clear_stop_locks
    start_singleton_watchdog
    if ensure_agh_started; then
        remount_nat_rules "manual-repair"
        ndc resolver flushenv >/dev/null 2>&1 || true
        ndc resolver flushdefaultif >/dev/null 2>&1 || true
        cmd netd resolver flushdefaultif >/dev/null 2>&1 || true
        exit 0
    fi
    disarm_nat_safety_valve
    exit 1
fi

# ==============================================================================
# 子命令 4：显式手动停止 / 启动接口 (stop / start)
# ==============================================================================
if [ "$1" = "stop" ] || [ "$1" = "--stop" ]; then
    : > "$SESSION_STOP_FILE" 2>/dev/null
    disarm_nat_safety_valve
    stop_agh_wait
    ndc resolver flushenv >/dev/null 2>&1 || true
    log_msg "[INFO] 已收到手动停止指令，核心与防火墙规则已卸下，守护进程保持静默"
    exit 0
fi

if [ "$1" = "start" ] || [ "$1" = "--start" ]; then
    clear_stop_locks
fi

# ==============================================================================
# 默认启动入口（开机或软重启由 Magisk / KernelSU / APatch 自动触发）
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
    disarm_nat_safety_valve
    if [ "$lang" = "zh" ]; then
        log_msg "[ERROR] 检测到 hosts 模块，AdGuardHome 启动已中止"
    else
        log_msg "[ERROR] Hosts module detected, AdGuardHome startup aborted"
    fi
    exit 1
fi

if is_manually_stopped; then
    disarm_nat_safety_valve
    start_singleton_watchdog
    exit 0
fi

if ! ensure_agh_started; then
    disarm_nat_safety_valve
    start_singleton_watchdog
    exit 1
fi

if ! nat_rules_healthy; then
    remount_nat_rules "startup"
fi

[ -f "$SCRIPT_DIR/NoAdsService.sh" ] && "$SH_BIN" "$SCRIPT_DIR/NoAdsService.sh" >/dev/null 2>&1 &
[ -f "$SCRIPT_DIR/ProxyConfig.sh" ] && "$SH_BIN" "$SCRIPT_DIR/ProxyConfig.sh" --once >/dev/null 2>&1 &

start_singleton_watchdog
exit 0
