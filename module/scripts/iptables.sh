#!/system/bin/sh
# ==============================================================================
# AdGuard Home for Android - 终极低功耗与精准 SNI 嗅探优化脚本
# 优化重点：
# 1. 彻底根除 /proc 暴力轮询死循环，改用 O(1) 轻量级 kill -0 / pidof 状态探测
# 2. 守护周期延长至 60 秒，息屏期间零额外负载，不阻断系统 Deep Sleep（深度休眠）
# 3. 修复原版 SNI 抓包漏洞，启用“首包精准盘查 + 承载数据流内核极速直通（connbytes）”，
#    既 100% 掐死流氓应用的 HTTPDNS / IP 直连广告，又彻底消除网络高延迟与发热
# 4. IPv6 DNS 阻断由 DROP 改为秒级 REJECT，彻底消灭应用打开时“假死转圈 2 秒”的等待
# ==============================================================================

# 屏蔽软重启 (Soft Reboot) 期间父进程派发的 SIGHUP 信号，确保临时 Root 下后台守护与核心不掉线
trap '' HUP

SH_BIN="/system/bin/sh"
[ -x "$SH_BIN" ] || SH_BIN="/bin/sh"

AGH_DIR="${AGH_DIR:-/data/adb/agh}"
MODDIR="${MODDIR:-/data/adb/modules/AdGuardHome}"
BIN_DIR="$AGH_DIR/bin"
MAIN_LOG="$AGH_DIR/agh.log"
PID_FILE="$BIN_DIR/AdGuardHome.pid"
AGH_GID=23333
export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"

for bb in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox /debug_ramdisk/.magisk/busybox/busybox /sbin/.magisk/busybox/busybox; do
    if [ -x "$bb" ]; then
        command -v awk >/dev/null 2>&1 || awk() { "$bb" awk "$@"; }
        command -v pidof >/dev/null 2>&1 || pidof() { "$bb" pidof "$@"; }
        command -v killall >/dev/null 2>&1 || killall() { "$bb" killall "$@"; }
        break
    fi
done

[ -f "$AGH_DIR/scripts/config.prop" ] && . "$AGH_DIR/scripts/config.prop"
redir_port=${redir_port:-55453}
ENABLE_SNI=${ENABLE_SNI:-0}
VPN_DNS_TAKEOVER=${VPN_DNS_TAKEOVER:-auto}

# 2. 高效检测 AdGuardHome 是否存活与本地 UDP DNS 端口是否真实监听
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

# 4. 清理旧版本及冲突规则 (彻底杜绝粗暴封禁443/853导致VPN无法连接的问题)
clean_legacy_conflicts() {
    while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null; do :; done
    while iptables -w 2 -D OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null; do :; done
    while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j DROP 2>/dev/null; do :; done
    while iptables -w 2 -D OUTPUT -p udp --dport 853 -j DROP 2>/dev/null; do :; done
    while iptables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
}

# 解析放行名单 (/data/adb/agh/app-allow.txt) 对应的 Android 应用 UID，实现内核层 0 延迟精准按应用分流
get_allowlist_uids() {
    [ -s "$AGH_DIR/app-allow.txt" ] && [ -r /data/system/packages.list ] || return 0
    awk '
        NR == FNR {
            sub(/\r$/, "")
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            if ($0 != "" && $0 !~ /^#/) allow[$0] = 1
            next
        }
        ($1 in allow) && $2 ~ /^[0-9]+$/ {
            if (!seen[$2]++) print $2
        }
    ' "$AGH_DIR/app-allow.txt" /data/system/packages.list 2>/dev/null
}

# 5. 精准 SNI 队列规则（首包严密盘查，承载数据流秒级直通 + 宽松 rp_filter 彻底消灭 TCP RST 假死转圈）
rebuild_sni() {
    # 彻底幂等清理旧链（循环移除所有重复跳转）
    while iptables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    iptables -w 2 -t filter -F AGH_SNI 2>/dev/null
    iptables -w 2 -t filter -X AGH_SNI 2>/dev/null
    while ip6tables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F AGH_SNI 2>/dev/null
    ip6tables -w 2 -t filter -X AGH_SNI 2>/dev/null

    [ "$ENABLE_SNI" = "0" ] && return 0

    # 将所有网卡 rp_filter 设为宽松模式 (2)，根治上游核心 snifilter 发送伪造 TCP RST 时因严格反向路径校验失败导致 App 卡顿转圈 10~30 秒的顽疾
    for rpf in /proc/sys/net/ipv4/conf/*/rp_filter; do
        [ -w "$rpf" ] && echo 2 > "$rpf" 2>/dev/null
    done

    sni_queue=$(sed -n 's/^[[:space:]]*queue_num:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
        "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
    [ -z "$sni_queue" ] && sni_queue=7
    [ -z "$sni_ports" ] && sni_ports="443,8443"
    sni_drop_quic=$(awk '/^sni_filter:/{f=1} f && /drop_quic:/{print $2; exit}' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null)
    allow_uids=$(get_allowlist_uids)

    # --- 局域网与本地保留地址段全协议免检直通列表 (LAN / Loopback / Link-Local Bypass) ---
    LAN_BYPASS_IPV4="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4 0.0.0.0/8"
    LAN_BYPASS_IPV6="::1/128 fc00::/7 fe80::/10 ff00::/8 ::ffff:127.0.0.0/104 ::ffff:10.0.0.0/104 ::ffff:172.16.0.0/108 ::ffff:192.168.0.0/112 ::ffff:169.254.0.0/112"

    # --- IPv4 SNI 链配置 ---
    iptables -w 2 -t filter -N AGH_SNI 2>/dev/null
    iptables -w 2 -t filter -A AGH_SNI -o lo -j RETURN
    # 始终豁免 AdGuardHome 自身进程 (uid 0 + gid 23333) 的出站 DoH 与规则订阅更新流量，免进 NFQUEUE 自嗅探
    iptables -w 2 -t filter -A AGH_SNI -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    # 内核级豁免放行名单内的应用 UID（0 延迟、全天候直通，不进 NFQUEUE 嗅探）
    for auid in $allow_uids; do
        iptables -w 2 -t filter -A AGH_SNI -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    # 局域网私有网段与本地回环全协议、全端口直接快速放行（不限制端口与协议，避免 UDP/QUIC 阻断或非标端口受扰；不跳过 198.18.0.0/15 Fake-IP）
    for net in $LAN_BYPASS_IPV4; do
        iptables -w 2 -t filter -A AGH_SNI -d "$net" -j RETURN
    done
    # 阻断 VPN 虚拟隧道内 (tun+ / wg+ / ppp+) 或显式开启 drop_quic 时的 HTTP/3 (QUIC UDP 443/8443)，
    # 强制浏览器/WebView 的异步 fetch/XHR/sendBeacon 毫秒级回退至 TCP 443 接受 SNI 审查，同时绝不影响物理网卡上的 Hysteria2/TUIC 等代理客户端
    if [ "$sni_drop_quic" = "true" ]; then
        iptables -w 2 -t filter -A AGH_SNI -p udp -m multiport --dports "$sni_ports" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || \
            iptables -w 2 -t filter -A AGH_SNI -p udp -m multiport --dports "$sni_ports" -j DROP 2>/dev/null
    else
        for viface in tun+ wg+ ppp+; do
            iptables -w 2 -t filter -A AGH_SNI -o "$viface" -p udp -m multiport --dports "$sni_ports" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || \
                iptables -w 2 -t filter -A AGH_SNI -o "$viface" -p udp -m multiport --dports "$sni_ports" -j DROP 2>/dev/null
        done
    fi
    # 【工业级核心优化】：适配 v2026-10-29 核心多段分片 TLS ClientHello 重组机制 (addSegmentLocked)
    # 1. --tcp-flags SYN,FIN,RST NONE 在内核层直接跳过 SYN 握手包与 FIN/RST 挥手包（0 队列开销）
    # 2. --connbytes 1:8 覆盖连接前 8 个出站包（含 1~6 个分片的后量子 X25519MLKEM768 超大 ClientHello，无论 ACK 或 PSH,ACK 均完整送入 snifilter 重组）
    # 3. 第 9 个包及后续成千上万个音视频/文件数据流直接在内核层 RETURN 直通，彻底杜绝 NFQUEUE 满队列丢包与高延迟发热！
    if iptables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
        --tcp-flags SYN,FIN,RST NONE \
        -m connbytes --connbytes 1:8 --connbytes-mode packets --connbytes-dir original \
        -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
        iptables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" -j RETURN
    else
        # 兼容无 connbytes 扩展模块的兜底规则：仅跳过 <=80 字节的纯 ACK 空确认包，保留 1448B 分片 ClientHello 数据包
        iptables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
            -m length --length 0:80 --tcp-flags ALL ACK -j RETURN 2>/dev/null || \
            iptables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
                --tcp-flags ALL ACK -j RETURN
        iptables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
            --tcp-flags SYN,FIN,RST NONE \
            -j NFQUEUE --queue-num "$sni_queue" --queue-bypass
    fi
    iptables -w 2 -t filter -C OUTPUT -j AGH_SNI 2>/dev/null || \
        iptables -w 2 -t filter -I OUTPUT 1 -j AGH_SNI

    # --- IPv6 SNI 链配置 ---
    ip6tables -w 2 -t filter -N AGH_SNI 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_SNI -o lo -j RETURN
    ip6tables -w 2 -t filter -A AGH_SNI -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        ip6tables -w 2 -t filter -A AGH_SNI -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    for net in $LAN_BYPASS_IPV6; do
        ip6tables -w 2 -t filter -A AGH_SNI -d "$net" -j RETURN 2>/dev/null
    done
    if [ "$sni_drop_quic" = "true" ]; then
        ip6tables -w 2 -t filter -A AGH_SNI -p udp -m multiport --dports "$sni_ports" -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || \
            ip6tables -w 2 -t filter -A AGH_SNI -p udp -m multiport --dports "$sni_ports" -j DROP 2>/dev/null
    else
        for viface in tun+ wg+ ppp+; do
            ip6tables -w 2 -t filter -A AGH_SNI -o "$viface" -p udp -m multiport --dports "$sni_ports" -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || \
                ip6tables -w 2 -t filter -A AGH_SNI -o "$viface" -p udp -m multiport --dports "$sni_ports" -j DROP 2>/dev/null
        done
    fi
    if ip6tables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
        --tcp-flags SYN,FIN,RST NONE \
        -m connbytes --connbytes 1:8 --connbytes-mode packets --connbytes-dir original \
        -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
        ip6tables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" -j RETURN
    else
        ip6tables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
            -m length --length 0:100 --tcp-flags ALL ACK -j RETURN 2>/dev/null || \
            ip6tables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
                --tcp-flags ALL ACK -j RETURN
        ip6tables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
            --tcp-flags SYN,FIN,RST NONE \
            -j NFQUEUE --queue-num "$sni_queue" --queue-bypass
    fi
    ip6tables -w 2 -t filter -C OUTPUT -j AGH_SNI 2>/dev/null || \
        ip6tables -w 2 -t filter -I OUTPUT 1 -j AGH_SNI
}

# 5b. DoT / DoQ 加密 DNS 端口（853, 784, 8853）智能防绕过链
# 仅豁免 AdGuardHome 自身 (uid 0 + gid 23333)、放行名单应用 UID、局域网/回环私有地址，以及「翻墙出国防污染模式」下的 VPN 虚拟网卡 (tun+ / wg+ / ppp+)；
# 在「回国加速模式」或未开 VPN 时拦截 853/784/8853，强制 netd 回退至 53 端口进入 AdGuardHome 过滤国内视频广告
rebuild_dot_guard() {
    takeover_mode="${1:-0}"
    while iptables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    iptables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    iptables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null
    while ip6tables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    ip6tables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null

    allow_uids=$(get_allowlist_uids)
    LAN_BYPASS_IPV4="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4 0.0.0.0/8"
    LAN_BYPASS_IPV6="::1/128 fc00::/7 fe80::/10 ff00::/8 ::ffff:127.0.0.0/104 ::ffff:10.0.0.0/104 ::ffff:172.16.0.0/108 ::ffff:192.168.0.0/112 ::ffff:169.254.0.0/112"

    iptables -w 2 -t filter -N ADGUARD_DOT 2>/dev/null
    iptables -w 2 -t filter -A ADGUARD_DOT -o lo -j RETURN
    iptables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        iptables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    for net in $LAN_BYPASS_IPV4; do
        iptables -w 2 -t filter -A ADGUARD_DOT -d "$net" -j RETURN
    done
    if [ "$takeover_mode" != "0" ]; then
        iptables -w 2 -t filter -A ADGUARD_DOT -o tun+ -j RETURN
        iptables -w 2 -t filter -A ADGUARD_DOT -o wg+ -j RETURN
        iptables -w 2 -t filter -A ADGUARD_DOT -o ppp+ -j RETURN
    fi
    iptables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        iptables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    iptables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || \
        iptables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    iptables -w 2 -t filter -I OUTPUT 1 -j ADGUARD_DOT

    ip6tables -w 2 -t filter -N ADGUARD_DOT 2>/dev/null
    ip6tables -w 2 -t filter -A ADGUARD_DOT -o lo -j RETURN
    ip6tables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        ip6tables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    for net in $LAN_BYPASS_IPV6; do
        ip6tables -w 2 -t filter -A ADGUARD_DOT -d "$net" -j RETURN 2>/dev/null
    done
    if [ "$takeover_mode" != "0" ]; then
        ip6tables -w 2 -t filter -A ADGUARD_DOT -o tun+ -j RETURN
        ip6tables -w 2 -t filter -A ADGUARD_DOT -o wg+ -j RETURN
        ip6tables -w 2 -t filter -A ADGUARD_DOT -o ppp+ -j RETURN
    fi
    ip6tables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        ip6tables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || \
        ip6tables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -I OUTPUT 1 -j ADGUARD_DOT
}

# 5c. 智能零耗电本地判定 VPN DNS 接管模式（仅在启动及 VPN 状态切换瞬间执行 1 次，0 网络请求、0 轮询、0 死循环）
# 返回 0 (true): 强制接管 VPN DNS（海外网络环境 / 回国加速模式，100% 拦截国内外应用与音视频广告）
# 返回 1 (false): 放行 VPN 自身 DNS（仅在漫游回中国大陆且开启翻墙防污染 VPN 时触发，靠 AGH_SNI 拦截广告）
should_takeover_vpn_dns() {
    if [ "$VPN_DNS_TAKEOVER" = "1" ]; then
        echo "takeover" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 0
    elif [ "$VPN_DNS_TAKEOVER" = "0" ]; then
        echo "bypass" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 1
    fi

    has_vpn=0
    for iface in /sys/class/net/tun* /sys/class/net/wg* /sys/class/net/ppp*; do
        if [ -d "$iface" ]; then
            has_vpn=1
            break
        fi
    done

    if [ "$has_vpn" = "0" ]; then
        echo "off" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 0
    fi

    # 第一层：识别知名回国加速 VPN 进程（Malus / QuickFox / 穿梭 / 快帆等），无论身处何地一律强制接管 DNS
    vpn_procs=$(ps -A -o ARGS 2>/dev/null || ps 2>/dev/null)
    if echo "$vpn_procs" | grep -qiE 'in\.malus|getmalus|transocks|shuttle|speedcn|quickfox|sixfast|golink|kanet|flycn|backcn|c2cvpn|haigui|guiyan|unblockcn'; then
        echo "takeover" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 0
    fi

    # 第二层：结合当前运行模式 (RUN_MODE) 与物理蜂窝基站国家码（纯内存读取 getprop，毫秒级）
    # 海外模式 (RUN_MODE=overseas) 且未连接中国大陆基站（非 cn / 非 460）时，本地无 GFW DNS 污染，
    # 无论开启 Clash/Sing-box 分流回国还是 Proton/Nord/WARP，均保持 takeover 强制接管 VPN 53 端口！
    op_country=$(getprop gsm.operator.iso-country 2>/dev/null | tr 'A-Z' 'a-z')
    op_mcc=$(getprop gsm.operator.numeric 2>/dev/null)
    in_mainland_cn=0
    [ "${RUN_MODE:-overseas}" = "cn" ] && in_mainland_cn=1
    case "$op_country" in
        *cn*) in_mainland_cn=1 ;;
    esac
    case "$op_mcc" in
        460*|*,460*) in_mainland_cn=1 ;;
    esac

    if [ "$in_mainland_cn" = "0" ]; then
        echo "takeover" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 0
    fi

    # 第三层：仅当用户漫游回中国大陆境内（cn / 460 基站）时，若开启了翻墙防污染 VPN 或 Fake-IP 隧道则切换为 bypass 防污染
    if ip -4 addr show 2>/dev/null | grep -qE '198\.18\.|172\.19\.' || \
       ip -4 route show table all 2>/dev/null | grep -qE '198\.18\.|172\.19\.' || \
       ip -6 addr show 2>/dev/null | grep -qiE 'fdfe:dcba:9876|fc00::' || \
       ip -6 route show table all 2>/dev/null | grep -qiE 'fdfe:dcba:9876|fc00::/18'; then
        echo "bypass" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 1
    fi
    if echo "$vpn_procs" | grep -qiE 'clash|mihomo|sing-box|singbox|v2ray|nekobox|nb4a|husi|karing|matsuri|sagernet|surfboard|shadowsocks|hiddify|xray|outline|psiphon|lantern|protonvpn|expressvpn|nordvpn|surfshark|mullvad|onedotonedotonedotone'; then
        echo "bypass" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 1
    fi

    echo "bypass" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
    return 1
}

# 6. 应用高效 DNS 重定向规则
apply_rules() {
    [ -f "$AGH_DIR/scripts/config.prop" ] && . "$AGH_DIR/scripts/config.prop"
    redir_port=${redir_port:-55453}
    ENABLE_SNI=${ENABLE_SNI:-0}
    VPN_DNS_TAKEOVER=${VPN_DNS_TAKEOVER:-auto}

    allow_uids=$(get_allowlist_uids)
    should_takeover_vpn_dns
    takeover_vpn=$?

    # 建立 IPv4 DNS 重定向（先幂等移除所有旧跳转再插入唯一跳转，杜绝多次软重启重复叠加）
    while iptables -w 2 -t nat -D OUTPUT -j ADGUARD 2>/dev/null; do :; done
    iptables -w 2 -t nat -N ADGUARD 2>/dev/null
    iptables -w 2 -t nat -F ADGUARD
    iptables -w 2 -t nat -I OUTPUT 1 -j ADGUARD
    # 【核心修复】：始终优先挂载专属 GID (23333) 豁免规则，与系统 netd (uid 0, gid 0) 彻底物理隔离！
    # 无论 WiFi / 回国 VPN 的 DNS 是否与上游 IP (如 1.1.1.1 / 8.8.8.8 / 223.5.5.5) 撞车，
    # netd 发起的 53 端口系统解析 100% 强制进入 AdGuardHome，同时 AGH 自身的 Bootstrap/上游请求永不自回环死锁！
    iptables -w 2 -t nat -A ADGUARD -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    # 应用放行名单 UID 级内核直通（豁免应用内置 DNS 解析器直连请求）
    for auid in $allow_uids; do
        iptables -w 2 -t nat -A ADGUARD -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    # 根据纯本地智能识别结果动态配置 VPN DNS 策略：
    # takeover_vpn=0 时（海外环境 / 回国加速 / 未开 VPN）：所有 53 端口请求（含发往 TUN 虚拟 DNS 172.19.0.2/198.18.0.2 的查询）全部重定向至 AdGuardHome
    # takeover_vpn!=0 时（漫游回大陆且开启翻墙防污染 VPN）：放行 Fake-IP 与 VPN 虚拟网卡 (tun+ / wg+ / ppp+) 的 53 端口，由 AGH_SNI 在 443 握手层拦截广告
    if [ "$takeover_vpn" -ne 0 ]; then
        iptables -w 2 -t nat -A ADGUARD -d 198.18.0.0/15 -j RETURN 2>/dev/null
        iptables -w 2 -t nat -A ADGUARD -d 172.19.0.0/16 -j RETURN 2>/dev/null
        iptables -w 2 -t nat -A ADGUARD -o tun+ -p udp --dport 53 -j RETURN 2>/dev/null
        iptables -w 2 -t nat -A ADGUARD -o tun+ -p tcp --dport 53 -j RETURN 2>/dev/null
        iptables -w 2 -t nat -A ADGUARD -o wg+ -p udp --dport 53 -j RETURN 2>/dev/null
        iptables -w 2 -t nat -A ADGUARD -o wg+ -p tcp --dport 53 -j RETURN 2>/dev/null
        iptables -w 2 -t nat -A ADGUARD -o ppp+ -p udp --dport 53 -j RETURN 2>/dev/null
        iptables -w 2 -t nat -A ADGUARD -o ppp+ -p tcp --dport 53 -j RETURN 2>/dev/null
    fi
    iptables -w 2 -t nat -A ADGUARD -p udp --dport 53 -j REDIRECT --to-ports "$redir_port"
    iptables -w 2 -t nat -A ADGUARD -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port"

    # 建立 IPv6 DNS 接管链：优先使用 ip6tables nat REDIRECT（防 Telstra 等纯 IPv6/464XLAT 移动网络断网），并同步豁免翻墙 VPN 隧道，不支持时自动回退 REJECT
    ip6tables -w 2 -t nat -N ADGUARD6_NAT 2>/dev/null
    ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null
    ip6tables -w 2 -t nat -A ADGUARD6_NAT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    if [ "$takeover_vpn" -ne 0 ]; then
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -d fc00::/18 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -d fdfe:dcba:9876::/48 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o tun+ -p udp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o tun+ -p tcp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o wg+ -p udp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o wg+ -p tcp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o ppp+ -p udp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o ppp+ -p tcp --dport 53 -j RETURN 2>/dev/null
    fi
    if ip6tables -w 2 -t nat -A ADGUARD6_NAT -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null && \
       ip6tables -w 2 -t nat -A ADGUARD6_NAT -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; then
        while ip6tables -w 2 -t nat -D OUTPUT -j ADGUARD6_NAT 2>/dev/null; do :; done
        ip6tables -w 2 -t nat -I OUTPUT 1 -j ADGUARD6_NAT 2>/dev/null
        while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
        ip6tables -w 2 -F ADGUARD6 2>/dev/null
        ip6tables -w 2 -X ADGUARD6 2>/dev/null
    else
        while ip6tables -w 2 -t nat -D OUTPUT -j ADGUARD6_NAT 2>/dev/null; do :; done
        ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null
        ip6tables -w 2 -t nat -X ADGUARD6_NAT 2>/dev/null
        while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
        ip6tables -w 2 -N ADGUARD6 2>/dev/null
        ip6tables -w 2 -F ADGUARD6
        ip6tables -w 2 -I OUTPUT 1 -j ADGUARD6
        ip6tables -w 2 -A ADGUARD6 -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
        for auid in $allow_uids; do
            ip6tables -w 2 -A ADGUARD6 -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
        done
        if [ "$takeover_vpn" -ne 0 ]; then
            ip6tables -w 2 -A ADGUARD6 -d fc00::/18 -j RETURN 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -d fdfe:dcba:9876::/48 -j RETURN 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -o tun+ -p udp --dport 53 -j RETURN 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -o tun+ -p tcp --dport 53 -j RETURN 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -o wg+ -p udp --dport 53 -j RETURN 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -o wg+ -p tcp --dport 53 -j RETURN 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -o ppp+ -p udp --dport 53 -j RETURN 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -o ppp+ -p tcp --dport 53 -j RETURN 2>/dev/null
        fi
        if ! ip6tables -w 2 -A ADGUARD6 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; then
            ip6tables -w 2 -A ADGUARD6 -p udp --dport 53 -j DROP 2>/dev/null
        fi
        if ! ip6tables -w 2 -A ADGUARD6 -p tcp --dport 53 -j REJECT --reject-with tcp-reset 2>/dev/null; then
            ip6tables -w 2 -A ADGUARD6 -p tcp --dport 53 -j DROP 2>/dev/null
        fi
    fi

    # 保护本地 DNS 端口免受公共 Wi-Fi 局域网其他设备探测或滥用（仅允许 lo 回环与本机重定向流量）
    while iptables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
    iptables -w 2 -t filter -N AGH_INPUT 2>/dev/null
    iptables -w 2 -t filter -F AGH_INPUT 2>/dev/null
    iptables -w 2 -t filter -A AGH_INPUT -i lo -j RETURN 2>/dev/null
    iptables -w 2 -t filter -A AGH_INPUT -p udp --dport "$redir_port" -j DROP 2>/dev/null
    iptables -w 2 -t filter -A AGH_INPUT -p tcp --dport "$redir_port" -j DROP 2>/dev/null
    iptables -w 2 -t filter -I INPUT 1 -j AGH_INPUT 2>/dev/null
    while ip6tables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -N AGH_INPUT 2>/dev/null
    ip6tables -w 2 -t filter -F AGH_INPUT 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_INPUT -i lo -j RETURN 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_INPUT -p udp --dport "$redir_port" -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_INPUT -p tcp --dport "$redir_port" -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -I INPUT 1 -j AGH_INPUT 2>/dev/null

    rebuild_dot_guard "$takeover_vpn"
    rebuild_sni
}

# 7. 彻底清理可能残留的热点策略路由与转发规则 (保证热点完全原生稳定)
clean_hotspot_rules() {
    ip rule del pref 99 2>/dev/null
    ip rule del pref 100 2>/dev/null
    ip rule del pref 101 2>/dev/null
    ip route flush table 61 2>/dev/null
    while iptables -w 2 -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; do :; done
    while iptables -w 2 -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; do :; done
}

# 8. 彻底清理所有 DNS / DoT / SNI 接管规则（原子化干净还原原生网络）
clean_all_rules() {
    while iptables -w 2 -t nat -D OUTPUT -j ADGUARD 2>/dev/null; do :; done
    iptables -w 2 -t nat -F ADGUARD 2>/dev/null
    iptables -w 2 -t nat -X ADGUARD 2>/dev/null
    while ip6tables -w 2 -t nat -D OUTPUT -j ADGUARD6_NAT 2>/dev/null; do :; done
    ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null
    ip6tables -w 2 -t nat -X ADGUARD6_NAT 2>/dev/null
    while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
    ip6tables -w 2 -F ADGUARD6 2>/dev/null
    ip6tables -w 2 -X ADGUARD6 2>/dev/null
    while iptables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
    iptables -w 2 -t filter -F AGH_INPUT 2>/dev/null
    iptables -w 2 -t filter -X AGH_INPUT 2>/dev/null
    while ip6tables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F AGH_INPUT 2>/dev/null
    ip6tables -w 2 -t filter -X AGH_INPUT 2>/dev/null
    while iptables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    iptables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    iptables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null
    while ip6tables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    ip6tables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null
    while iptables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    iptables -w 2 -t filter -F AGH_SNI 2>/dev/null
    iptables -w 2 -t filter -X AGH_SNI 2>/dev/null
    while ip6tables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F AGH_SNI 2>/dev/null
    ip6tables -w 2 -t filter -X AGH_SNI 2>/dev/null
    clean_hotspot_rules
    rm -f "$AGH_DIR/app_pause_active" "$AGH_DIR/vpn_mode_status" 2>/dev/null
}

# 9. 刷新网络状态（温和刷新，绝不开关飞行模式打断 VPN）
refresh_network() {
    ndc resolver flushenv 2>/dev/null
}

# 10. 挂载前健康预检 (Pre-flight Check：严禁在此直接拉起核心；若核心未存活或端口未监听，立即执行防断网安全阀卸规则！)
preflight_check() {
    [ -f "$AGH_DIR/scripts/config.prop" ] && . "$AGH_DIR/scripts/config.prop"
    redir_port=${redir_port:-55453}
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if agh_running && udp_port_listening "$redir_port"; then
            agh_real_pid=$(pidof AdGuardHome 2>/dev/null | awk '{print $1}')
            [ -n "$agh_real_pid" ] && echo "$agh_real_pid" > "$PID_FILE" 2>/dev/null
            echo "$(date '+%F %T') [PRE-FLIGHT] 本地 DNS 端口 ($redir_port) 就绪，执行规则接管。" >> "$MAIN_LOG" 2>/dev/null
            return 0
        fi
        sleep 0.2 2>/dev/null || sleep 1
    done
    clean_all_rules
    echo "$(date '+%F %T') [WARNING] AdGuardHome 未存活或端口 ($redir_port) 未监听，已触发防断网安全阀卸载 NAT 规则！" >> "$MAIN_LOG" 2>/dev/null
    return 1
}

# 11. 幂等命令行子指令分发（统一由 service.sh 负责根命名空间核心生命周期与 30 秒低功耗巡检）
case "${1:-}" in
    clean|--clean)
        clean_legacy_conflicts
        clean_all_rules
        exit 0
        ;;
    disable|stop|--disable|--stop)
        mkdir -p /dev/shm 2>/dev/null
        : > /dev/shm/agh_manual_stop 2>/dev/null || { mkdir -p "$AGH_DIR/run" 2>/dev/null; : > "$AGH_DIR/run/agh_manual_stop" 2>/dev/null; }
        clean_legacy_conflicts
        clean_all_rules
        if pidof AdGuardHome >/dev/null 2>&1; then
            killall -15 AdGuardHome 2>/dev/null
            sleep 1
            pidof AdGuardHome >/dev/null 2>&1 && killall -9 AdGuardHome 2>/dev/null
        fi
        rm -f "$PID_FILE" 2>/dev/null
        refresh_network
        exit 0
        ;;
    --reload|--apply-allowlist)
        rm -f /dev/shm/agh_manual_stop "$AGH_DIR/run/agh_manual_stop" \
              "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" "$AGH_DIR/app_pause_active" 2>/dev/null
        [ -f "$AGH_DIR/scripts/config.prop" ] && . "$AGH_DIR/scripts/config.prop"
        redir_port=${redir_port:-55453}
        if agh_running && udp_port_listening "$redir_port"; then
            clean_legacy_conflicts
            clean_hotspot_rules
            apply_rules
            refresh_network
            exit 0
        fi
        # 防断网安全阀：核心未运行或端口未监听时立即卸下规则，绝不挂载死端口
        clean_all_rules
        exit 1
        ;;
    enable|--enable)
        clean_legacy_conflicts
        clean_hotspot_rules
        if preflight_check; then
            apply_rules
            refresh_network
            exit 0
        fi
        clean_all_rules
        exit 1
        ;;
    *)
        # 兼容无参调用与一键修复：清理所有停止锁，100% 统一委托 service.sh --repair 在根命名空间完成自愈与规则挂载
        rm -f /dev/shm/agh_manual_stop "$AGH_DIR/run/agh_manual_stop" \
              "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" "$AGH_DIR/app_pause_active" 2>/dev/null
        if [ -f "$MODDIR/service.sh" ]; then
            exec "$SH_BIN" "$MODDIR/service.sh" --repair
        fi
        clean_all_rules
        exit 1
        ;;
esac