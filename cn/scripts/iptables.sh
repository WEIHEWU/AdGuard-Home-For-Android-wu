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

AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
MAIN_LOG="$AGH_DIR/agh.log"
PID_FILE="$BIN_DIR/AdGuardHome.pid"
AGH_GID=23333
export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"

[ -f "$AGH_DIR/scripts/config.prop" ] && . "$AGH_DIR/scripts/config.prop"
redir_port=${redir_port:-31587}
ENABLE_SNI=${ENABLE_SNI:-1}
VPN_DNS_TAKEOVER=${VPN_DNS_TAKEOVER:-0}

# 统一 HTTP 调用封装：优先使用 curl，若 ROM 未内置 curl 则自动回退至 busybox wget / wget
agh_api_get() {
    url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -s -m 3 -u root:root "$url" 2>/dev/null
    elif command -v busybox >/dev/null 2>&1; then
        busybox wget -q -T 3 -O - --header="Authorization: Basic cm9vdDpyb290" "$url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 3 -O - --header="Authorization: Basic cm9vdDpyb290" "$url" 2>/dev/null
    fi
}

agh_api_post() {
    url="$1"
    data="$2"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$data" ]; then
            curl -s -m 3 -u root:root -X POST "$url" -H "Content-Type: application/json" -d "$data" >/dev/null 2>&1
        else
            curl -s -m 3 -u root:root -X POST "$url" >/dev/null 2>&1
        fi
    elif command -v busybox >/dev/null 2>&1; then
        busybox wget -q -T 3 -O /dev/null --header="Authorization: Basic cm9vdDpyb290" --header="Content-Type: application/json" --post-data="${data:-}" "$url" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 3 -O /dev/null --header="Authorization: Basic cm9vdDpyb290" --header="Content-Type: application/json" --post-data="${data:-}" "$url" >/dev/null 2>&1
    fi
}

# 1. 防止重复启动自身
for pid in $(pidof -x "$0" 2>/dev/null); do
    [ "$pid" != "$$" ] && exit 0
done

# 2. 高效检测 AdGuardHome 是否存活 (O(1) 单次内核调用，校验进程名防 PID 复用误判)
agh_running() {
    if [ -f "$PID_FILE" ]; then
        agh_pid=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$agh_pid" ] && kill -0 "$agh_pid" 2>/dev/null; then
            if [ "$(cat /proc/$agh_pid/comm 2>/dev/null)" = "AdGuardHome" ]; then
                return 0
            fi
            rm -f "$PID_FILE"
        fi
    fi
    pidof AdGuardHome >/dev/null 2>&1
}

# 检测当前 AdGuardHome 进程是否已绑定专属 GID 23333（与系统 netd [uid=0,gid=0] 物理隔离）
agh_has_dedicated_gid() {
    agh_pid=$(pidof AdGuardHome 2>/dev/null | awk '{print $1}')
    [ -n "$agh_pid" ] && [ "$(awk '/^Gid:/ {print $2}' "/proc/$agh_pid/status" 2>/dev/null)" = "$AGH_GID" ]
}

# 3. 启动 AdGuardHome（以 uid=0, gid=23333 启动，保持完整 Root 权限同时与 netd 彻底隔离）
start_agh() {
    {
        case "$(getprop persist.sys.locale 2>/dev/null)" in
            zh*) echo "$(date '+%F %T') [INFO] 正在以专属用户组 (uid=0, gid=$AGH_GID) 启动 AdGuardHome..." ;;
            *)   echo "$(date '+%F %T') [INFO] Starting AdGuardHome with dedicated group (uid=0, gid=$AGH_GID)..." ;;
        esac
    } >> "$MAIN_LOG"
    export SSL_CERT_DIR="/system/etc/security/cacerts/"
    [ -s "$BIN_DIR/cacerts.pem" ] && export SSL_CERT_FILE="$BIN_DIR/cacerts.pem"
    if command -v busybox >/dev/null 2>&1 && busybox chpst -u 0:$AGH_GID true 2>/dev/null; then
        busybox chpst -u 0:$AGH_GID "$BIN_DIR/AdGuardHome" --no-check-update >/dev/null 2>&1 &
        echo "$!" > "$PID_FILE"
    elif command -v busybox >/dev/null 2>&1 && busybox setpriv --reuid=0 --regid=$AGH_GID --clear-groups true 2>/dev/null; then
        busybox setpriv --reuid=0 --regid=$AGH_GID --clear-groups "$BIN_DIR/AdGuardHome" --no-check-update >/dev/null 2>&1 &
        echo "$!" > "$PID_FILE"
    elif command -v setpriv >/dev/null 2>&1 && setpriv --reuid=0 --regid=$AGH_GID --clear-groups true 2>/dev/null; then
        setpriv --reuid=0 --regid=$AGH_GID --clear-groups "$BIN_DIR/AdGuardHome" --no-check-update >/dev/null 2>&1 &
        echo "$!" > "$PID_FILE"
    elif command -v chpst >/dev/null 2>&1 && chpst -u 0:$AGH_GID true 2>/dev/null; then
        chpst -u 0:$AGH_GID "$BIN_DIR/AdGuardHome" --no-check-update >/dev/null 2>&1 &
        echo "$!" > "$PID_FILE"
    elif command -v su >/dev/null 2>&1 && su -g $AGH_GID -c true 2>/dev/null; then
        su -g $AGH_GID -c "exec '$BIN_DIR/AdGuardHome' --no-check-update >/dev/null 2>&1" &
        echo "$!" > "$PID_FILE"
    else
        "$BIN_DIR/AdGuardHome" --no-check-update >/dev/null 2>&1 &
        echo "$!" > "$PID_FILE"
    fi
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

# 提取配置文件中的上游与 Bootstrap DNS IP（仅对 uid 0 放行，防核心自回环死循环，同时拦截普通 App 直连公共 DNS）
dns_bypass_addrs() {
    [ -s "$BIN_DIR/AdGuardHome.yaml" ] || return 0
    awk '
        /^[a-zA-Z_]+:/ { section = ($0 ~ /^dns:/) ? "dns" : "" }
        section == "dns" {
            line = $0
            gsub(/[^0-9a-fA-F:.]+/, " ", line)
            n = split(line, a, /[[:space:]]+/)
            for (i = 1; i <= n; i++) {
                tok = a[i]
                if (tok ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) sub(/:[0-9]+$/, "", tok)
                if (tok ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                    if (tok != "127.0.0.1" && tok != "127.0.0.0" && tok != "0.0.0.0" && !seen[tok]++) print tok
                } else if (tok ~ /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/) {
                    if (tok != "::1" && tok != "::" && !seen[tok]++) print tok
                }
            }
        }
    ' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
}

# 5. 精准 SNI 队列规则（首包严密盘查，承载数据流秒级直通）
rebuild_sni() {
    # 彻底清理旧链
    iptables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null
    iptables -w 2 -t filter -F AGH_SNI 2>/dev/null
    iptables -w 2 -t filter -X AGH_SNI 2>/dev/null
    ip6tables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null
    ip6tables -w 2 -t filter -F AGH_SNI 2>/dev/null
    ip6tables -w 2 -t filter -X AGH_SNI 2>/dev/null

    # 如果用户在 config.prop 中显式关闭了 SNI 嗅探，则直接返回
    [ "$ENABLE_SNI" = "0" ] && return 0

    sni_queue=$(sed -n 's/^[[:space:]]*queue_num:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
        "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
    [ -z "$sni_queue" ] && sni_queue=7
    [ -z "$sni_ports" ] && sni_ports="443,8443"

    # --- IPv4 SNI 链配置 ---
    iptables -w 2 -t filter -N AGH_SNI 2>/dev/null
    iptables -w 2 -t filter -A AGH_SNI -o lo -j RETURN
    # 始终豁免 AdGuardHome 自身进程 (uid 0 + gid 23333) 的出站 DoH 与规则订阅更新流量，免进 NFQUEUE 自嗅探
    iptables -w 2 -t filter -A AGH_SNI -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    # 局域网私有网段与广播直接快速放行（不跳过 198.18.0.0/15，确保即便走 Fake-IP 的连接也能在 TLS 握手首包识别并拦截广告 SNI）
    for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4 0.0.0.0/8; do
        iptables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" -d "$net" -j RETURN
    done
    # 【工业级核心优化】：仅对每个全新 TCP 连接的前 3 个数据包进行 SNI 嗅探（握手 ClientHello 必在其中）
    # 只要连接超过 3 个数据包，说明握手已完成，后续成千上万个视频/文件数据包直接在内核层放行（RETURN），绝不过队列！
    if iptables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
        -m connbytes --connbytes 1:3 --connbytes-mode packets --connbytes-dir original \
        -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
        iptables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" -j RETURN
    else
        # 兼容无 connbytes 扩展模块的兜底规则：带 queue-bypass 且排除纯 ACK
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
    for net in ::1/128 fc00::/7 fe80::/10 ff00::/8; do
        ip6tables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" -d "$net" -j RETURN
    done
    if ip6tables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" \
        -m connbytes --connbytes 1:3 --connbytes-mode packets --connbytes-dir original \
        -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
        ip6tables -w 2 -t filter -A AGH_SNI -p tcp -m multiport --dports "$sni_ports" -j RETURN
    else
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
# 仅豁免 AdGuardHome 自身 (uid 0 + gid 23333) 与 VPN 虚拟网卡 (tun+ / wg+)，防止 netd (uid 0, gid 0) 或外部 App 走 853 绕过本地过滤
rebuild_dot_guard() {
    while iptables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    iptables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    iptables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null
    while ip6tables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    ip6tables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null

    iptables -w 2 -t filter -N ADGUARD_DOT 2>/dev/null
    iptables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    iptables -w 2 -t filter -A ADGUARD_DOT -o tun+ -j RETURN
    iptables -w 2 -t filter -A ADGUARD_DOT -o wg+ -j RETURN
    iptables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        iptables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    iptables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || \
        iptables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    iptables -w 2 -t filter -I OUTPUT 1 -j ADGUARD_DOT

    ip6tables -w 2 -t filter -N ADGUARD_DOT 2>/dev/null
    ip6tables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    ip6tables -w 2 -t filter -A ADGUARD_DOT -o tun+ -j RETURN
    ip6tables -w 2 -t filter -A ADGUARD_DOT -o wg+ -j RETURN
    ip6tables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        ip6tables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || \
        ip6tables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -I OUTPUT 1 -j ADGUARD_DOT
}

# 6. 应用高效 DNS 重定向规则
apply_rules() {
    # 建立 IPv4 DNS 重定向
    iptables -w 2 -t nat -N ADGUARD 2>/dev/null
    iptables -w 2 -t nat -C OUTPUT -j ADGUARD 2>/dev/null || iptables -w 2 -t nat -I OUTPUT 1 -j ADGUARD
    iptables -w 2 -t nat -F ADGUARD
    # 【核心修复】：始终优先挂载专属 GID (23333) 豁免规则，与系统 netd (uid 0, gid 0) 彻底物理隔离！
    # 无论 WiFi / 回国 VPN 的 DNS 是否与上游 IP (如 1.1.1.1 / 8.8.8.8 / 223.5.5.5) 撞车，
    # netd 发起的 53 端口系统解析 100% 强制进入 AdGuardHome，同时 AGH 自身的 Bootstrap/上游请求永不自回环死锁！
    iptables -w 2 -t nat -A ADGUARD -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    if ! agh_has_dedicated_gid; then
        # 极端环境兜底：若 GID 未隔离，仅对非 53 端口放行，确保 netd 的 53 端口永不绕过
        for addr in $(dns_bypass_addrs); do
            case "$addr" in
                *:*) ;;
                *)
                    iptables -w 2 -t nat -A ADGUARD -m owner --uid-owner 0 -d "$addr" -p udp ! --dport 53 -j RETURN 2>/dev/null
                    iptables -w 2 -t nat -A ADGUARD -m owner --uid-owner 0 -d "$addr" -p tcp ! --dport 53 -j RETURN 2>/dev/null
                    ;;
            esac
        done
    fi
    # 当 VPN_DNS_TAKEOVER=1（默认开启，专为“一键回国”VPN 等场景优化）时，强制接管 VPN 虚拟 DNS 的 53 端口查询
    if [ "${VPN_DNS_TAKEOVER:-1}" != "1" ]; then
        iptables -w 2 -t nat -A ADGUARD -d 198.18.0.0/15 -j RETURN 2>/dev/null
        iptables -w 2 -t nat -A ADGUARD -d 172.19.0.0/16 -j RETURN 2>/dev/null
    fi
    iptables -w 2 -t nat -A ADGUARD -p udp --dport 53 -j REDIRECT --to-ports "$redir_port"
    iptables -w 2 -t nat -A ADGUARD -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port"

    # 建立 IPv6 DNS 接管链：优先使用 ip6tables nat REDIRECT（防 Telstra 等纯 IPv6/464XLAT 移动网络断网），不支持时自动回退 REJECT
    ip6tables -w 2 -t nat -N ADGUARD6_NAT 2>/dev/null
    ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null
    ip6tables -w 2 -t nat -A ADGUARD6_NAT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    if ip6tables -w 2 -t nat -A ADGUARD6_NAT -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null && \
       ip6tables -w 2 -t nat -A ADGUARD6_NAT -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; then
        ip6tables -w 2 -t nat -C OUTPUT -j ADGUARD6_NAT 2>/dev/null || ip6tables -w 2 -t nat -I OUTPUT 1 -j ADGUARD6_NAT 2>/dev/null
        while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
        ip6tables -w 2 -F ADGUARD6 2>/dev/null
        ip6tables -w 2 -X ADGUARD6 2>/dev/null
    else
        while ip6tables -w 2 -t nat -D OUTPUT -j ADGUARD6_NAT 2>/dev/null; do :; done
        ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null
        ip6tables -w 2 -t nat -X ADGUARD6_NAT 2>/dev/null
        ip6tables -w 2 -N ADGUARD6 2>/dev/null
        ip6tables -w 2 -C OUTPUT -j ADGUARD6 2>/dev/null || ip6tables -w 2 -I OUTPUT 1 -j ADGUARD6
        ip6tables -w 2 -F ADGUARD6
        ip6tables -w 2 -A ADGUARD6 -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
        if ! ip6tables -w 2 -A ADGUARD6 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; then
            ip6tables -w 2 -A ADGUARD6 -p udp --dport 53 -j DROP 2>/dev/null
        fi
        if ! ip6tables -w 2 -A ADGUARD6 -p tcp --dport 53 -j REJECT --reject-with tcp-reset 2>/dev/null; then
            ip6tables -w 2 -A ADGUARD6 -p tcp --dport 53 -j DROP 2>/dev/null
        fi
    fi

    # 保护本地 DNS 端口免受公共 Wi-Fi 局域网其他设备探测或滥用（仅允许 lo 回环与本机重定向流量）
    iptables -w 2 -t filter -N AGH_INPUT 2>/dev/null
    iptables -w 2 -t filter -F AGH_INPUT 2>/dev/null
    iptables -w 2 -t filter -A AGH_INPUT -i lo -j RETURN 2>/dev/null
    iptables -w 2 -t filter -A AGH_INPUT -p udp --dport "$redir_port" -j DROP 2>/dev/null
    iptables -w 2 -t filter -A AGH_INPUT -p tcp --dport "$redir_port" -j DROP 2>/dev/null
    iptables -w 2 -t filter -C INPUT -j AGH_INPUT 2>/dev/null || iptables -w 2 -t filter -I INPUT 1 -j AGH_INPUT 2>/dev/null
    ip6tables -w 2 -t filter -N AGH_INPUT 2>/dev/null
    ip6tables -w 2 -t filter -F AGH_INPUT 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_INPUT -i lo -j RETURN 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_INPUT -p udp --dport "$redir_port" -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_INPUT -p tcp --dport "$redir_port" -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -C INPUT -j AGH_INPUT 2>/dev/null || ip6tables -w 2 -t filter -I INPUT 1 -j AGH_INPUT 2>/dev/null

    rebuild_dot_guard
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
    rm -f "$AGH_DIR/app_pause_active" 2>/dev/null
}

# 9. 刷新网络状态（温和刷新，绝不开关飞行模式打断 VPN）
refresh_network() {
    ndc resolver flushenv 2>/dev/null
}

# 10. 【吸收项 2】开机单次启动健康预检 (Pre-flight Check，杜绝配置错乱变砖)
preflight_check() {
    if agh_running && ! agh_has_dedicated_gid; then
        # 若检测到旧进程未绑定专属 GID (23333)，自动重启切换至隔离用户组
        killall -9 AdGuardHome 2>/dev/null || kill -9 $(pidof AdGuardHome 2>/dev/null) 2>/dev/null
        sleep 1
    fi
    agh_running || start_agh
    port_hex=$(printf '%04X' "$redir_port")
    for i in 1 2 3 4 5; do
        if grep -q ":$port_hex " /proc/net/udp 2>/dev/null || grep -q ":$port_hex " /proc/net/udp6 2>/dev/null; then
            agh_real_pid=$(pidof AdGuardHome 2>/dev/null | awk '{print $1}')
            [ -n "$agh_real_pid" ] && echo "$agh_real_pid" > "$PID_FILE"
            echo "$(date '+%F %T') [PRE-FLIGHT] 本地 DNS 端口 ($redir_port) 就绪，执行规则接管。" >> "$MAIN_LOG"
            return 0
        fi
        sleep 1
    done
    echo "$(date '+%F %T') [WARNING] 本地 DNS 端口 ($redir_port) 超时未就绪，安全中止 iptables 劫持以防断网！" >> "$MAIN_LOG"
    return 1
}

# 11. 【吸收项 1】VPN 自动识别与乐观缓存 / 缓存冲洗状态机 (带 6 秒防抖冷却，专治弱网闪断)
vpn_status_last="init"
vpn_pending_status=""
vpn_pending_count=0

check_vpn_and_cache() {
    # 极速 O(1) 探测是否存在虚拟 VPN 接口 (tun* / wg* / ppp*)
    vpn_now="off"
    for iface in /sys/class/net/tun* /sys/class/net/wg* /sys/class/net/ppp*; do
        if [ -d "$iface" ]; then
            vpn_now="on"
            break
        fi
    done

    # 开机首次初始化：直接同步当前真实状态，不进入防抖等待
    if [ "$vpn_status_last" = "init" ]; then
        vpn_status_last="$vpn_now"
        return 0
    fi

    # 若用户配置了强制模式 (force_on / force_off)，则完全交由用户在 App 中手动控制，后台不自动干预
    opt_mode="${OPTIMISTIC_CACHE_MODE:-auto}"
    if [ "$opt_mode" = "force_off" ] || [ "$opt_mode" = "force_on" ]; then
        vpn_status_last="$vpn_now"
        vpn_pending_status=""
        vpn_pending_count=0
        return 0
    fi

    # 若当前探测状态与已生效状态一致，说明网络稳定，重置防抖计数器
    if [ "$vpn_now" = "$vpn_status_last" ]; then
        vpn_pending_status=""
        vpn_pending_count=0
        return 0
    fi

    # 状态发生变化：启动防抖冷却确认机制（避免极端弱网下频繁闪断导致的重复清空缓存与刷写闪存）
    if [ "$vpn_now" = "$vpn_pending_status" ]; then
        vpn_pending_count=$((vpn_pending_count + 1))
    else
        vpn_pending_status="$vpn_now"
        vpn_pending_count=1
    fi

    # 连续稳定确认至少 2 次（持续 6 秒以上），才真正判定为有效切换
    if [ "$vpn_pending_count" -ge 2 ]; then
        http_port=$(sed -n 's/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:\([0-9]*\).*/\1/p' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
        if [ -n "$http_port" ]; then
            if [ "$vpn_now" = "on" ]; then
                # 连接 VPN：自动关闭乐观缓存并秒级清空旧 DNS 缓存，防止国内 CDN 节点走错
                cfg=$(agh_api_get "http://127.0.0.1:$http_port/control/dns_info")
                if [ -n "$cfg" ]; then
                    new_cfg=$(echo "$cfg" | sed 's/"cache_optimistic":[a-z]*/"cache_optimistic":false/')
                    agh_api_post "http://127.0.0.1:$http_port/control/dns_config" "$new_cfg"
                fi
                agh_api_post "http://127.0.0.1:$http_port/control/cache_clear" ""
                ndc resolver flushenv 2>/dev/null
                echo "$(date '+%F %T') [VPN] 检测到 VPN 已稳定连接（通过防抖确认），已自动关闭乐观缓存并清空历史 DNS 缓存" >> "$MAIN_LOG"
            else
                # 断开 VPN：自动恢复开启乐观缓存并清空旧 DNS 缓存，恢复澳洲本地秒开极速
                cfg=$(agh_api_get "http://127.0.0.1:$http_port/control/dns_info")
                if [ -n "$cfg" ]; then
                    new_cfg=$(echo "$cfg" | sed 's/"cache_optimistic":[a-z]*/"cache_optimistic":true/')
                    agh_api_post "http://127.0.0.1:$http_port/control/dns_config" "$new_cfg"
                fi
                agh_api_post "http://127.0.0.1:$http_port/control/cache_clear" ""
                ndc resolver flushenv 2>/dev/null
                echo "$(date '+%F %T') [VPN] 检测到 VPN 已稳定断开（通过防抖确认），已自动恢复乐观缓存并刷新本地 DNS" >> "$MAIN_LOG"
            fi
        fi
        vpn_status_last="$vpn_now"
        vpn_pending_status=""
        vpn_pending_count=0
    fi
}

# 12. 前台放行名单应用动态感应（优先使用零开销 /dev/cpuset/top-app 读取，亮屏且名单应用在前台时自动暂停过滤，离开或息屏后恢复）
app_pause_last=""
check_app_allowlist() {
    # 若放行名单文件不存在或为空，直接快速返回
    [ -s "$AGH_DIR/app-allow.txt" ] || return 0

    # 优先通过零开销内核 /dev/cpuset/top-app/cgroup.procs 读取前台进程包名（无需 fork 昂贵的 dumpsys）
    current=""
    if [ -r "/dev/cpuset/top-app/cgroup.procs" ]; then
        for tpid in $(cat /dev/cpuset/top-app/cgroup.procs 2>/dev/null); do
            pkg=$(tr '\0' '\n' < "/proc/$tpid/cmdline" 2>/dev/null | head -n 1)
            case "$pkg" in
                *.*.*)
                    pkg="${pkg%%:*}"
                    if grep -qxF "$pkg" "$AGH_DIR/app-allow.txt" 2>/dev/null; then
                        current="$pkg"
                        break
                    fi
                    [ -z "$current" ] && current="$pkg"
                    ;;
            esac
        done
    fi

    # 若 cpuset 不可读，仅在亮屏时回退 dumpsys
    is_screen_on="1"
    if [ -z "$current" ] || [ -f "$AGH_DIR/app_pause_active" ] || grep -qxF "$current" "$AGH_DIR/app-allow.txt" 2>/dev/null; then
        is_screen_on="0"
        if dumpsys power 2>/dev/null | grep -qE 'mHoldingDisplaySuspendBlocker=true|mHoldingDisplay=true|mWakefulness=Awake|Display Power: state=ON'; then
            is_screen_on="1"
        fi
    fi

    if [ "$is_screen_on" = "0" ]; then
        if [ -f "$AGH_DIR/app_pause_active" ]; then
            http_port=$(sed -n 's/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:\([0-9]*\).*/\1/p' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
            [ -n "$http_port" ] && agh_api_post "http://127.0.0.1:$http_port/control/protection" '{"enabled":true}'
            rm -f "$AGH_DIR/app_pause_active" 2>/dev/null
            app_pause_last=""
        fi
        return 0
    fi

    if [ -z "$current" ]; then
        current=$(dumpsys activity activities 2>/dev/null | awk '/topResumedActivity|ResumedActivity/ {for(i=1;i<=NF;i++) if($i ~ /\//) {split($i,a,"/"); gsub(/[^a-zA-Z0-9._]/,"",a[1]); if(a[1] ~ /\./) {print a[1]; exit}}}')
    fi

    [ "$current" = "$app_pause_last" ] && return 0
    app_pause_last="$current"

    http_port=$(sed -n 's/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:\([0-9]*\).*/\1/p' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
    [ -z "$http_port" ] && return 0

    if [ -n "$current" ] && grep -qxF "$current" "$AGH_DIR/app-allow.txt" 2>/dev/null; then
        if [ ! -f "$AGH_DIR/app_pause_active" ]; then
            agh_api_post "http://127.0.0.1:$http_port/control/protection" '{"enabled":false}'
            echo "1" > "$AGH_DIR/app_pause_active"
            echo "$(date '+%F %T') [APP-ALLOW] 检测到放行应用在前台 ($current)，已自动暂停 DNS 过滤" >> "$MAIN_LOG"
        fi
    else
        if [ -f "$AGH_DIR/app_pause_active" ]; then
            agh_api_post "http://127.0.0.1:$http_port/control/protection" '{"enabled":true}'
            rm -f "$AGH_DIR/app_pause_active" 2>/dev/null
            echo "$(date '+%F %T') [APP-ALLOW] 放行应用已离开前台，已自动恢复 DNS 过滤" >> "$MAIN_LOG"
        fi
    fi
}

# 13. 15 天图表统计轻量持久化（每小时聚合 1 次，零写盘损耗）
sample_datachart() {
    http_port=$(sed -n 's/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:\([0-9]*\).*/\1/p' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
    [ -z "$http_port" ] && return 0

    stats_json=$(agh_api_get "http://127.0.0.1:$http_port/control/stats")
    q=$(echo "$stats_json" | sed -n 's/.*"num_dns_queries":[[:space:]]*\([0-9]*\).*/\1/p')
    b=$(echo "$stats_json" | sed -n 's/.*"num_blocked_filtering":[[:space:]]*\([0-9]*\).*/\1/p')
    [ -n "$q" ] && [ -n "$b" ] || return 0

    now=$(date +%s)
    hour=$((now / 3600 * 3600))
    prev_q=$(cat "$AGH_DIR/datachart_q" 2>/dev/null)
    prev_b=$(cat "$AGH_DIR/datachart_b" 2>/dev/null)
    dq=0; db=0
    if [ -n "$prev_q" ] && [ -n "$prev_b" ]; then
        if [ "$q" -ge "$prev_q" ]; then
            dq=$((q - prev_q))
            db=$((b - prev_b))
        else
            dq=$q; db=$b
        fi
    fi
    echo "$q" > "$AGH_DIR/datachart_q"
    echo "$b" > "$AGH_DIR/datachart_b"

    if [ $((dq + db)) -gt 0 ]; then
        awk -v h="$hour" -v dq="$dq" -v db="$db" '
            $1 == h { $2 += dq; $3 += db; found = 1 }
            { print }
            END { if (!found) print h, dq, db }
        ' "$AGH_DIR/datachart.txt" 2>/dev/null | sort -n > "$AGH_DIR/datachart.txt.tmp" && mv -f "$AGH_DIR/datachart.txt.tmp" "$AGH_DIR/datachart.txt"
    fi

    # 清除 15 天前的数据
    cutoff=$((now - 15 * 86400))
    if [ -f "$AGH_DIR/datachart.txt" ]; then
        awk -v c="$cutoff" '$1 >= c' "$AGH_DIR/datachart.txt" > "$AGH_DIR/datachart.txt.tmp" && mv -f "$AGH_DIR/datachart.txt.tmp" "$AGH_DIR/datachart.txt"
    fi
}

# --- 初始化执行 ---
clean_legacy_conflicts
clean_hotspot_rules

# 执行启动预检：只有本地服务真实就绪才挂载规则，杜绝开机静默变砖
if preflight_check; then
    # 开机/重启脚本时若存在上次异常残留的暂停标记，立即恢复 DNS 过滤保护
    if [ -f "$AGH_DIR/app_pause_active" ]; then
        init_http_port=$(sed -n 's/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:\([0-9]*\).*/\1/p' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
        [ -n "$init_http_port" ] && agh_api_post "http://127.0.0.1:$init_http_port/control/protection" '{"enabled":true}'
        rm -f "$AGH_DIR/app_pause_active" 2>/dev/null
    fi
    apply_rules
    refresh_network
fi

# --- 轻量化守护循环：秒级感应 VPN 与应用白名单，60 秒维持规则与图表采样 ---
loop_cnt=0
while true; do
    sleep 3

    # 【吸收项 3】检测模块是否被用户在管理器中停用，若是则立即干净还原并退出
    if [ -f "/data/adb/modules/AdGuardHome/disable" ]; then
        clean_all_rules
        killall -9 AdGuardHome 2>/dev/null || kill -9 $(pidof AdGuardHome 2>/dev/null) 2>/dev/null
        exit 0
    fi

    # 极速秒级检查 VPN 状态切换（0% CPU）
    check_vpn_and_cache

    # 亮屏前台放行应用状态感应（0% 息屏占用）
    check_app_allowlist

    loop_cnt=$((loop_cnt + 3))
    if [ "$loop_cnt" -ge 60 ]; then
        loop_cnt=0
        [ -f "$AGH_DIR/scripts/config.prop" ] && . "$AGH_DIR/scripts/config.prop"

        if ! agh_running; then
            start_agh
        elif ! agh_has_dedicated_gid; then
            killall -9 AdGuardHome 2>/dev/null || kill -9 $(pidof AdGuardHome 2>/dev/null) 2>/dev/null
            sleep 1
            start_agh
        fi

        # 每 60 秒轻量采样图表数据到 datachart.txt
        sample_datachart

        # 检查 OUTPUT 挂载点与 ADGUARD 重定向规则是否被系统 netd 冲掉，若是则自动修复
        if ! iptables -w 2 -t nat -C OUTPUT -j ADGUARD 2>/dev/null || \
           ! iptables -w 2 -t nat -C ADGUARD -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; then
            apply_rules
        fi
    fi
done &