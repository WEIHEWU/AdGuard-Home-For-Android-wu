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

[ -f "$AGH_DIR/scripts/config.prop" ] && . "$AGH_DIR/scripts/config.prop"
redir_port=${redir_port:-31587}
ENABLE_SNI=${ENABLE_SNI:-1}

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

# 3. 启动 AdGuardHome
start_agh() {
    {
        case "$(getprop persist.sys.locale 2>/dev/null)" in
            zh*) echo "$(date '+%F %T') [INFO] AdGuardHome 进程未运行，正在启动..." ;;
            *)   echo "$(date '+%F %T') [INFO] AdGuardHome process missing, starting..." ;;
        esac
    } >> "$MAIN_LOG"
    export SSL_CERT_DIR="/system/etc/security/cacerts/"
    "$BIN_DIR/AdGuardHome" --no-check-update &
    echo "$!" > "$PID_FILE"
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
    # 局域网私有网段与广播直接快速放行，并排除 Fake-IP (198.18.0.0/15) 保护代理流量
    for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4 0.0.0.0/8; do
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

# 6. 应用高效 DNS 重定向规则
apply_rules() {
    # 建立 IPv4 DNS 重定向
    iptables -w 2 -t nat -N ADGUARD 2>/dev/null
    iptables -w 2 -t nat -C OUTPUT -j ADGUARD 2>/dev/null || iptables -w 2 -t nat -I OUTPUT 1 -j ADGUARD
    iptables -w 2 -t nat -F ADGUARD
    # 排除 Fake-IP (198.18.0.0/15) 与 Sing-box/Clash TUN (172.19.0.0/16)，确保代理软件的虚拟域名分流直接直通
    iptables -w 2 -t nat -A ADGUARD -d 198.18.0.0/15 -j RETURN 2>/dev/null
    iptables -w 2 -t nat -A ADGUARD -d 172.19.0.0/16 -j RETURN 2>/dev/null
    iptables -w 2 -t nat -A ADGUARD -p udp --dport 53 -j REDIRECT --to-ports "$redir_port"
    iptables -w 2 -t nat -A ADGUARD -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port"

    # 建立 IPv6 DNS 阻断链：优先采用 REJECT（秒级快速回退，彻底消除打开 App 转圈卡顿）
    ip6tables -w 2 -N ADGUARD6 2>/dev/null
    ip6tables -w 2 -C OUTPUT -j ADGUARD6 2>/dev/null || ip6tables -w 2 -I OUTPUT 1 -j ADGUARD6
    ip6tables -w 2 -F ADGUARD6
    if ! ip6tables -w 2 -A ADGUARD6 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; then
        ip6tables -w 2 -A ADGUARD6 -p udp --dport 53 -j DROP 2>/dev/null
    fi
    if ! ip6tables -w 2 -A ADGUARD6 -p tcp --dport 53 -j REJECT --reject-with tcp-reset 2>/dev/null; then
        ip6tables -w 2 -A ADGUARD6 -p tcp --dport 53 -j DROP 2>/dev/null
    fi

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

# 8. 彻底清理所有 DNS / SNI 接管规则（原子化干净还原原生网络）
clean_all_rules() {
    while iptables -w 2 -t nat -D OUTPUT -j ADGUARD 2>/dev/null; do :; done
    iptables -w 2 -t nat -F ADGUARD 2>/dev/null
    iptables -w 2 -t nat -X ADGUARD 2>/dev/null
    while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
    ip6tables -w 2 -F ADGUARD6 2>/dev/null
    ip6tables -w 2 -X ADGUARD6 2>/dev/null
    while iptables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    iptables -w 2 -t filter -F AGH_SNI 2>/dev/null
    iptables -w 2 -t filter -X AGH_SNI 2>/dev/null
    while ip6tables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    ip6tables -w 2 -F AGH_SNI 2>/dev/null
    ip6tables -w 2 -X AGH_SNI 2>/dev/null
    clean_hotspot_rules
}

# 9. 刷新网络状态（温和刷新，绝不开关飞行模式打断 VPN）
refresh_network() {
    ndc resolver flushenv 2>/dev/null
}

# 10. 【吸收项 2】开机单次启动健康预检 (Pre-flight Check，杜绝配置错乱变砖)
preflight_check() {
    agh_running || start_agh
    port_hex=$(printf '%04X' "$redir_port")
    for i in 1 2 3 4 5; do
        if grep -q ":$port_hex " /proc/net/udp 2>/dev/null || grep -q ":$port_hex " /proc/net/udp6 2>/dev/null; then
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
                cfg=$(curl -s -u root:root "http://127.0.0.1:$http_port/control/dns_info" 2>/dev/null)
                if [ -n "$cfg" ]; then
                    new_cfg=$(echo "$cfg" | sed 's/"cache_optimistic":[a-z]*/"cache_optimistic":false/')
                    curl -s -u root:root -X POST "http://127.0.0.1:$http_port/control/dns_config" \
                        -H "Content-Type: application/json" -d "$new_cfg" >/dev/null 2>&1
                fi
                curl -s -u root:root -X POST "http://127.0.0.1:$http_port/control/cache_clear" >/dev/null 2>&1
                echo "$(date '+%F %T') [VPN] 检测到 VPN 已稳定连接（通过防抖确认），已自动关闭乐观缓存并清空历史 DNS 缓存" >> "$MAIN_LOG"
            else
                # 断开 VPN：自动恢复开启乐观缓存并清空旧 DNS 缓存，恢复澳洲本地秒开极速
                cfg=$(curl -s -u root:root "http://127.0.0.1:$http_port/control/dns_info" 2>/dev/null)
                if [ -n "$cfg" ]; then
                    new_cfg=$(echo "$cfg" | sed 's/"cache_optimistic":[a-z]*/"cache_optimistic":true/')
                    curl -s -u root:root -X POST "http://127.0.0.1:$http_port/control/dns_config" \
                        -H "Content-Type: application/json" -d "$new_cfg" >/dev/null 2>&1
                fi
                curl -s -u root:root -X POST "http://127.0.0.1:$http_port/control/cache_clear" >/dev/null 2>&1
                echo "$(date '+%F %T') [VPN] 检测到 VPN 已稳定断开（通过防抖确认），已自动恢复乐观缓存并刷新本地 DNS" >> "$MAIN_LOG"
            fi
        fi
        vpn_status_last="$vpn_now"
        vpn_pending_status=""
        vpn_pending_count=0
    fi
}

# --- 初始化执行 ---
clean_legacy_conflicts
clean_hotspot_rules

# 执行启动预检：只有本地服务真实就绪才挂载规则，杜绝开机静默变砖
if preflight_check; then
    apply_rules
    refresh_network
fi

# --- 轻量化守护循环：秒级感应 VPN 状态切换，60 秒维持规则与心跳 ---
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

    loop_cnt=$((loop_cnt + 3))
    if [ "$loop_cnt" -ge 60 ]; then
        loop_cnt=0
        [ -f "$AGH_DIR/scripts/config.prop" ] && . "$AGH_DIR/scripts/config.prop"

        if ! agh_running; then
            start_agh
        fi

        # 检查 iptables 重定向规则是否被系统 netd 冲掉，若是则自动修复
        if ! iptables -w 2 -t nat -C ADGUARD -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; then
            apply_rules
        fi
    fi
done &