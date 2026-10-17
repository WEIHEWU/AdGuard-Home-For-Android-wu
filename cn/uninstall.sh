#!/system/bin/sh
AGH_DIR="/data/adb/agh"
ADGPATH="/data/adb/modules/AdGuardHome"
PROXY_SCRIPT="$AGH_DIR/scripts/ProxyConfig.sh"

# 1. 检查并强制停止所有 AdGuardHome 及关联守护进程 (极速干净退出)
killall -9 AdGuardHome 2>/dev/null
for pid in $(pidof AdGuardHome 2>/dev/null); do kill -9 "$pid" 2>/dev/null; done
pkill -f "$AGH_DIR/scripts/" 2>/dev/null

# 2. 还原代理模块/Clash配置修改
[ -f "$PROXY_SCRIPT" ] && "$PROXY_SCRIPT" --clean

# 3. 彻底循环清理所有可能残留的 iptables / ip6tables 规则（循环删除所有重复项）
while iptables -w 2 -t nat -D OUTPUT -j ADGUARD 2>/dev/null; do :; done
iptables -w 2 -t nat -F ADGUARD 2>/dev/null
iptables -w 2 -t nat -X ADGUARD 2>/dev/null

while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
ip6tables -w 2 -F ADGUARD6 2>/dev/null
ip6tables -w 2 -X ADGUARD6 2>/dev/null

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

while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j DROP 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p udp --dport 853 -j DROP 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done

# 清理热点 VPN 转发与策略路由
while iptables -w 2 -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; do :; done
while iptables -w 2 -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; do :; done
while iptables -w 2 -t nat -D POSTROUTING -o tun+ -j MASQUERADE 2>/dev/null; do :; done
while iptables -w 2 -t filter -D FORWARD -o tun+ -j ACCEPT 2>/dev/null; do :; done
while iptables -w 2 -t filter -D FORWARD -i tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
for dev in $(ls /sys/class/net 2>/dev/null | grep -E '^tun[0-9]+'); do
    iptables -w 2 -t nat -D POSTROUTING -o "$dev" -j MASQUERADE 2>/dev/null
    iptables -w 2 -t filter -D FORWARD -o "$dev" -j ACCEPT 2>/dev/null
    iptables -w 2 -t filter -D FORWARD -i "$dev" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
done
ip rule del pref 99 2>/dev/null
ip rule del pref 100 2>/dev/null
ip rule del pref 101 2>/dev/null
ip route flush table 61 2>/dev/null

# 4. 解除应用广告缓存文件的锁定并清理 (还原被 NoAdsService 占位锁定的目录)
NOADS_SCRIPT="$AGH_DIR/scripts/NoAdsService.sh"
[ ! -f "$NOADS_SCRIPT" ] && NOADS_SCRIPT="$(dirname "$0")/scripts/NoAdsService.sh"
_traverse() {
    if [ -f "$1" ]; then
        chattr -i "$1" 2>/dev/null
        rm -f "$1" 2>/dev/null
    elif [ -d "$1" ]; then
        for f in "$1"/*; do
            [ -e "$f" ] && _traverse "$f"
        done
        chattr -i "$1" 2>/dev/null
        rmdir "$1" 2>/dev/null
    fi
}
if [ -f "$NOADS_SCRIPT" ]; then
    while IFS= read -r line; do
        case "$line" in
            *block_ad*)
                path="${line#*\"}"
                path="${path%%\"*}"
                [ -n "$path" ] && [ -e "$path" ] && _traverse "$path"
                ;;
        esac
    done < "$NOADS_SCRIPT"
fi

# 5. 解除模块自身文件的防篡改锁定，并彻底删除数据与模块目录
for dir in "$AGH_DIR" "$ADGPATH"; do
    [ -d "$dir" ] && chattr -R -i "$dir" 2>/dev/null
done
[ -d "$AGH_DIR" ] && rm -rf "$AGH_DIR"
[ -d "$ADGPATH" ] && rm -rf "$ADGPATH"

# 6. 恢复系统私人DNS设置 (从关闭状态恢复为系统的默认自动模式)
[ "$(settings get global private_dns_mode)" = "off" ] && settings put global private_dns_mode opportunistic 2>/dev/null

# 7. 刷新网络状态（使手机立即生效原生网络与DNS，温和刷新不打断飞行模式）
ndc resolver flushenv 2>/dev/null