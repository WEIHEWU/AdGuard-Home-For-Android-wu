#!/system/bin/sh
# ==============================================================================
# ProxyConfig.sh - 双模自适应代理联动脚本
# 1. 当用户在管理 App 中未填写 PROXY_URL（默认留空，使用独立 VPN App 模式）：
#    自动保持原生的 fake-ip 模式并清理任何历史劫持残留，完全静默不干预外部代理。
# 2. 当用户在管理 App 中填写了 PROXY_URL（使用 Box/Clash/Mihomo 订阅链接模式）：
#    自动将订阅链接与最新的随机端口 (127.0.0.1:redir_port) 注入代理配置并温和重启服务。
# ==============================================================================

CONFIG_FILE="$(dirname "$0")/config.prop"
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"
LOCAL_DNS="127.0.0.1:${redir_port}"

# 防止重复启动后台守护实例（允许 --clean 和 --once 单次立即执行）
if [ "$1" != "--clean" ] && [ "$1" != "--once" ]; then
    for pid in $(pidof -x "$0" 2>/dev/null); do
        [ "$pid" != "$$" ] && exit 0
    done
fi

# 支持的 Root 代理模块配置文件路径与重启命令
PROXY_CONFIGS="
/data/adb/box_bll/clash/*.yaml|/data/adb/box_bll/scripts/box.service restart
/data/adb/box/mihomo/*.yaml|/data/adb/box/scripts/box.service restart
/data/clash/*.yaml|/data/clash/scripts/clash.service -k && /data/clash/scripts/clash.service -s
/data/media/0/Android/Clash/*.yaml|/data/adb/modules/Clash/Scripts/Clash.Service stop; /data/adb/modules/Clash/Scripts/Clash.Service start
"

ALL_SECTIONS="direct-nameserver: proxy-server-nameserver: nameserver: default-nameserver: [Rr][Uu][Ll][Ee]-[Ss][Ee][Tt] [Gg][Ee][Oo][Ss][Ii][Tt][Ee] "

# 温和重启代理服务并刷新系统 DNS 缓存（绝不粗暴开关飞行模式导致断网）
restart_service() {
    eval "$1" >/dev/null 2>&1
    ndc resolver flushenv 2>/dev/null
}

# 检查配置文件是否已同步最新订阅链接与当前随机端口
is_standard_config() {
    [ -f "$1" ] || return 1
    [ -z "$CLEAN_URL" ] || grep -qF "$CLEAN_URL" "$1" || return 1
    grep -q "^[[:space:]]*dns:" "$1" && grep -q "^[[:space:]]*enhanced-mode:[[:space:]]*redir-host" "$1" || return 1
    for section in $ALL_SECTIONS; do
        grep -q "^[[:space:]]*['\"]*${section}" "$1" || continue
        section_content=$(sed -n "/^[[:space:]]*['\"]*${section}/,/^[^[:space:]#]/p" "$1")
        has_local_dns=$(echo "$section_content" | grep -c "^[[:space:]]*-[[:space:]]*$LOCAL_DNS")
        other_dns=$(echo "$section_content" | grep "^[[:space:]]*- " | grep -v "^[[:space:]]*- *#" | grep -v "$LOCAL_DNS" | wc -l)
        commented_local_dns=$(echo "$section_content" | grep -c "^[[:space:]]*#.*-[[:space:]]*$LOCAL_DNS")
        [ "$commented_local_dns" -gt 0 ] && return 1
        if [ "$has_local_dns" -eq 0 ] || [ "$other_dns" -gt 0 ]; then
            return 1
        fi
    done
    return 0
}

# 清理配置文件中的本地 DNS 注入并还原原版 DNS 与 fake-ip
clean_config() {
    [ -f "$1" ] || return 1
    grep -q "127\.0\.0\.1:" "$1" 2>/dev/null || grep -q "enhanced-mode:[[:space:]]*redir-host" "$1" 2>/dev/null || return 1
    for section in $ALL_SECTIONS; do
        sed -i "/^[[:space:]]*['\"]*${section}/,/^[^[:space:]]/{/^[[:space:]]*#\{0,1\}[[:space:]]*-[[:space:]]*127\.0\.0\.1:[0-9][0-9]*$/d;s/^\([[:space:]]*\)#[[:space:]]*\(-[[:space:]]*[^#].*\)/\1\2/}" "$1" 2>/dev/null
    done
    sed -i 's/enhanced-mode:[[:space:]]*redir-host/enhanced-mode: fake-ip/g' "$1" 2>/dev/null
    return 0
}

# 注入订阅链接与当前 AdGuardHome 随机端口
process_config() {
    is_standard_config "$1" && return 1
    modified=0
    if [ -n "$CLEAN_URL" ] && ! grep -qF "$CLEAN_URL" "$1"; then
        ESCAPED_URL=$(printf '%s' "$CLEAN_URL" | sed 's/[&|]/\\&/g')
        sed -i "/proxy-providers:/,/url:/{s|^\([[:space:]]*\)url:.*|\1url: \"$ESCAPED_URL\"|}" "$1" && modified=1
    fi
    if ! (grep -q "^[[:space:]]*dns:" "$1" && grep -q "^[[:space:]]*enhanced-mode:[[:space:]]*redir-host" "$1"); then
        sed -i '/^[[:space:]]*dns:/,/^[^[:space:]]/s/^\([[:space:]]*enhanced-mode:\).*/\1 redir-host/' "$1" && modified=1
    fi
    for section in $ALL_SECTIONS; do
        sed -i "/^[[:space:]]*['\"]*${section}/,/^[^[:space:]]/{/^[[:space:]]*#\{0,1\}[[:space:]]*-[[:space:]]*127\.0\.0\.1:[0-9][0-9]*$/d;s/^\([[:space:]]*\)#[[:space:]]*\(-[[:space:]]*[^#].*\)/\1\2/}" "$1" 2>/dev/null
    done
    for section in $ALL_SECTIONS; do
        sed -i "/^[[:space:]]*['\"]*${section}/,/^[[:space:]]*[^[:space:]#'\"=-]/{/- $LOCAL_DNS/! s/^\\([[:space:]]*\\)\\(-[[:space:]]*[^#].*\\)/\\1# \\2/;/- $LOCAL_DNS/b;/^[[:space:]]*['\"]*${section}/{n;:l;/^[[:space:]]*#*[[:space:]]*-/!{n;bl};/- $LOCAL_DNS/!{s/^\\([[:space:]]*\\)\\(#*[[:space:]]*-[[:space:]]*.*\\)/\\1- $LOCAL_DNS\\
\\1# \\2/}}}" "$1" 2>/dev/null
    done
    [ "$modified" -eq 1 ] && return 0
    grep -q "$LOCAL_DNS" "$1"
    return $?
}

run_pass() {
    [ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"
    LOCAL_DNS="127.0.0.1:${redir_port}"
    CLEAN_URL=$(printf '%s' "$PROXY_URL" | tr -d '[:space:]')

    printf '%s\n' "$PROXY_CONFIGS" | while IFS='|' read -r pattern restart_cmd; do
        [ -z "$pattern" ] && continue
        need_restart=0
        for cfg in $pattern; do
            [ -f "$cfg" ] || continue
            if [ "$1" = "--clean" ] || [ -z "$CLEAN_URL" ]; then
                clean_config "$cfg" && need_restart=1
            else
                process_config "$cfg" && need_restart=1
            fi
        done
        [ "$need_restart" -eq 1 ] && [ "$1" != "--clean" ] && restart_service "$restart_cmd"
    done
}

if [ "$1" = "--clean" ] || [ "$1" = "--once" ]; then
    run_pass "$1"
    exit 0
fi

# 后台守护循环：开机立即执行一次同步，随后每 20 秒轻量检查一次
while :; do
    run_pass
    sleep 20
done