#!/system/bin/sh
SCRIPT_DIR="/data/adb/agh/scripts"
ADGPATH="/data/adb/modules/AdGuardHome"
AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
MAIN_LOG="$AGH_DIR/agh.log"
MODULES_DIR="/data/adb/modules"
AGH_MODULE_PROP="/data/adb/modules/AdGuardHome/module.prop"

# 解锁脚本防篡改保护
find "$ADGPATH" -type f -name "*.sh" -exec chattr -i {} \;

# 系统语言检测
locale=$(getprop persist.sys.locale)
[ -z "$locale" ] && locale="zh"
case $locale in zh*) lang=zh ;; *) lang=en ;; esac

# 检查hosts模块并中止启动
found_hosts=false
for module in "$MODULES_DIR"/*; do 
  [ -d "$module" ] && [ -f "$module/system/etc/hosts" ] && {
    found_hosts=true
    touch "$module/remove"
  }
done
if [ "$found_hosts" = true ]; then
    if [ "$lang" = "zh" ]; then
        MSG="检测到hosts模块，AdGuardHome启动已中止"
        DESC="⚠️ AdGuardHome已禁用 - 检测到hosts模块（已标记移除，请重启设备）"
    else
        MSG="Hosts module detected, AdGuardHome startup aborted"
        DESC="⚠️ AdGuardHome disabled - Hosts module detected (marked for removal, Please restart the device)"
    fi
    [ -f "$AGH_MODULE_PROP" ] && sed -i "s/description=.*/description=$DESC/" "$AGH_MODULE_PROP"
    echo "$(date '+%F %T') [ERROR] $MSG" >> "$MAIN_LOG"
    exit 1
fi

# 检测AGH是否运行 (O(1) 快速探测，校验进程名防 PID 复用误判)
agh_running() {
    PID_FILE="$BIN_DIR/AdGuardHome.pid"
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

# 动态端口随机化与安全启动（带 3 次重试熔断防护，杜绝卡米死循环）
if ! agh_running; then
    MAX_TRIES=3
    try_count=0
    while [ "$try_count" -lt "$MAX_TRIES" ]; do
        try_count=$((try_count + 1))
        [ "$lang" = "zh" ] && echo "$(date '+%F %T') 正在启动 AdGuardHome (尝试 $try_count/$MAX_TRIES)..." >> "$MAIN_LOG" || echo "$(date '+%F %T') Starting AdGuardHome (attempt $try_count/$MAX_TRIES)..." >> "$MAIN_LOG"

        R1=$((30000+RANDOM%35536)); R2=$((30000+RANDOM%35536))
        sed -i "/^dns:/,/^[^[:space:]]/ s/^\([[:space:]]*port:\) [0-9]*/\1 $R1/; s/^\([[:space:]]*address:\) 127\.0\.0\.1:[0-9]*/\1 127.0.0.1:$R2/" "$BIN_DIR/AdGuardHome.yaml"
        sed -i "s/^redir_port=.*/redir_port=$R1/" "$SCRIPT_DIR/config.prop"

        # 保持 config.prop 与 AdGuardHome.yaml 中 sni_filter 开关完全同步
        [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
        ENABLE_SNI=${ENABLE_SNI:-1}
        if [ "$ENABLE_SNI" = "1" ]; then
            sed -i '/^sni_filter:/,/^[^[:space:]]/ s/^\([[:space:]]*enabled:\) false/\1 true/' "$BIN_DIR/AdGuardHome.yaml"
        else
            sed -i '/^sni_filter:/,/^[^[:space:]]/ s/^\([[:space:]]*enabled:\) true/\1 false/' "$BIN_DIR/AdGuardHome.yaml"
        fi

        # 启动AdGuardHome
        export SSL_CERT_DIR="/system/etc/security/cacerts/"
        "$BIN_DIR/AdGuardHome" --no-check-update >/dev/null 2>&1 &
        echo "$!" > "$BIN_DIR/AdGuardHome.pid"

        sleep 2
        if agh_running; then
            [ "$lang" = "zh" ] && echo "$(date '+%F %T') AdGuardHome 启动成功。" >> "$MAIN_LOG" || echo "$(date '+%F %T') AdGuardHome started successfully." >> "$MAIN_LOG"
            break
        fi
    done

    if ! agh_running; then
        [ "$lang" = "zh" ] && echo "$(date '+%F %T') [FATAL] AdGuardHome 启动连续失败 $MAX_TRIES 次，触发安全熔断，终止重试以防卡米！" >> "$MAIN_LOG" || echo "$(date '+%F %T') [FATAL] AdGuardHome failed after $MAX_TRIES attempts, fuse triggered to prevent bootloop!" >> "$MAIN_LOG"
        exit 1
    fi
fi

# 启动模块附加脚本
"$SCRIPT_DIR/iptables.sh" &
"$SCRIPT_DIR/NoAdsService.sh" &
"$SCRIPT_DIR/ProxyConfig.sh" &

# 执行脚本防篡改保护
find "$ADGPATH" -type f -name "*.sh" -exec chattr +i {} \;

# 日志超限时清空
[ "$(wc -c < "$MAIN_LOG")" -ge 102400 ] && : > "$MAIN_LOG"