#!/system/bin/sh
AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
YAML_FILE="$BIN_DIR/AdGuardHome.yaml"
SERVICE_SH="/data/adb/modules/AdGuardHome/service.sh"
export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"

# 1. 解除手动停止标记，并执行一次核心、幂等防火墙规则与单例守护自检修复
rm -f /dev/shm/agh_manual_stop "$AGH_DIR/run/agh_manual_stop" "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" "$AGH_DIR/app_pause_active" 2>/dev/null
if ! pidof AdGuardHome >/dev/null 2>&1; then
    echo "- 检测到核心未运行，正在拉起 AdGuardHome 与自愈守护..."
    sh "$SERVICE_SH" start >/dev/null 2>&1
elif ! iptables -w 2 -t nat -C OUTPUT -j ADGUARD >/dev/null 2>&1; then
    echo "- 检测到防火墙规则未挂载，正在执行幂等重挂..."
    sh "$AGH_DIR/scripts/iptables.sh" clean >/dev/null 2>&1
    sh "$AGH_DIR/scripts/iptables.sh" enable >/dev/null 2>&1
    sh "$SERVICE_SH" start >/dev/null 2>&1
else
    sh "$AGH_DIR/scripts/iptables.sh" --reload >/dev/null 2>&1
    sh "$SERVICE_SH" start >/dev/null 2>&1
    echo "- AdGuard Home 运行正常，已刷新防火墙与本地 DNS 缓存。"
fi

# 2. 优先打开原生管理器 App，若未安装则回退打开浏览器 Web UI
if pm path com.wu.adgogogo >/dev/null 2>&1; then
    echo "- 正在打开 AdGuard Home 管理器 App..."
    am start -n com.wu.adgogogo/.MainActivity >/dev/null 2>&1 && exit 0
fi

PORT=$(sed -n 's/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:\([0-9]*\).*/\1/p' "$YAML_FILE" | head -n 1)
[ -z "$PORT" ] && PORT=3000
echo "- 正在打开浏览器 Web 控制台 (端口 $PORT)..."
am start -a android.intent.action.VIEW -d "http://127.0.0.1:$PORT" >/dev/null 2>&1
