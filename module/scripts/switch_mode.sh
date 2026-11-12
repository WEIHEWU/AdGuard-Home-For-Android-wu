#!/system/bin/sh
# ==============================================================================
# AdGuard Home GoGoGo - 海外 / 国内双模无损热切换脚本 (switch_mode.sh)
# 特性：
# 1. 第一时间主动清理所有手动停止锁标记，防止守护进程误判静默
# 2. 100% POSIX awk (-v sq="'") 合并个人 user_rules、动态端口、密码与防护开关
# 3. 写入前强制执行 AdGuardHome --check-config 预校验，杜绝任何 YAML 截断或语法损坏
# 4. 100% 复用 service.sh --restart 在根命名空间与独立会话中安全重启核心并重挂 NAT
# ==============================================================================

trap '' HUP

SH_BIN="/system/bin/sh"
[ -x "$SH_BIN" ] || SH_BIN="/bin/sh"

AGH_DIR="${AGH_DIR:-/data/adb/agh}"
MODDIR="${MODDIR:-/data/adb/modules/AdGuardHome}"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
YAML_FILE="$BIN_DIR/AdGuardHome.yaml"
PROP_FILE="$SCRIPT_DIR/config.prop"
MAIN_LOG="$AGH_DIR/agh.log"
SERVICE_SH="$MODDIR/service.sh"
export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"

for bb in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox /debug_ramdisk/.magisk/busybox/busybox /sbin/.magisk/busybox/busybox; do
    if [ -x "$bb" ]; then
        command -v awk >/dev/null 2>&1 || awk() { "$bb" awk "$@"; }
        break
    fi
done

TARGET_MODE="${1:-overseas}"
NO_RESTART="${2:-}"

case "$TARGET_MODE" in
    cn|CN) TARGET_MODE="cn" ;;
    overseas|OVERSEAS|global|GLOBAL|*) TARGET_MODE="overseas" ;;
esac

# 第一时间清理所有停止锁标记（仅在非 --no-restart 正常切换时执行）
if [ "$NO_RESTART" != "--no-restart" ]; then
    rm -f /dev/shm/agh_manual_stop "$AGH_DIR/run/agh_manual_stop" \
          "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" "$AGH_DIR/app_pause_active" 2>/dev/null
    if [ -f "$PROP_FILE" ]; then
        sed -i '/^STOPPED=/d; /^MANUAL_STOP=/d' "$PROP_FILE" 2>/dev/null
    fi
fi

TEMPLATE_FILE="$BIN_DIR/AdGuardHome_${TARGET_MODE}.yaml"
if [ ! -s "$TEMPLATE_FILE" ]; then
    echo "$(date '+%F %T') [ERROR] Mode template not found: $TEMPLATE_FILE" >> "$MAIN_LOG" 2>/dev/null
    exit 1
fi

# 1. 提取当前运行配置中的动态端口、管理员密码哈希与总防护开关状态
cur_dns_port=""
cur_http_addr=""
cur_pwd=""
cur_prot=""
if [ -s "$YAML_FILE" ]; then
    cur_dns_port=$(awk '/^dns:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/^[[:space:]]*port:[[:space:]]*[0-9]+/{sub(/.*port:[[:space:]]*/, ""); print; exit}' "$YAML_FILE" 2>/dev/null)
    cur_http_addr=$(awk '/^http:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:[0-9]+/{sub(/.*address:[[:space:]]*/, ""); print; exit}' "$YAML_FILE" 2>/dev/null)
    cur_pwd=$(sed -n 's/^[[:space:]]*password:[[:space:]]*\(.*\)/\1/p' "$YAML_FILE" 2>/dev/null | head -n 1)
    cur_prot=$(awk '/^filtering:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/^[[:space:]]*protection_enabled:[[:space:]]*(true|false)/{sub(/.*protection_enabled:[[:space:]]*/, ""); print; exit}' "$YAML_FILE" 2>/dev/null)
fi

apply_preserved_fields() {
    target_f="$1"
    if [ -n "$cur_dns_port" ]; then
        sed -i "/^dns:/,/^[^[:space:]]/ s/^\([[:space:]]*port:\) [0-9]*/\1 $cur_dns_port/" "$target_f" 2>/dev/null
    fi
    if [ -n "$cur_http_addr" ]; then
        sed -i "/^http:/,/^[^[:space:]]/ s/^\([[:space:]]*address:\) 127\.0\.0\.1:[0-9]*/\1 $cur_http_addr/" "$target_f" 2>/dev/null
    fi
    if [ -n "$cur_pwd" ]; then
        escaped_pwd=$(printf '%s' "$cur_pwd" | sed 's/[&|\\]/\\&/g')
        sed -i "s|^\([[:space:]]*password:[[:space:]]*\).*|\1$escaped_pwd|" "$target_f" 2>/dev/null
    fi
    if [ "$cur_prot" = "true" ] || [ "$cur_prot" = "false" ]; then
        sed -i "/^filtering:/,/^[^[:space:]]/ s/^\([[:space:]]*protection_enabled:\)[[:space:]]*\(true\|false\)/\1 $cur_prot/" "$target_f" 2>/dev/null
    fi
}

# 2. 基于目标模板合成新配置，使用纯 POSIX awk (-v sq="'") 保留个人自定义 user_rules
TMP_YAML="$YAML_FILE.switch.tmp"
rm -f "$TMP_YAML" 2>/dev/null
if [ -s "$YAML_FILE" ] && [ -s "$BIN_DIR/default_user_rules.txt" ]; then
    awk -v sq="'" '
        FILENAME == ARGV[1] {
            gsub(/\r$/, "")
            if ($0 != "") known[$0] = 1
            next
        }
        FILENAME == ARGV[2] {
            if (/^user_rules:/) { in_old = 1; next }
            if (in_old && /^[a-zA-Z_]+:/) { in_old = 0 }
            if (in_old && /^[[:space:]]*-[[:space:]]*/) {
                rule = $0
                sub(/^[[:space:]]*-[[:space:]]*/, "", rule)
                sub(sq "[[:space:]]*#.*$", sq, rule)
                if (substr(rule, 1, 1) == sq && substr(rule, length(rule), 1) == sq) {
                    rule = substr(rule, 2, length(rule) - 2)
                } else if (substr(rule, 1, 1) == "\"" && substr(rule, length(rule), 1) == "\"") {
                    rule = substr(rule, 2, length(rule) - 2)
                }
                gsub(/[[:space:]]+$/, "", rule)
                gsub(sq sq, sq, rule)
                if (rule != "" && !(rule in known) && rule !~ /^#/ && rule !~ /1e100\.net|oschina\.net|in-addr\.arpa|@@\|\|googleapis\.com\^\$important|@@\|\|app-measurement\.com|@@\|\|crashlytics\.com|@@\|\|xp\.apple\.com|\|\|update\.googleapis\.com|\|\|ad\.\*\^/) {
                    known[rule] = 1
                    extra[++n] = rule
                }
            }
            next
        }
        FILENAME == ARGV[3] {
            if (/^filtering:/) {
                for (i = 1; i <= n; i++) {
                    r = extra[i]
                    gsub(sq, sq sq, r)
                    printf "  - %s%s%s\n", sq, r, sq
                }
            }
            print $0
        }
    ' "$BIN_DIR/default_user_rules.txt" "$YAML_FILE" "$TEMPLATE_FILE" > "$TMP_YAML" 2>/dev/null
else
    cp -f "$TEMPLATE_FILE" "$TMP_YAML" 2>/dev/null
fi

if [ ! -s "$TMP_YAML" ] || ! grep -q '^schema_version:' "$TMP_YAML" 2>/dev/null; then
    cp -f "$TEMPLATE_FILE" "$TMP_YAML" 2>/dev/null
fi

apply_preserved_fields "$TMP_YAML"

# 3. 覆盖前执行核心级 --check-config 严格语法与字段校验；若合并异常则回退纯净预设模板再验
if [ -x "$BIN_DIR/AdGuardHome" ]; then
    if ! "$BIN_DIR/AdGuardHome" --check-config -c "$TMP_YAML" -w "$BIN_DIR" >/dev/null 2>&1; then
        echo "$(date '+%F %T') [WARN] Merged YAML failed --check-config, falling back to clean template ($TARGET_MODE)" >> "$MAIN_LOG" 2>/dev/null
        cp -f "$TEMPLATE_FILE" "$TMP_YAML" 2>/dev/null
        apply_preserved_fields "$TMP_YAML"
        if ! "$BIN_DIR/AdGuardHome" --check-config -c "$TMP_YAML" -w "$BIN_DIR" >/dev/null 2>&1; then
            echo "$(date '+%F %T') [ERROR] Template YAML failed --check-config, aborting switch to protect active core!" >> "$MAIN_LOG" 2>/dev/null
            rm -f "$TMP_YAML" 2>/dev/null
            exit 1
        fi
    fi
fi

mv -f "$TMP_YAML" "$YAML_FILE"

# 4. 持久化记录 RUN_MODE 与当前 redir_port 到 config.prop
if [ -f "$PROP_FILE" ]; then
    if grep -q '^RUN_MODE=' "$PROP_FILE" 2>/dev/null; then
        sed -i "s/^RUN_MODE=.*/RUN_MODE=$TARGET_MODE/" "$PROP_FILE" 2>/dev/null
    else
        [ -n "$(tail -c 1 "$PROP_FILE" 2>/dev/null)" ] && echo "" >> "$PROP_FILE"
        echo "RUN_MODE=$TARGET_MODE" >> "$PROP_FILE"
    fi
    if [ -n "$cur_dns_port" ] && grep -q '^redir_port=' "$PROP_FILE" 2>/dev/null; then
        sed -i "s/^redir_port=.*/redir_port=$cur_dns_port/" "$PROP_FILE" 2>/dev/null
    fi
fi

if [ "$NO_RESTART" = "--no-restart" ]; then
    exit 0
fi

# 5. 100% 统一委托 service.sh --restart 在根命名空间与独立会话中安全重启核心并重挂规则
if [ -f "$SERVICE_SH" ]; then
    exec "$SH_BIN" "$SERVICE_SH" --restart
fi

echo "$(date '+%F %T') [ERROR] service.sh not found at $SERVICE_SH" >> "$MAIN_LOG" 2>/dev/null
exit 1
