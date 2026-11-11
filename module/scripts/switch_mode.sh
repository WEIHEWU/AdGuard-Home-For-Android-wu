#!/system/bin/sh
AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
YAML_FILE="$BIN_DIR/AdGuardHome.yaml"
PROP_FILE="$SCRIPT_DIR/config.prop"
MAIN_LOG="$AGH_DIR/agh.log"
CA_BUNDLE="$BIN_DIR/cacerts.pem"
AGH_GID=23333
export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"

TARGET_MODE="${1:-overseas}"
NO_RESTART="${2:-}"

case "$TARGET_MODE" in
    cn|CN) TARGET_MODE="cn" ;;
    overseas|OVERSEAS|global|GLOBAL|*) TARGET_MODE="overseas" ;;
esac

TEMPLATE_FILE="$BIN_DIR/AdGuardHome_${TARGET_MODE}.yaml"
if [ ! -s "$TEMPLATE_FILE" ]; then
    echo "$(date '+%F %T') [ERROR] Mode template not found: $TEMPLATE_FILE" >> "$MAIN_LOG"
    exit 1
fi

# 1. 提取当前运行配置中的动态端口与管理员密码哈希
cur_dns_port=""
cur_http_addr=""
cur_pwd=""
if [ -s "$YAML_FILE" ]; then
    cur_dns_port=$(awk '/^dns:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/^[[:space:]]*port:[[:space:]]*[0-9]+/{sub(/.*port:[[:space:]]*/, ""); print; exit}' "$YAML_FILE")
    cur_http_addr=$(awk '/^http:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:[0-9]+/{sub(/.*address:[[:space:]]*/, ""); print; exit}' "$YAML_FILE")
    cur_pwd=$(sed -n 's/^[[:space:]]*password:[[:space:]]*\(.*\)/\1/p' "$YAML_FILE" | head -n 1)
fi

# 2. 基于目标模式模板合成新配置，100% 保留用户在 user_rules 中添加的个人自定义规则（严格 2 空格缩进）
TMP_YAML="$YAML_FILE.switch.tmp"
if [ -s "$YAML_FILE" ] && [ -s "$BIN_DIR/default_user_rules.txt" ]; then
    awk '
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
                sub(/\x27[[:space:]]*#.*$/, "\x27", rule)
                gsub(/^'\''|'\''$|^"|"$|[[:space:]]+$/, "", rule)
                gsub(/\x27\x27/, "\x27", rule)
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
                    gsub(/\x27/, "\x27\x27", r)
                    printf "  - \x27%s\x27\n", r
                }
            }
            print $0
        }
    ' "$BIN_DIR/default_user_rules.txt" "$YAML_FILE" "$TEMPLATE_FILE" > "$TMP_YAML" 2>/dev/null
else
    cp -f "$TEMPLATE_FILE" "$TMP_YAML"
fi

if [ ! -s "$TMP_YAML" ] || ! grep -q '^schema_version:' "$TMP_YAML" 2>/dev/null; then
    cp -f "$TEMPLATE_FILE" "$TMP_YAML"
fi

# 3. 恢复原动态端口与后台密码哈希，确保切换前后端口不变、WebUI 连接不断开
if [ -n "$cur_dns_port" ]; then
    sed -i "/^dns:/,/^[^[:space:]]/ s/^\([[:space:]]*port:\) [0-9]*/\1 $cur_dns_port/" "$TMP_YAML" 2>/dev/null
fi
if [ -n "$cur_http_addr" ]; then
    sed -i "/^http:/,/^[^[:space:]]/ s/^\([[:space:]]*address:\) 127\.0\.0\.1:[0-9]*/\1 $cur_http_addr/" "$TMP_YAML" 2>/dev/null
fi
if [ -n "$cur_pwd" ]; then
    escaped_pwd=$(printf '%s' "$cur_pwd" | sed 's/[&|]/\\&/g')
    sed -i "s|^\([[:space:]]*password:[[:space:]]*\).*|\1$escaped_pwd|" "$TMP_YAML" 2>/dev/null
fi

mv -f "$TMP_YAML" "$YAML_FILE"

# 4. 持久化记录 RUN_MODE 到 config.prop
if [ -f "$PROP_FILE" ]; then
    if grep -q '^RUN_MODE=' "$PROP_FILE" 2>/dev/null; then
        sed -i "s/^RUN_MODE=.*/RUN_MODE=$TARGET_MODE/" "$PROP_FILE" 2>/dev/null
    else
        [ -n "$(tail -c 1 "$PROP_FILE" 2>/dev/null)" ] && echo "" >> "$PROP_FILE"
        echo "RUN_MODE=$TARGET_MODE" >> "$PROP_FILE"
    fi
fi

if [ "$NO_RESTART" = "--no-restart" ]; then
    exit 0
fi

# 5. 无感热重启 AdGuardHome 核心并冲洗系统 DNS 与防火墙规则
killall -15 AdGuardHome 2>/dev/null
sleep 1
pidof AdGuardHome >/dev/null 2>&1 && killall -9 AdGuardHome 2>/dev/null

AGH_TZ="$(getprop persist.sys.timezone 2>/dev/null)"
[ -n "$AGH_TZ" ] && export TZ="$AGH_TZ"
export SSL_CERT_DIR="/system/etc/security/cacerts/"
[ -s "$CA_BUNDLE" ] && export SSL_CERT_FILE="$CA_BUNDLE"

nsenter -G $AGH_GID -t 1 "$BIN_DIR/AdGuardHome" --no-check-update --crash-log "$AGH_DIR/crash.log" --logfile discard >/dev/null 2>&1 &
echo "$!" > "$BIN_DIR/AdGuardHome.pid"
sleep 1
agh_real_pid=$(pidof AdGuardHome 2>/dev/null | awk '{print $1}')
[ -n "$agh_real_pid" ] && echo "$agh_real_pid" > "$BIN_DIR/AdGuardHome.pid"

sh "$SCRIPT_DIR/iptables.sh" --reload >/dev/null 2>&1
ndc resolver flushenv >/dev/null 2>&1 || true
ndc resolver flushdefaultif >/dev/null 2>&1 || true
cmd netd resolver flushdefaultif >/dev/null 2>&1 || true

echo "$(date '+%F %T') 已热切换运行模式为: $TARGET_MODE (PID=${agh_real_pid:-unknown})" >> "$MAIN_LOG"
exit 0
