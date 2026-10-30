#!/system/bin/sh
SKIPUNZIP=1

# 多语言检测
locale=$(getprop persist.sys.locale | tr '[:upper:]' '[:lower:]')
[ -z "$locale" ] && locale="zh"
ui_print "- $locale"
case $locale in
  en*) language=en ;;
  *)   language=zh ;;
esac
i18n_print() {
  [ "$language" = "zh" ] && ui_print "$2" || ui_print "$1"
}

# 检测所有Hosts模块
i18n_print "- Checking for Hosts modules" "- 正在检测Hosts模块"
found_hosts=false;for module in /data/adb/modules/*;do [ -f "$module/system/etc/hosts" ]&&[ -f "$module/module.prop" ]&&{ [ "$found_hosts" = false ]&&i18n_print "- Found Hosts modules, auto-removing:" "- 发现Hosts模块，正在自动移除:"&&found_hosts=true;ui_print "  $(grep_prop name "$module/module.prop")";touch "$module/remove";};done
[ "$found_hosts" = true ]&&i18n_print "- Conflicting modules have been marked for removal. Please reboot after installation." "- 冲突模块已标记移除，安装完成后请重启设备。"

AGH_DIR="/data/adb/agh"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
BACKUP_DIR="$AGH_DIR/backup"
ADGPATH="/data/adb/modules/AdGuardHome"
PROXY_SCRIPT="$AGH_DIR/scripts/ProxyConfig.sh"

i18n_print "- Extracting basic module files" "- 正在解压模块基本文件"
for file in uninstall.sh module.prop service.sh action.sh AdGuardHomeManager.apk; do
  unzip -q -o "$ZIPFILE" "$file" -d "$MODPATH"
done

# 检查并停止运行中的进程
if [ -d "$AGH_DIR" ]; then
i18n_print "- Stopping AdGuardHome and its additional processes" "- 正在终止AdGuardHome及附加进程"
while true; do
    found=0
    for p in /proc/[0-9]*; do
        IFS= read -r cmd < "$p/cmdline"
        case "$cmd" in
            "$AGH_DIR/bin/AdGuardHome"*|*"$AGH_DIR/scripts/"*)
                kill -9 "${p#/proc/}"
                found=1
                ;;
        esac
    done
    [ "$found" -eq 0 ] && break
    sleep 1
done
fi

# 检查是否首次安装
if [ -d "$AGH_DIR" ]; then
  i18n_print "- Backing up configuration" "- 正在备份配置文件"
  mkdir -p "$BACKUP_DIR"
  [ -f "$BIN_DIR/AdGuardHome.yaml" ] && cp -f "$BIN_DIR/AdGuardHome.yaml" "$BACKUP_DIR/"
  [ -f "$SCRIPT_DIR/config.prop" ] && cp -f "$SCRIPT_DIR/config.prop" "$BACKUP_DIR/"
  [ -f "$SCRIPT_DIR/NoAdsService.sh" ] && cp -f "$SCRIPT_DIR/NoAdsService.sh" "$BACKUP_DIR/"
fi

# 解锁旧版可能残留的脚本防篡改属性
if [ -d "$SCRIPT_DIR" ]; then
    find "$AGH_DIR/scripts" "$ADGPATH" -type f -name "*.sh" -exec chattr -i {} \; 2>/dev/null
fi

# 清除旧模块残留
if [ -d "$AGH_DIR/ifw" ] || [ -d "$AGH_DIR/scripts" ] || [ -d "$BIN_DIR/agh_pid" ] || [ -d "$BIN_DIR/data/filters" ]; then
  i18n_print "- Cleaning up old module residues" "- 正在清理旧模块残留"
  rm -rf "$AGH_DIR/ifw" "$AGH_DIR/scripts" "$BIN_DIR/agh_pid" "$BIN_DIR/data/filters"
fi

# 创建目录并解压文件
mkdir -p "$AGH_DIR" "$BIN_DIR" "$SCRIPT_DIR" "$BACKUP_DIR"
i18n_print "- Extracting AdGuardHome files" "- 正在解压 AdGuardHome 文件"
unzip -q -o "$ZIPFILE" "scripts/*" -d "$AGH_DIR"
unzip -q -o "$ZIPFILE" "bin/*" -d "$AGH_DIR"
i18n_print "- Setting permissions" "- 设置权限"
find "$AGH_DIR" -type d -exec chmod 0700 {} \;
chmod +x "$BIN_DIR/AdGuardHome" 
chmod +x "$SCRIPT_DIR"/*.sh
chown root:net_raw "$BIN_DIR/AdGuardHome"

# 立即执行一次性安全解锁与广告缓存清理（主用户，零死循环，解除所有历史锁死）
i18n_print "- Unlocking app directories & cleaning legacy ad caches..." "- 正在全面解锁应用目录并安全清理旧广告缓存..."
sh "$SCRIPT_DIR/NoAdsService.sh" >/dev/null 2>&1

# 清理旧版本可能残留的冲突规则与策略路由
ip rule del pref 99 2>/dev/null
ip rule del pref 100 2>/dev/null
ip rule del pref 101 2>/dev/null
ip route flush table 61 2>/dev/null
while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j DROP 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p udp --dport 853 -j DROP 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
while ip6tables -w 2 -D OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null; do :; done
while ip6tables -w 2 -D OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null; do :; done
while ip6tables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
iptables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null
iptables -w 2 -t filter -F AGH_SNI 2>/dev/null
iptables -w 2 -t filter -X AGH_SNI 2>/dev/null
ip6tables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null
ip6tables -w 2 -t filter -F AGH_SNI 2>/dev/null
ip6tables -w 2 -t filter -X AGH_SNI 2>/dev/null

# 正在智能迁移与保留配置文件（保留个人自定义规则与开关，同时升级最新分流上游并清理已知问题规则）
if [ -f "$BACKUP_DIR/AdGuardHome.yaml" ] && [ -f "$BIN_DIR/AdGuardHome.yaml" ]; then
    # 1. 保留用户修改过的后台密码哈希
    old_pwd=$(sed -n 's/^[[:space:]]*password:[[:space:]]*\(.*\)/\1/p' "$BACKUP_DIR/AdGuardHome.yaml" | head -n 1)
    if [ -n "$old_pwd" ]; then
        escaped_pwd=$(printf '%s' "$old_pwd" | sed 's/[&|]/\\&/g')
        sed -i "s|^\([[:space:]]*password:[[:space:]]*\).*|\1$escaped_pwd|" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
    fi
    # 2. 提取用户在旧版中自行添加的自定义规则（自动过滤已被移除的 1e100.net 过宽白名单），合并至新版配置 user_rules 末尾（^filtering: 之前）
    awk '
        /^user_rules:/ { in_rules = 1; next }
        in_rules && /^[^[:space:]#]/ { in_rules = 0 }
        in_rules && /^[[:space:]]*-[[:space:]]*/ {
            rule = $0
            sub(/^[[:space:]]*-[[:space:]]*/, "", rule)
            gsub(/^'\''|'\''$|^"|"$|[[:space:]]+$/, "", rule)
            if (rule != "" && rule !~ /1e100\.net|oschina\.net/) print rule
        }
    ' "$BACKUP_DIR/AdGuardHome.yaml" 2>/dev/null | while IFS= read -r urule; do
        [ -z "$urule" ] && continue
        if ! grep -qF "$urule" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null; then
            escaped_rule=$(printf '%s' "$urule" | sed "s/'/''/g")
            sed -i "/^filtering:/i\\
  - '$escaped_rule'" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
        fi
    done
    i18n_print "- Merged custom user_rules from backup (cleaned 1e100.net)" "- 已从备份智能合并个人自定义规则（并自动清理 1e100.net 漏洞规则）"
fi

if [ -f "$BACKUP_DIR/config.prop" ]; then
    sed -i 's/\(VPN_DNS_TAKEOVER=[^O]*\)OPTIMISTIC_CACHE_MODE=/\1\nOPTIMISTIC_CACHE_MODE=/' "$BACKUP_DIR/config.prop" 2>/dev/null
    [ -n "$(tail -c 1 "$SCRIPT_DIR/config.prop" 2>/dev/null)" ] && echo "" >> "$SCRIPT_DIR/config.prop"
    old_url=$(sed -n 's/^PROXY_URL=//p' "$BACKUP_DIR/config.prop" | tr -d '"' | tr -d "'")
    if [ -n "$old_url" ] && [ "$old_url" != " " ] && ! echo "$old_url" | grep -q "smjcdh\.top"; then
        sed -i "/^PROXY_URL=/d" "$SCRIPT_DIR/config.prop"
        [ -n "$(tail -c 1 "$SCRIPT_DIR/config.prop" 2>/dev/null)" ] && echo "" >> "$SCRIPT_DIR/config.prop"
        echo "PROXY_URL=\"$old_url\"" >> "$SCRIPT_DIR/config.prop"
        i18n_print "- Preserved PROXY_URL from backup" "- 已从备份恢复 PROXY_URL"
    fi
    old_mode=$(sed -n 's/^OPTIMISTIC_CACHE_MODE=//p' "$BACKUP_DIR/config.prop" | tr -d '"' | tr -d "'")
    if [ -n "$old_mode" ]; then
        sed -i "/^OPTIMISTIC_CACHE_MODE=/d" "$SCRIPT_DIR/config.prop"
        [ -n "$(tail -c 1 "$SCRIPT_DIR/config.prop" 2>/dev/null)" ] && echo "" >> "$SCRIPT_DIR/config.prop"
        echo "OPTIMISTIC_CACHE_MODE=\"$old_mode\"" >> "$SCRIPT_DIR/config.prop"
        i18n_print "- Preserved OPTIMISTIC_CACHE_MODE from backup" "- 已从备份恢复 OPTIMISTIC_CACHE_MODE"
    fi
    for key in ENABLE_SNI sni_ports VPN_DNS_TAKEOVER; do
        old_val=$(sed -n "s/^${key}=//p" "$BACKUP_DIR/config.prop" | head -n 1)
        if [ -n "$old_val" ]; then
            sed -i "s|^${key}=.*|${key}=${old_val}|" "$SCRIPT_DIR/config.prop" 2>/dev/null
        fi
    done
fi
sh "$SCRIPT_DIR/ProxyConfig.sh" --once >/dev/null 2>&1
# 安装 AdGuard Home 管理器 APP 到手机主用户 (User 0)
if [ -f "$MODPATH/AdGuardHomeManager.apk" ]; then
    i18n_print "- Installing AdGuard Home Manager to primary user (user 0)..." "- 正在安装 AdGuard Home 管理器至主用户 (用户 0)..."
    
    # 自动卸载原版未魔改的 JGeek00 上游旧应用，杜绝桌面上产生 2 个同名管理工具
    pm uninstall --user 0 com.jgeek00.adguard_home_manager >/dev/null 2>&1
    
    # 优先安装到主用户 (user 0)
    # -r: 保留数据覆盖升级
    # -d: 允许降级/同版本重装
    # -g: 授权所有运行时权限 (Android 6.0+)
    # --user 0: 锁定主用户，杜绝应用分身/多用户导致图标重复
    install_res=$(pm install -r -d -g --user 0 "$MODPATH/AdGuardHomeManager.apk" 2>&1)
    if ! echo "$install_res" | grep -q "Success"; then
        # 兼容无 --user 参数的系统重试
        install_res=$(pm install -r -d -g "$MODPATH/AdGuardHomeManager.apk" 2>&1)
    fi

    # 如果由于签名变更或降级限制导致失败，自动清理旧包重新安装
    if ! echo "$install_res" | grep -q "Success"; then
        if echo "$install_res" | grep -q -i -E "INCOMPATIBLE|SIGNATURE|CONFLICT|FAILED"; then
            i18n_print "- Reinstalling cleanly due to signature change..." "- 检测到应用签名变更，正在清理旧版本后重新安装..."
            pm uninstall --user 0 com.liuzq2002.adguard_home_manager >/dev/null 2>&1
            pm uninstall com.liuzq2002.adguard_home_manager >/dev/null 2>&1
            install_res=$(pm install -r -d -g --user 0 "$MODPATH/AdGuardHomeManager.apk" 2>&1)
            if ! echo "$install_res" | grep -q "Success"; then
                install_res=$(pm install -r -d -g "$MODPATH/AdGuardHomeManager.apk" 2>&1)
            fi
        fi
    fi

    if echo "$install_res" | grep -q "Success"; then
        i18n_print "- Manager APP installed successfully" "- 管理器 APP 安装成功"
        rm -f "$MODPATH/AdGuardHomeManager.apk"
    else
        i18n_print "! Manager install notice: $install_res" "⚠️ 管理器安装提示: $install_res"
        i18n_print "! APK retained at module directory for manual install" "! 安装包已保留在模块目录，重启后可手动安装"
    fi
fi

i18n_print "- Installation complete. Reboot device." "- 安装完成，请重启设备。"