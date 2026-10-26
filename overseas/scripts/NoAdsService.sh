#!/system/bin/sh
# AdGuard Home For Android - 主用户广告缓存安全清理与解锁脚本
# 特性：单次极速执行、原子互斥防并发、60秒冷却防抖、零后台常驻、零死循环耗电

LOCK_DIR="/data/adb/agh/cache_clean.lock"
LAST_TIME_FILE="/data/adb/agh/last_clean_time"

# 1. 内核级原子互斥锁（避免极端环境下并发争抢）
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT

# 2. 60秒时间戳防抖冷却（避免用户短时间连续误触导致重复读写闪存）
NOW=$(date +%s)
if [ -f "$LAST_TIME_FILE" ]; then
    LAST=$(cat "$LAST_TIME_FILE" 2>/dev/null)
    [ -n "$LAST" ] && [ $((NOW - LAST)) -lt 60 ] && exit 0
fi
echo "$NOW" > "$LAST_TIME_FILE"

# 3. 自动关闭系统私人DNS（防止DoT通过853端口绕过本地AdGuard拦截）
[ "$(settings get global private_dns_mode 2>/dev/null)" = "off" ] || settings put global private_dns_mode off 2>/dev/null

# 4. 清理卸载残留的删除标记目录
for d in /data/data/*==deleted==; do
    [ -d "$d" ] && chattr -R -i "$d" 2>/dev/null && rm -rf "$d" 2>/dev/null
done

# 5. 还原与解锁误伤的系统 IFW 目录
[ -e "/data/system/ifw" ] && chattr -R -i "/data/system/ifw" 2>/dev/null

# 6. 安全清理与全面解锁核心函数（仅针对主用户 User 0）
safe_clean() {
    p="$1"
    [ ! -e "$p" ] && return 0
    # 彻底解除可能存在的只读锁，恢复合法沙盒权限
    chattr -R -i "$p" 2>/dev/null
    if [ -d "$p" ]; then
        # 仅清空目录内部缓存文件，绝不在 root 下重建目录破坏所有者 UID
        rm -rf "$p"/* 2>/dev/null
    elif [ -f "$p" ]; then
        rm -f "$p" 2>/dev/null
    fi
}

# 7. 精准清理主用户常见 App 广告缓存专用目录（绝不使用宽泛通配符，保护用户离线数据）
# 美团外卖
safe_clean "/data/data/com.sankuai.meituan.takeoutnew/files/cips/common/waimai/assets/ad"
safe_clean "/data/media/0/Android/data/com.sankuai.meituan.takeoutnew/files/cips/common/waimai/assets/promotion"

# 知乎
safe_clean "/data/data/com.zhihu.android/files/ad"

# 哔哩哔哩
safe_clean "/data/data/tv.danmaku.bili/files/res_cache"
safe_clean "/data/data/tv.danmaku.bili/files/update"
safe_clean "/data/media/0/Android/data/tv.danmaku.bili/cache/default/journal"
safe_clean "/data/data/tv.danmaku.bili/files/splash2"
safe_clean "/data/data/tv.danmaku.bili/files/splash_top_view"
safe_clean "/data/data/tv.danmaku.bili/files/resmanager_resource_1"
safe_clean "/data/data/tv.danmaku.bili/files/resmanager_resource_2"
safe_clean "/data/data/tv.danmaku.bili/files/resmanager_resource_3"

# 中国广电
safe_clean "/data/data/com.ai.obc.cbn.app/files/splashShow"

# QQ音乐 (解除文件锁并清理广告缓存)
safe_clean "/data/data/com.tencent.qqmusic/cache/TMEAds"
safe_clean "/data/data/com.tencent.qqmusic/files/app_ad_cache"
safe_clean "/data/data/com.tencent.qqmusic/files/playable_ad"
safe_clean "/data/data/com.tencent.qqmusic/files/tad_cache"
safe_clean "/data/media/0/Android/data/com.tencent.qqmusic/cache/TMEAds"

# 酷我音乐
safe_clean "/data/media/0/Android/data/cn.kuwo.player/files/KuwoMusic/.screenad"
safe_clean "/data/media/0/Android/data/cn.kuwo.player/files/KuwoMusic/.ad"
safe_clean "/data/media/0/Android/data/cn.kuwo.kwmusichd/files/KwPlayerHD/.screenad"

# 网易云音乐
safe_clean "/data/media/0/Android/data/com.netease.cloudmusic/cache/Ad"
safe_clean "/data/data/com.netease.cloudmusic/cache/MusicWebApp"
safe_clean "/data/data/com.netease.cloudmusic/shared_prefs/ad.xml"

# 大麦
safe_clean "/data/data/cn.damai/files/ad_dir"

# 顺丰速递
safe_clean "/data/data/com.sf.activity/files/openScreenADsImg"

# 猫耳FM
safe_clean "/data/data/cn.missevan/cache/splash"

# 小米有品
safe_clean "/data/data/com.xiaomi.youpin/shared_prefs/ad_prf.xml"

# 小爱音箱
safe_clean "/data/media/0/Android/data/com.xiaomi.mico/files/data_cache/journal"

# 高德地图
safe_clean "/data/data/com.autonavi.minimap/files/LaunchDynamicResource"
safe_clean "/data/data/com.autonavi.minimap/files/splash"

# 抖音
safe_clean "/data/data/com.ss.android.ugc.aweme/files/im_common_resource/common_resource/scene_strategy/incentive_chat_group_panel_alpha_video_festival"

# 腾讯QQ
safe_clean "/data/media/0/Android/data/com.tencent.mobileqq/files/vas_ad"

# 安居客
safe_clean "/data/data/com.anjuke.android.app/cache/splash_ad"

# 买单吧
safe_clean "/data/data/com.bankcomm.maidanba/files/imageCachePath"
safe_clean "/data/data/com.bankcomm.maidanba/files/tabAdsPath"

# 米家
safe_clean "/data/data/com.xiaomi.smarthome/files/sh_ads_file"

# 米游社
safe_clean "/data/media/0/Android/data/com.mihoyo.hyperion/cache/splash"

# 天翼云盘
safe_clean "/data/data/com.cn21.ecloud/files/ecloud_current_screenad.obj"

# 闲鱼
safe_clean "/data/media/0/Android/data/com.taobao.idlefish/files/splash_ad_assets"
safe_clean "/data/media/0/Android/data/com.taobao.idlefish/files/ad"
safe_clean "/data/data/com.taobao.idlefish/cache/beizi"

# 航旅纵横
safe_clean "/data/data/com.umetrip.android.msky.app/files/ad"

# 携程旅行
safe_clean "/data/media/0/Android/data/ctrip.android.view/cache/CTADCache"
safe_clean "/data/data/ctrip.android.view/files/CTAD"

# 智行火车票
safe_clean "/data/media/0/Android/data/com.yipiao/files/CTADCache"
safe_clean "/data/media/0/Android/data/com.yipiao/files/CTADSet"

# 京东
safe_clean "/data/media/0/Android/data/com.jingdong.app.mall/cache/JDVideoFileDir"

# 小福家
safe_clean "/data/data/com.coocaa.familychat/app_e_qq_com_setting_7d767d052a5753acb54b111c8a40c128/sdkCloudSetting.cfg"

# 同花顺
safe_clean "/data/data/com.hexin.plat.android/cache/splash_images"

# 锦江荟
safe_clean "/data/data/com.plateno.botaoota/cache/image_manager_disk_cache"

# 腾讯地图
safe_clean "/data/data/com.tencent.map/databases/splash.db"

# 今日头条
safe_clean "/data/data/com.ss.android.article.news/files/splashCache"

# 驾考宝典
safe_clean "/data/data/com.handsgo.jiakao.android/shared_prefs/mucangData.db.xml"

# Apkpure
safe_clean "/data/data/com.apkpure.aegon/cache/splash"

# 酷狗音乐
safe_clean "/data/media/0/Android/data/com.kugou.android/files/kugou/.splash_v4"

# 掌上无畏契约
safe_clean "/data/media/0/Android/data/com.tencent.apps.valorant/cache/splash"

# WakeUp课程表
safe_clean "/data/data/com.suda.yzune.wakeupschedule/shared_prefs/com.baidu.homework.Preference.FastAdPreference.xml"
safe_clean "/data/data/com.suda.yzune.wakeupschedule/shared_prefs/mobads_aplist_status_new.xml"

# 猫眼
safe_clean "/data/media/0/Android/data/com.sankuai.movie/cache/maoyan_downlaod"
safe_clean "/data/data/com.sankuai.movie/cache/cips/common/mtplatform_mtpicasso/assets/image_manager_disk_cache"

# 心悦俱乐部
safe_clean "/data/data/com.tencent.tgclub/cache/image_manager_disk_cache"

# 瓜子二手车
safe_clean "/data/data/com.ganji.android.haoche_c/files/guazi_theme_image"

# 小象超市
safe_clean "/data/media/0/Android/data/com.meituan.retail.v.android/files/cips/common/waimai"
safe_clean "/data/data/com.meituan.retail.v.android/cache/cips/common/mtplatform_mtpicasso/assets/image_manager_disk_cache"

# 中信银行
safe_clean "/data/data/com.ecitic.bank.mobile/files/citic/advs"

# 江苏银行
safe_clean "/data/data/cn.jsb.china/cache/images"
safe_clean "/data/data/cn.jsb.china/files/jsbank/splash"

# 滴滴出行
safe_clean "/data/data/com.sdu.didi.psnger/cache/image_manager_disk_cache"

# 盒马
safe_clean "/data/data/com.wudaokou.hippo/shared_prefs/splash.xml"

# 完美世界电竞
safe_clean "/data/data/com.pwrd.steam.esports/shared_prefs/advertisement_sp_name.xml"

# 人卫
safe_clean "/data/data/com.pmph.irenwei/cache/image_manager_disk_cache"
safe_clean "/data/data/com.pmph.irenwei/files/ad.gif"

# 南方基金
safe_clean "/data/media/0/Android/data/com.nanfangjijin.app/files/ad"
safe_clean "/data/data/com.nanfangjijin.app/cache/image_manager_disk_cache"

# 银华利生宝
safe_clean "/data/data/com.ihandy.fund/cache/image_manager_disk_cache"
safe_clean "/data/media/0/Android/data/com.ihandy.fund/cache/download/splash"

# 中国移动云盘
safe_clean "/data/media/0/Android/data/com.chinamobile.mcloud/files/M_Cloud/temp/bigcloudimage"
safe_clean "/data/media/0/Android/data/com.chinamobile.mcloud/files/boot_logo"

# 建信基金
safe_clean "/data/data/com.ccb.zzb.activity/files/image"

# 大学搜题酱
safe_clean "/data/media/0/Android/data/com.zmzx.college.search/cache/glide"

# 汽水音乐
safe_clean "/data/media/0/com.luna.music/cache/image_commercial_cache"
safe_clean "/data/media/0/com.luna.music/cache/pangle_com.byted.pangle"
safe_clean "/data/media/0/com.luna.music/files/splashCache"

# 小猿搜题
safe_clean "/data/media/0/Android/data/com.fenbi.android.solar/cache/glide"
safe_clean "/data/media/0/Android/data/com.fenbi.android.solar/files/presentImage"

# 8. 永久静默大厂典型应用的设备日志读取权限（双重保险，根绝系统弹窗）
for pkg in \
    com.tencent.qqmusic \
    com.tencent.mobileqq \
    tv.danmaku.bili \
    com.zhihu.android \
    com.netease.cloudmusic \
    com.sankuai.meituan.takeoutnew \
    com.autonavi.minimap \
    com.taobao.idlefish \
    com.ss.android.ugc.aweme \
    com.ss.android.article.news \
    cn.kuwo.player \
    com.kugou.android; do
    if pm path "$pkg" >/dev/null 2>&1; then
        appops set "$pkg" READ_LOGS ignore >/dev/null 2>&1
        pm revoke "$pkg" android.permission.READ_LOGS >/dev/null 2>&1
    fi
done

exit 0