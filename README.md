# AdGuard Home For Android

**[📥 下载海外版模块 (Overseas)](https://github.com/WEIHEWU/AdGuard-Home-For-Android-wu/raw/main/releases/AdGuard_Home_For_Android_20261018_Beta1_Overseas.zip)** · **[📥 下载国内版模块 (CN)](https://github.com/WEIHEWU/AdGuard-Home-For-Android-wu/raw/main/releases/AdGuard_Home_For_Android_20261018_Beta1_CN.zip)** · **[📱 单独下载管理器 APK](https://github.com/WEIHEWU/AdGuard-Home-For-Android-wu/raw/main/releases/AdGuardHomeManager.apk)** · [Releases 页面](https://github.com/WEIHEWU/AdGuard-Home-For-Android-wu/releases)

基于 Magisk / KernelSU / APatch 的 **AdGuard Home For Android** 全设备级 DNS 与内核 NFQUEUE SNI 去广告模块。专为追求**极致省电、零断流、临时 Root 软重启兼容、以及 VPN / 代理无缝协同**打造。

配套管理器开源仓库：[AdGuard Home Manager](https://github.com/WEIHEWU/AdGuard-Home-Manager-wu)

---

## 🌏 海外版 vs 🇨🇳 国内版 选择指南

两个版本共用完全相同的二进制核心、低功耗守护脚本与配套管理器（模块包内已内置 `AdGuard Home Manager`，刷入模块时会自动安装），仅针对所在物理网络环境定制了默认 DNS 与规则源：

| 对比维度 | 🌏 海外版 (`Overseas`) | 🇨🇳 中国国内版 (`CN`) |
| :--- | :--- | :--- |
| **适用人群** | 身处海外（澳洲/欧美/亚太等），物理网络可直连全球 | 身处中国大陆（纯国内直连，或配合 VPN / 订阅链接翻墙） |
| **默认上游 DNS** | **Cloudflare / Google / Quad9 超低延迟 IP DoH** + 国内大厂域名分流回阿里/腾讯 DoH | **腾讯 DNSPod (`1.12.12.12` / `120.53.53.53`) DoH** + 阿里/腾讯 Bootstrap |
| **规则订阅源** | GitHub 官方直连源 (`raw.githubusercontent.com`) | 国内免翻墙高速镜像 (`ghfast.top`) |
| **独立 VPN App 模式** | ✅ 默认支持（`PROXY_URL` 留空即可） | ✅ 默认支持（`PROXY_URL` 留空即可） |
| **App 填订阅链接模式** | ✅ 支持（填入 `PROXY_URL` 自动激活） | ✅ 支持（填入 `PROXY_URL` 自动激活对接 Box/Clash） |

---

## ✨ 核心优化亮点

1. **V2 零内存分配 SNI 深度嗅探引擎 (`AGH_SNI`) + 公共 DNS / DoT 防绕过 (`ADGUARD_DOT`)**：
   - 集成上游最新 SolidJS V2 WebUI 与零分配原地解析 `internal/snifilter` 引擎；
   - 采用 `connbytes 1:3` 首包精准盘查机制：仅对每个新 TCP 连接的前 3 个握手包（含 TLS `ClientHello`）送入 NFQUEUE 嗅探，彻底掐死国内 App 的 HTTPDNS / IP 直连开屏广告；握手完成后后续成千上万个视频/下载数据包在内核层直接 `RETURN` 放行，零队列延迟、零发热；
   - 动态解析上游 DNS 地址并仅豁免 `uid 0`（AdGuardHome 自身），彻底拦截普通 App 硬编码公共 DNS 或私自使用 `853/784/8853` 加密端口绕过过滤的行为。
2. **双模代理自适应（通吃“独立 VPN App”与“填订阅链接”）**：
   - **用法 A（使用独立 VPN App）**：无需任何额外设置（保持管理 App 内的 `PROXY_URL` 留空）。模块绝不触碰外部代理配置，自动放行 Fake-IP (`198.18.0.0/15`) 与 Sing-box/Clash TUN (`172.19.0.0/16`)，并通过 `O(1)` 级 `/sys/class/net/tun*` 状态感知 + **6 秒防抖确认**，在开关 VPN 时自动切换乐观缓存并冲洗旧 DNS 缓存。
   - **用法 B（使用 Box / Clash / Mihomo 模块 + 填订阅链接）**：在 `AdGuard Home Manager` 的【设置 -> 模块设置 -> `PROXY_URL 订阅链接`】中填入机场订阅并保存，[`ProxyConfig.sh`](cn/scripts/ProxyConfig.sh) 立即自动将订阅地址与每次开机随机生成的最新 `127.0.0.1:${redir_port}` 端口注入代理配置并温和刷新服务（已移除原版粗暴开关飞行模式导致的断网问题）。
3. **临时 Root 与软重启（Soft Reboot）加固 + 动态 CA 证书包聚合**：
   - 针对三星 S24 Ultra 等锁 BL 临时 Root 环境深度适配；
   - [`service.sh`](overseas/service.sh) 内置 3 次启动重试安全熔断（防卡米死循环）、`/proc/$pid/comm` 进程名二次校验，以及开机自动聚合系统与用户 CA 证书包 (`cacerts.pem`)。
4. **极致省电与闪存保护（做减法）**：
   - 查询日志改为纯内存环状队列（`file_enabled: false`, `size_memory: 1000`），App 内实时查看拦截日志不受影响，同时彻底消灭后台高频写盘耗电与闪存磨损；
   - 关闭移动端无意义的 `whois` / `arp` / `hosts` 客户端反向扫描与本地 `dnssec` 校验开销；
   - 守护周期放宽至 60 秒，`O(1)` 级存活探测，绝不阻断手机进入 Deep Sleep（深度休眠）。
5. **去广告不误杀 + 管理器一键维护套件**：
   - 预置 `GOODBYEADS` + `AWAvenue (秋风广告规则)` + `AdGuard DNS Filter`；
   - 内置完善的 Google 全家桶、Google Wallet / Pay 银行卡验证、FCM 推送及国内主流 App（微信、支付宝、淘宝、京东、B站、抖音、小红书等）防误杀白名单；
   - 配套管理器点击查询日志一键放行/拦截自动追加 `$important` 最高优先级修饰符，并内置**模块运行状态自检与日志查看器**、**一键清理开屏广告缓存**、**智能补全/重置出厂默认规则**等维护工具。

---

## 🛠️ 目录结构与构建

```text
├── overseas/        # 🌏 海外版模块完整源码
├── cn/              # 🇨🇳 中国国内版模块完整源码
├── releases/        # 打包好的模块 zip 与配套管理器 APK
└── build.sh         # 一键构建双版本模块脚本
```

在 macOS / Linux 下运行以下命令即可同时重新打包两个版本：

```bash
chmod +x build.sh
./build.sh 20261018 Beta1
```

## 致谢

- 上游核心与模块原版作者：[liuzq2002](https://github.com/liuzq2002)
- 上游管理器原版项目：[JGeek00/adguard-home-manager](https://github.com/JGeek00/adguard-home-manager)
- 修改与维护：春梦无痕
