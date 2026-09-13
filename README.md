# Surge IP Leak

为 Surge 自动聚合 IP、DNS、IPv6、代理质量与泄漏检测站点规则。每天通过 GitHub Actions 跟随上游更新，并进行格式标准化、文本去重和语义去重。

## Surge 用法

将以下规则放在需要优先代理的应用分流、国内域名直连和中国 ASN 直连规则之前。已有广告/隐私拦截规则可保留在本规则集之前，以保持拦截优先：

```ini
PROTOCOL,STUN,REJECT

# 此处保留你已有的广告/隐私拦截规则

RULE-SET,https://raw.githubusercontent.com/Shennai1/Surge-IP-Leak/main/rules/IPLeak.list,Proxy,extended-matching,update-interval=86400

# 之后再放应用分流、国内域名/ASN 直连规则
RULE-SET,你的直连规则,DIRECT
GEOIP,CN,DIRECT
FINAL,Proxy
```

如果你的策略组不叫 `Proxy`，请替换为实际策略组名称。Surge 按从上到下首次命中生效，因此该规则集和 STUN 规则应位于可能覆盖这些域名的直连规则之前。

`PROTOCOL,STUN,REJECT` 是协议级的 WebRTC/STUN 防泄漏补充，故意不写进域名规则集。它可能影响依赖 STUN 的语音、视频通话、P2P 或游戏；如遇兼容性问题，可删除或改用其他策略。

这是 `RULE-SET` 格式，不是 `DOMAIN-SET`。例如 `DOMAIN-SUFFIX,aapq.net` 已覆盖 `aapq.net` 和随机生成的子域，无须逐个添加完整随机域名。

本规则集只决定已收录域名的请求走向，不是完整的匿名或防泄漏保证。DNS 路径、IPv6、STUN、未收录的第三方接口仍需分别检查；普通应用也可能调用这些检测接口，命中并不必然表示你打开了检测网站。

## 上游

- [v2fly/domain-list-community：category-ip-geo-detect](https://github.com/v2fly/domain-list-community/blob/master/data/category-ip-geo-detect)，递归解析其 `include:` 依赖
- [v2fly/domain-list-community：test-ipv6](https://github.com/v2fly/domain-list-community/blob/master/data/test-ipv6)
- [iab0x00/ProxyRules：IPCheck.txt](https://github.com/iab0x00/ProxyRules/blob/main/Rule/IPCheck.txt)
- [zzerding/ip-test Gist](https://gist.github.com/zzerding/2708745eda41024b366100f6896d0067)，使用不含 revision 的 raw URL 跟随最新版本
- [falling-sky/source：sites/sites.json](https://github.com/falling-sky/source/blob/master/sites/sites.json)，自动提取未标记隐藏的 IPv4/IPv6 探针主机，只生成精确 `DOMAIN`，不扩大到探针提供者的整个域名

此外，每次构建都会合并 [人工审核补充清单](supplements/IPLeak.list)。这些条目来自其他分流仓库及检测站点的公开实现；上游更新不会把本地补充冲掉。参见 [2026-09-14 筛选记录](docs/review-2026-09-14.md)，其中记录了来源、新增范围及未纳入的域名。

每日自动跟随的是上述远程上游；其他参考仓库不会整份自动导入，补充清单的新条目仍需审核。

各上游内容仍受其各自许可与条款约束。

## 构建与去重

`scripts/build.py` 仅使用 Python 标准库，处理内容包括：

- 递归解析 v2fly `include:`，并支持 `@attr` / `@-attr` 选择器
- 将裸域名和 `domain:` 转换为 `DOMAIN-SUFFIX`，将 `full:` 转换为 `DOMAIN`
- 解析现有 Surge `DOMAIN` / `DOMAIN-SUFFIX` 规则
- 解析 test-ipv6 官方探针 JSON，并严格校验本地补充清单
- 统一小写、移除域名尾点，并将 Unicode 域名标准化为 IDNA
- 删除完全重复规则
- 当父级 `DOMAIN-SUFFIX` 已覆盖子域时删除子级 suffix
- 当任一 `DOMAIN-SUFFIX` 已覆盖某条 `DOMAIN` 时删除该 exact 规则

本地构建：

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build.py
```

工作流支持手动运行，在每天 UTC 03:23 自动检查更新，也会在构建脚本、补充清单、测试或工作流变更时运行。每次先测试再构建，只有 `rules/IPLeak.list` 实际发生变化时才会提交；上游获取失败或新增输入格式异常会使构建失败，不发布半成品。GitHub 定时任务可能延迟执行。
