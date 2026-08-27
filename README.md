# Surge IP Leak

为 Surge 自动聚合 IP、DNS、IPv6、代理质量与泄漏检测站点规则。每天通过 GitHub Actions 跟随上游更新，并进行格式标准化、文本去重和语义去重。

## Surge 用法

将以下规则放在需要优先代理的 `DIRECT`、`GEOIP,CN` 等规则之前：

```ini
RULE-SET,https://raw.githubusercontent.com/Shennai1/Surge-IP-Leak/main/rules/IPLeak.list,Proxy,extended-matching,update-interval=86400
PROTOCOL,STUN,REJECT

# 之后再放直连规则
RULE-SET,你的直连规则,DIRECT
GEOIP,CN,DIRECT
FINAL,Proxy
```

如果你的策略组不叫 `Proxy`，请替换为实际策略组名称。Surge 按从上到下首次命中生效，因此该规则集和 STUN 规则应位于可能覆盖这些域名的直连规则之前。

`PROTOCOL,STUN,REJECT` 是协议级的 WebRTC/STUN 防泄漏补充，故意不写进域名规则集。它可能影响依赖 STUN 的语音、视频通话、P2P 或游戏；如遇兼容性问题，可删除或改用其他策略。

## 上游

- [v2fly/domain-list-community：category-ip-geo-detect](https://github.com/v2fly/domain-list-community/blob/master/data/category-ip-geo-detect)，递归解析其 `include:` 依赖
- [v2fly/domain-list-community：test-ipv6](https://github.com/v2fly/domain-list-community/blob/master/data/test-ipv6)
- [iab0x00/ProxyRules：IPCheck.txt](https://github.com/iab0x00/ProxyRules/blob/main/Rule/IPCheck.txt)
- [zzerding/ip-test Gist](https://gist.github.com/zzerding/2708745eda41024b366100f6896d0067)，使用不含 revision 的 raw URL 跟随最新版本

各上游内容仍受其各自许可与条款约束。

## 构建与去重

`scripts/build.py` 仅使用 Python 标准库，处理内容包括：

- 递归解析 v2fly `include:`，并支持 `@attr` / `@-attr` 选择器
- 将裸域名和 `domain:` 转换为 `DOMAIN-SUFFIX`，将 `full:` 转换为 `DOMAIN`
- 解析现有 Surge `DOMAIN` / `DOMAIN-SUFFIX` 规则
- 统一小写、移除域名尾点，并将 Unicode 域名标准化为 IDNA
- 删除完全重复规则
- 当父级 `DOMAIN-SUFFIX` 已覆盖子域时删除子级 suffix
- 当任一 `DOMAIN-SUFFIX` 已覆盖某条 `DOMAIN` 时删除该 exact 规则

本地构建：

```bash
python3 scripts/build.py
```

工作流支持手动运行，并在每天 UTC 03:23 自动检查更新。只有 `rules/IPLeak.list` 实际发生变化时才会提交。
