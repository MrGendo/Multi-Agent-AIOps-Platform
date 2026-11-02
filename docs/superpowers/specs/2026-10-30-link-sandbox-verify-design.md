# 链接沙箱自动验证 (urlscan L1) 设计规格

日期: 2026-10-30
状态: 待审批
前置: 邮件研判页面已上线 (2026-10-30-email-triage-frontend)

## 1. 背景与决策

当前邮件研判对链接只做**本地确定性检测** (punycode/裸 IP/短链/仿冒域名) +
**人工验证剧本** — OPSEC 上绝不自动访问。本设计把验证升级为 **L1 第三方沙箱**:
调 urlscan.io API, 由其沙箱渲染页面, 我们只消费判定结果 — 本方网络零接触,
扫描器 IP 公开已知, 攻击者无法区分例行扫描与针对性分析。

明确不做:
- L0 (情报库历史查询) 已由人工剧本覆盖, 不自动化 (价值低)
- L2 (自建 Docker+Playwright 隔离浏览器) 暂缓 — 维护成本高, 等真有
  "URL 不可外发给第三方" 的合规场景再立项

**残余风险 (写进 UI 提示而非文档)**: 自动提交即向 urlscan/攻击者暴露
"该链接被分析过"; 一次性链接可能被烧掉。因此验证仅对**前 3 条** URL 生效,
且**未配置 API key 时功能完全关闭**, 保持现状零接触。

## 2. 交互流 (SSE 事件序列扩展)

管线顺序 (有 key 且提取到 URL 时):

```
start → parsing → analyzing → report → verifying → link_report → complete
                                        └─ (无 key / 无 URL / 全部失败: 跳过, 直接 complete)
```

- 验证放在 report **之后**: 研判结论先到, 沙箱结果 (urlscan 扫描 10~60s) 异步补充,
  不阻塞主研判
- `parsing` 事件新增 `auto_verify: bool` 字段 (key 存在且 urls 非空) — 前端据此
  把新增的"链接验证"阶段标 active 或 skip (与"截图转写"同机制)
- `verifying`: 提示沙箱验证中 (带 URL 计数)
- `link_report`: `results[]` — 每条 URL 一份判定:
  `{url, status: verified|skipped|error, malicious?, score?, categories?,
   final_url?, domain_age_days?, screenshot?}`
- 超时预算: 每条 URL 提交+轮询共 60s, 超时记 skipped; 全部失败不阻塞 complete

## 3. urlscan.io API (实现时以实测校准, 已核实 search API 结构)

- 提交: `POST https://urlscan.io/api/v1/scan/` `{"url": ..., "visibility": "public"}`
  + `Authorization: API-Key <key>` → `{uuid}`
- 结果: `GET https://urlscan.io/api/v1/result/{uuid}/` (异步, 3s 间隔轮询) →
  `verdicts` (恶意判定/评分/类别), `page` (最终落地 URL/域名年龄/TLS, 已核实),
  截图 `https://urlscan.io/screenshots/{uuid}.png`
- 额度: 免费账户 submit 次数有限; 429/超额 → 该 URL 记 error, 整体 fail-soft
- visibility 可配 (public/unlisted), 默认 public (免费档)

## 4. 模块设计

```
app/security/link_verifier.py (新)
  async verify_urls(urls: list[str], *, limit=3) -> list[dict]
    - 域名去重后取前 limit 条, asyncio.gather 并发
    - 单条: submit → 轮询 result (60s 预算) → 提炼判定 dict
    - 任一环节异常 → {url, status: error|skipped}, 绝不抛出
  纯 httpx 异步; 无 key 时调用方直接跳过 (不发 verifying 事件)
```

配置 (settings + .env):
- `URLSCAN_API_KEY` (空 = 功能关闭, 默认空 — 部署面零影响)
- `URLSCAN_VISIBILITY` (public | unlisted, 默认 public)

## 5. 前端改动 (frontend/)

- 流水加第五阶段"链接验证" (data-stage=verify; auto_verify=false 时 st-skip)
- `verifying` 事件: 阶段 active + findings 提示"沙箱验证中 (urlscan)…"
- `link_report` 事件: 阶段 done; **URL 列表升级为验证卡**: 每条 URL 一行,
  徽章 `已验证·恶意` (红) / `已验证·干净` (绿) / `沙箱超时` / `未验证` (灰),
  可展开看 final_url / 评分 / 类别 / 域名年龄 / 截图外链 (noopener)
- 无 key 现状完全不变 (第五阶段灰置, 与今天行为一致)

## 6. 安全与 OPSEC 纪律

1. 只提交 URL 给 urlscan, 绝不在本方网络发起对目标 URL 的任何请求 (代码里
   httpx 只打 urlscan.io 域)
2. `verify_urls` 只取前 3 条 — 控制额度消耗与"烧链接"影响面
3. UI 明示行为: 验证卡区头部固定提示"已由 urlscan 沙箱代访, 本机零接触"
4. 截图入口提取的 URL 同样适用 (同一管线)

## 7. 文件改动清单

| 文件 | 改动 |
|------|------|
| `app/core/config.py` + `.env.example`(如有) | urlscan_api_key / urlscan_visibility |
| `app/security/link_verifier.py` (新) | 沙箱验证客户端 |
| `app/api/v1/secops.py` | SSE 流插 verifying/link_report; parsing 带 auto_verify |
| `frontend/index.html` | 流水第五阶段 |
| `frontend/email.js` | 新事件处理 + URL 验证卡 |
| `frontend/styles.css` | 验证卡/徽章样式 |
| `tests/test_link_verifier.py` (新) | mock httpx: 提交/轮询/超时/429/无 key |

## 8. 验收标准

1. 无 key: 行为与现状完全一致 (事件序列、前端第五阶段灰置)
2. 有 key (mock): parsing 带 auto_verify=true; report 后发 verifying; link_report
   含 3 条内判定; complete 正常收尾
3. 单条 URL 超时/429: 该条 error/skipped, 不影响其余与 complete
4. 前端: 恶意/干净徽章正确着色, 卡片可展开, 无 XSS (全部 escapeHtml)
