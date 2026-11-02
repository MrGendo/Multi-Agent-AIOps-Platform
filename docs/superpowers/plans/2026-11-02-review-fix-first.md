# Review FIX-FIRST 修复计划

日期: 2026-11-02
来源: /review-flow 首战报告(三维度审查, 3 项带实测复现)

## 必改清单(按序)

- [x] 1. 断连任务泄漏: `link_verifier.verify_urls_bounded` 加 try/except CancelledError 级联取消
       + 微竞态(pending 刚完成的结果误丢); `secops._run_email_triage_sse` 加 finally cancel sandbox_task
- [x] 2. 中文正文转义: `email_triage._extract_body` 弃 get_content(), 改 get_payload(decode=True)
       + charset 解码(修通 test_parse_excerpt_fallback)
- [x] 3. `index.html` secops-midrow 补 id(三态互斥对该区块失效)
- [x] 4. `email.js` link_report 改追加渲染(不覆写已验证卡)
- [x] 5. `email.js` 运行态禁用截图入口(防双 SSE 并发)
- [x] 6. `link_verifier._TOTAL_BUDGET_SEC` 80→70(须 ≤ 75s 窗口, 自注释约束)
- [x] 7. `test_email_triage.py::test_api_email_triage_sse` monkeypatch 隔离 urlscan key(防出网)

## 验证

- [x] 全量: pytest 两个测试文件 + node --check 两个 js + 三态互斥实测(服务起, 切模式看面板)
