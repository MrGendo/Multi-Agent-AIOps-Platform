# 安全设备告警接入实战指南

平台统一入口：`POST /api/v1/webhook/security`（自动识别 Wazuh / Suricata EVE / Falco 原生格式并归一化；未识别格式走通用 schema）。研判结果落 `data/alert_history.jsonl`，同时创建研判对话会话（前端「安全研判」tab 的历史列表可见，可继续多轮研判）。

## 一、Wazuh

### 方式 A：ossec.conf 集成脚本（推荐）

Wazuh manager 原生支持 webhook 集成。在 manager 服务器编辑 `/var/ossec/etc/ossec.conf`：

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://<平台IP>:9900/api/v1/webhook/security</hook_url>
  <level>7</level>            <!-- 只发 level>=7, 低危噪声不发 -->
  <alert_format>json</alert_format>
  <options>JSON</options>
</integration>
```

然后 `systemctl restart wazuh-manager`。Wazuh 会把完整 alert JSON POST 到 hook_url，平台的 Wazuh 适配器自动识别（rule.level → 四档 severity 映射：≤3 LOW / 4-7 MEDIUM / 8-11 HIGH / ≥12 CRITICAL）。

> 若用 `<name>custom-webhook</name>` 不生效，用方式 B 的通用集成脚本。

### 方式 B：自定义集成脚本

`/var/ossec/integrations/custom-aiops`（可执行权限）：

```bash
#!/bin/sh
# Wazuh 集成协议: $1=hook_url $2=alert_file $3=api_key(可空)
WPYTHON="/var/ossec/framework/python/bin/python3"
cat "$2" | curl -s -X POST -H "Content-Type: application/json" \
  --data-binary @- "$1"
```

ossec.conf 里 `<name>aiops</name>` 对应此脚本名。

## 二、Suricata

### 方式 A：eve.json 搬运脚本（无需 filebeat，最简）

平台内置搬运器（幂等：偏移量落盘，重启不重发；发送失败不推进偏移防丢告警）：

```bash
# 单次搬运 (cron 每 5 分钟跑一次也行)
.venv/bin/python scripts/ship_suricata_alerts.py --eve /var/log/suricata/eve.json

# 持续轮询模式
.venv/bin/python scripts/ship_suricata_alerts.py --eve /var/log/suricata/eve.json --loop

# 先干跑看看会发什么
.venv/bin/python scripts/ship_suricata_alerts.py --eve /var/log/suricata/eve.json --dry-run
```

### 方式 B：filebeat（已有 ELK 生态时）

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths: ["/var/log/suricata/eve.json"]
    json.keys_under_root: true
    json.add_error_key: true
processors:
  - drop_event.when.not.equals.json.event_type: "alert"   # 只发 alert 事件
output.http:
  enabled: true
  hosts: ["http://<平台IP>:9900/api/v1/webhook/security"]
  content_type: "application/json"
  batch_mode: false    # 逐条发送 (平台按单条告警处理)
```

注意 eve.json 是 JSONL（一行一个事件），`event_type != alert` 的（flow/http/dns 等）会被平台丢弃，建议 filebeat 侧就过滤掉省带宽。

## 三、Falco

Falco 原生 webhook 输出。`/etc/falco/falco.yaml`：

```yaml
json_output: true
json_include_output_property: true
http_output:
  enabled: true
  url: http://<平台IP>:9900/api/v1/webhook/security
  user_agent: "falco/webhook"
```

`systemctl restart falco`（或 `falco -c /etc/falco/falco.yaml` 容器部署时挂载配置）。Falco 的 `output_fields` 里的 `fd.sip` / `connection.sip` 会被提取为源 IP。

## 四、其他设备（通用 schema）

任何能发 HTTP POST 的设备/NMS/SIEM，按通用格式发：

```bash
curl -X POST http://<平台IP>:9900/api/v1/webhook/security \
  -H "Content-Type: application/json" \
  -d '{
    "source": "设备标识",
    "severity": "HIGH",
    "rule": "规则/告警名",
    "description": "告警详情 (含 IP/hash/域名/CVE 会被自动提取为 IOC)",
    "src_ip": "1.2.3.4",
    "dst_ip": "10.0.0.5",
    "agent": "上报主机",
    "fingerprint": "去重指纹"
  }'
```

## 五、验证与排错

```bash
# 1. 服务健康
curl http://127.0.0.1:9900/api/v1/health

# 2. 手工发一条 Wazuh 格式测试告警
curl -X POST http://127.0.0.1:9900/api/v1/webhook/security -H "Content-Type: application/json" -d '{
  "alert": {"rule": {"id": "5710", "level": 10, "description": "sshd: brute force trying to get access to the system."},
  "agent": {"name": "web-prod-01"},
  "data": {"srcip": "203.0.113.42"},
  "full_log": "sshd[9812]: Failed password for root from 203.0.113.42 port 55120 ssh2"}}'

# 3. 查后台研判结果 (返回 200 后 1-4 分钟)
curl http://127.0.0.1:9900/api/v1/webhook/history | python3 -m json.tool | head -40

# 4. 服务日志看格式识别与研判进度
tail -f logs/app.log | grep -E "webhook.*安全|SecConsolidation|Triage"
```

常见问题：
- **422 INVALID_SECURITY_PAYLOAD**：格式既不是三种原生格式也不满足通用 schema——检查 JSON 结构
- **发出去没反应**：webhook 是异步后台研判，看 `data/alert_history.jsonl` 或 history 接口，别等同步响应
- **同指纹重复告警**：webhook 不去重（Alertmanager 路径才有 15 分钟窗口去重），高频设备建议在设备侧限流或用 Suricata 搬运脚本的偏移机制自然去重
