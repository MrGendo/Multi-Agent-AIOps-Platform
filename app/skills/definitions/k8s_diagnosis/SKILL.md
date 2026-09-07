---
name: k8s_diagnosis
display_name: Kubernetes 诊断 (Pod/Deployment/节点)
description: 排查 K8s 集群故障：Pod CrashLoopBackOff/Pending/ImagePullBackOff、Deployment 不就绪、节点 NotReady、Service 无端点、OOMKilled、调度失败。本机无真实集群时优先 search_knowledge_base 检索 kube-prometheus-alerts 语料（kubernetes 37 条 + cilium 31 条已入库）做 SOP 诊断，有 kubeconfig 则可用 execute_python_script 调 kubectl/HTTP API 只读查询
triggers:
  - k8s
  - kubernetes
  - pod
  - deployment
  - crashloopbackoff
  - crashloop
  - pending
  - imagepullbackoff
  - notready
  - not ready
  - oomkilled
  - oom killed
  - 副本
  - service 无端点
  - 调度失败
  - 集群
  - cilium
  - kubelet
  - kubectl
  - 节点
allowed_tools:
  - search_knowledge_base
  - get_current_time
  - check_port
  - http_check
  - dns_lookup
  - execute_python_script
  - delegate_to_evidence_collector
  - delegate_to_kb_researcher
risk_level: medium
---

# Kubernetes 诊断 Playbook (Pod/Deployment/节点)

## 适用场景
- Pod CrashLoopBackOff / Pending / ImagePullBackOff
- Deployment 不就绪 (副本数一直上不去)
- 节点 NotReady
- Service 无端点 (Endpoints 为空)
- OOMKilled / 调度失败

## 不适用场景
- 非容器编排问题
- 单机 Docker 容器故障 → container_diagnosis

## Phase 1: 信息收集 (判断集群入口)
1. 检查有无 kubeconfig (`~/.kube/config` 或 `KUBECONFIG` 环境变量) / API server 地址
2. **没有入口就在输出里明确声明「离线 SOP 模式」**, 不装作能连集群, 直接走 Phase 2

## Phase 2: 离线 SOP 诊断 (无入口时主路径)
按症状查知识库 (kube-prometheus-alerts 语料已入库: kubernetes 37 条 + cilium 31 条):
- CrashLoopBackOff → 查容器日志 / 探针配置 / 启动命令
- Pending → 资源不足 / 调度约束 / PVC 未绑定
- NotReady → kubelet / 容器运行时 / 节点资源
- Service 无端点 → selector 与 Pod label 不匹配 / endpoint 未就绪

## Phase 3: 在线验证 (有入口时)
- 用 `execute_python_script` 只读查询: `kubectl get / describe / logs --tail`, 或 HTTP API GET
- **严禁 apply / delete / patch / edit / scale 等任何写操作**

## 输出格式
- **结论**: 一句话根因判断
- **证据**: 具体指标 + 来源 (哪个工具 / 哪条 SOP)
- **处置建议**: 可执行的动作清单
- **是否需要人工介入**: 是/否 + 理由

## 注意事项
- **全自动无人值守诊断 — 严禁反问用户**; 信息不足时基于现有信息推理并**标注假设**继续
- 工具查不到就如实报告「工具不可用 / 无数据」并继续
- 无集群入口时, 结论必须标注「基于 SOP 离线推断, 未连真实集群」
- 任何写操作 (重启 / 扩缩容 / 改配置) 仅作建议, 不自主执行
