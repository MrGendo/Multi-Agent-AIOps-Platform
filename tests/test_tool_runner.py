"""app.runtime.tool_runner.partition_tool_calls 分批逻辑测试.

规则 (见源码 docstring):
  - 相邻 safe 工具合并到同一批, 直到 batch 达到 max_parallel
  - 遇到 unsafe 工具立即新开一批, 该批只放它自己 (is_safe=False)
  - 未在 TOOL_META 登记的工具 → 保守默认 concurrency_safe=False, 单独成批
"""

from __future__ import annotations

from app.runtime.tool_runner import partition_tool_calls
from app.tools.meta import get_meta


def _tc(name: str, idx: int = 0) -> dict:
    return {"id": f"call_{name}_{idx}", "name": name, "args": {}}


# safe (concurrency_safe=True) / unsafe 工具样例, 取自 TOOL_META 真实登记
SAFE_TOOL = "get_local_cpu_memory"       # read_only + concurrency_safe
SAFE_TOOL_2 = "get_local_disk_usage"     # read_only + concurrency_safe
UNSAFE_TOOL = "web_search"               # read_only 但 concurrency_safe=False


def test_safe_tools_merge_into_one_batch():
    calls = [_tc(SAFE_TOOL, 0), _tc(SAFE_TOOL_2, 1)]
    batches = partition_tool_calls(calls)
    assert len(batches) == 1
    is_safe, batch = batches[0]
    assert is_safe is True
    assert [tc["name"] for tc in batch] == [SAFE_TOOL, SAFE_TOOL_2]


def test_unsafe_tool_gets_own_batch():
    calls = [_tc(SAFE_TOOL, 0), _tc(UNSAFE_TOOL, 1), _tc(SAFE_TOOL_2, 2)]
    batches = partition_tool_calls(calls)
    assert len(batches) == 3
    # 中间 unsafe 单独成批且标记 is_safe=False
    assert batches[0] == (True, [calls[0]])
    assert batches[1] == (False, [calls[1]])
    assert batches[2] == (True, [calls[2]])


def test_batch_capped_at_max_parallel():
    # 8 个 safe 工具, max_parallel=3 → 应切成 3+3+2
    calls = [_tc(SAFE_TOOL, i) for i in range(8)]
    batches = partition_tool_calls(calls, max_parallel=3)
    sizes = [len(batch) for _, batch in batches]
    assert sizes == [3, 3, 2]
    assert all(is_safe for is_safe, _ in batches)


def test_unregistered_tool_defaults_to_unsafe():
    name = "totally_not_registered_tool_xyz"
    assert get_meta(name).concurrency_safe is False  # fail-closed 保守默认
    calls = [_tc(SAFE_TOOL, 0), _tc(name, 1)]
    batches = partition_tool_calls(calls)
    assert len(batches) == 2
    assert batches[1][0] is False
    assert len(batches[1][1]) == 1


def test_empty_input_returns_empty():
    assert partition_tool_calls([]) == []


def test_safe_after_unsafe_starts_new_safe_batch():
    # unsafe 之后的连续 safe 应合并成一个新批
    calls = [_tc(UNSAFE_TOOL, 0), _tc(SAFE_TOOL, 1), _tc(SAFE_TOOL_2, 2)]
    batches = partition_tool_calls(calls)
    assert len(batches) == 2
    assert batches[0][0] is False
    assert batches[1][0] is True
    assert len(batches[1][1]) == 2


def test_exact_max_parallel_boundary():
    # 恰好 max_parallel 个 safe → 单批不超限
    calls = [_tc(SAFE_TOOL, i) for i in range(4)]
    batches = partition_tool_calls(calls, max_parallel=4)
    assert len(batches) == 1
    assert len(batches[0][1]) == 4
