"""一次性迁移: app/data/alert_history.jsonl (历史 bug 落错位置) → data/."""
import shutil
from pathlib import Path

src = Path("app/data/alert_history.jsonl")
dst = Path("data/alert_history.jsonl")

if src.exists():
    text = src.read_text(encoding="utf-8")
    lines = [l for l in text.splitlines() if l.strip()]
    print(f"src lines: {len(lines)}")
    with dst.open("a", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")
    print("appended to data/alert_history.jsonl")
    shutil.rmtree(Path("app/data"))
    print("removed app/data/")
else:
    print("src 不存在, 跳过")

# 验证 join 样本
import app.security.calibration as cal

r = cal.calibration_report()
print("calibration:", r.get("status"), "samples:", r.get("sample_count"))
print("metrics:", r.get("metrics"))
