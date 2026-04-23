"""Save example JSON fixtures to tests/fixtures/."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_models_serialization import (
    build_dynamic_report,
    build_evaluation_result,
    build_static_report,
)

os.makedirs("tests/fixtures", exist_ok=True)

sr = build_static_report()
with open("tests/fixtures/example_static_report.json", "w", encoding="utf-8") as f:
    f.write(sr.model_dump_json(indent=2))

dr = build_dynamic_report(sr.app_info, sr.hookable_targets)
with open("tests/fixtures/example_dynamic_report.json", "w", encoding="utf-8") as f:
    f.write(dr.model_dump_json(indent=2))

ev = build_evaluation_result(sr.app_info)
with open("tests/fixtures/example_evaluation.json", "w", encoding="utf-8") as f:
    f.write(ev.model_dump_json(indent=2))

print("Fixtures saved to tests/fixtures/")
