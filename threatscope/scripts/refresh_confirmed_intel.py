from __future__ import annotations

import json
import os
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from enrichment import IntelligenceCache, lookup_virustotal  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: refresh_confirmed_intel.py JOB_ID")
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        raise SystemExit("VIRUSTOTAL_API_KEY is not configured")

    job_id = sys.argv[1]
    analysis_path = PROJECT / "storage" / "jobs" / job_id / "analysis.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    results = analysis.get("enrichment", {}).get("results", {})
    targets = [
        file_hash
        for file_hash, providers in results.items()
        if providers.get("virustotal", {}).get("verdict") == "malicious"
    ]
    cache = IntelligenceCache(PROJECT / "storage" / "intel_cache.sqlite3")
    for file_hash in targets:
        result = lookup_virustotal(file_hash, api_key)
        result["cached"] = False
        results[file_hash]["virustotal"] = result
        cache.put("virustotal", file_hash, result)
        print(
            f"{file_hash}: verdict={result.get('verdict')} "
            f"malicious={result.get('malicious', 0)} "
            f"label={result.get('suggested_threat_label') or '-'}"
        )

    temporary = analysis_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(analysis_path)
    print(f"updated={len(targets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
