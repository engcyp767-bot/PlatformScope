"""Local, explainable learning engine shared by FlowScope and ThreatScope.

The first release intentionally runs in shadow mode: it learns a behavioural
baseline and exposes anomaly/feedback signals, but it never replaces the
existing rule and reputation scores.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import threading
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
STORE = ROOT / "storage" / "learning.sqlite3"
MODEL_VERSION = "hybrid-shadow-1"
VALID_APPS = {"flowscope", "threatscope", "logscope"}
VALID_LABELS = {"confirmed_threat", "false_positive", "benign", "needs_review"}
LOCK = threading.RLock()
BACKFILL_STATE: dict[str, Any] = {
    "status": "not_started", "processed_jobs": 0, "total_jobs": 0, "error": None,
}

FEATURE_LABELS = {
    "transfer_log": "حجم البيانات المنقولة",
    "packets_log": "عدد الحزم",
    "target_count": "عدد الوجهات",
    "event_type": "نوع الحدث",
    "priority": "الأولوية",
    "protocol": "البروتوكول",
    "dst_port": "منفذ الوجهة",
    "classification": "تصنيف التهديد",
    "confidence": "مستوى الثقة",
    "incident_status": "حالة الحادث",
    "status": "حالة المعالجة",
    "engine": "محرك الكشف",
    "site": "الموقع",
    "hash_type": "نوع الهاش",
}


def _connect() -> sqlite3.Connection:
    STORE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(STORE, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=30000")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS numeric_stats (
            app TEXT NOT NULL, feature TEXT NOT NULL, n INTEGER NOT NULL,
            mean REAL NOT NULL, m2 REAL NOT NULL,
            PRIMARY KEY (app, feature)
        );
        CREATE TABLE IF NOT EXISTS categorical_counts (
            app TEXT NOT NULL, feature TEXT NOT NULL, value TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (app, feature, value)
        );
        CREATE TABLE IF NOT EXISTS categorical_totals (
            app TEXT NOT NULL, feature TEXT NOT NULL, total INTEGER NOT NULL,
            PRIMARY KEY (app, feature)
        );
        CREATE TABLE IF NOT EXISTS entity_counts (
            app TEXT NOT NULL, kind TEXT NOT NULL, value_hash TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (app, kind, value_hash)
        );
        CREATE TABLE IF NOT EXISTS datasets (
            app TEXT NOT NULL, fingerprint TEXT NOT NULL, first_job TEXT NOT NULL,
            created TEXT NOT NULL,
            PRIMARY KEY (app, fingerprint)
        );
        CREATE TABLE IF NOT EXISTS observations (
            app TEXT NOT NULL, job_id TEXT NOT NULL, record_index INTEGER NOT NULL,
            features_json TEXT NOT NULL, assessment_json TEXT NOT NULL,
            learned INTEGER NOT NULL, created TEXT NOT NULL,
            PRIMARY KEY (app, job_id, record_index)
        );
        CREATE TABLE IF NOT EXISTS feedback (
            app TEXT NOT NULL, job_id TEXT NOT NULL, record_index INTEGER NOT NULL,
            label TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', updated TEXT NOT NULL,
            PRIMARY KEY (app, job_id, record_index),
            FOREIGN KEY (app, job_id, record_index)
                REFERENCES observations(app, job_id, record_index)
        );
    """)
    return connection


def _clean_category(value: Any) -> str:
    clean = " ".join(str(value or "غير محدد").strip().lower().split())
    return clean[:120] or "غير محدد"


def _truthy(value: Any) -> float:
    if isinstance(value, bool):
        return float(value)
    return float(str(value or "").strip().lower() in {"1", "true", "yes", "نعم", "مطلوب"})


def _port(value: Any) -> float:
    try:
        number = int(str(value).strip())
        return float(number if 0 <= number <= 65535 else 0)
    except (TypeError, ValueError):
        return 0.0


def _size_from_text(*values: Any) -> float:
    factors = {"b": 1, "kb": 1_000, "kib": 1024, "mb": 1_000_000,
               "mib": 1024 ** 2, "gb": 1_000_000_000, "gib": 1024 ** 3,
               "tb": 1_000_000_000_000, "tib": 1024 ** 4}
    sizes: list[float] = []
    text = " ".join(str(value or "") for value in values)
    for number, unit in re.findall(r"([0-9]+(?:\.[0-9]+)?)\s*(TiB|TB|GiB|GB|MiB|MB|KiB|KB|B)\b", text, re.I):
        sizes.append(float(number) * factors[unit.lower()])
    for number in re.findall(r"(?:bytes(?:in|out)?|octets)\s*[=:]\s*([0-9]+)", text, re.I):
        sizes.append(float(number))
    return max(sizes, default=0.0)


def _entity_hash(value: Any) -> str:
    return hashlib.sha256(_clean_category(value).encode("utf-8")).hexdigest()


def extract_features(app: str, record: dict[str, Any]) -> dict[str, Any]:
    if app not in VALID_APPS:
        raise ValueError("Unknown application")
    if app == "flowscope":
        transfer = float(record.get("bytes") or 0) or _size_from_text(record.get("detail"), record.get("attributes"))
        numeric = {
            "transfer_log": math.log1p(max(transfer, 0)),
            "packets_log": math.log1p(max(float(record.get("packets") or 0), 0)),
            "target_count": float(len(record.get("event_targets") or [])),
            "src_port_number": _port(record.get("src_port")),
            "dst_port_number": _port(record.get("dst_port")),
        }
        categorical = {
            "event_type": _clean_category(record.get("event_type") or "network_flow"),
            "priority": _clean_category(record.get("priority")),
            "protocol": _clean_category(record.get("protocol")),
            "dst_port": _clean_category(record.get("dst_port")),
        }
        entities = {
            "source": [_entity_hash(record.get("event_source") or record.get("src_ip"))],
            "destination": [_entity_hash(value) for value in (
                record.get("event_targets") or [record.get("dst_ip")]
            ) if value],
        }
    elif app == "logscope":
        numeric = {
            "risk_score": float(record.get("risk_score") or 0),
            "extracted_ip_count": float(len(record.get("extracted_ips") or [])),
            "description_length": float(len(str(record.get("description") or ""))),
        }
        categorical = {
            "event_id": _clean_category(record.get("event_id")),
            "priority": _clean_category(record.get("priority")),
            "severity": _clean_category(record.get("severity")),
            "event_source": _clean_category(record.get("event_source")),
        }
        entities = {
            "source_ip": [_entity_hash(record.get("src_ip"))] if record.get("src_ip") else [],
            "user_account": [_entity_hash(record.get("user_account"))] if record.get("user_account") else [],
        }
    else:
        numeric = {
            "pending_action": _truthy(record.get("pending_actions")),
            "failed_action": _truthy(record.get("failed_actions")),
            "reboot_required": _truthy(record.get("reboot_required")),
            "mitigated_preemptively": _truthy(record.get("mitigated_preemptively")),
        }
        categorical = {
            "classification": _clean_category(record.get("classification")),
            "confidence": _clean_category(record.get("confidence")),
            "incident_status": _clean_category(record.get("incident_status")),
            "status": _clean_category(record.get("status")),
            "engine": _clean_category(record.get("engine")),
            "site": _clean_category(record.get("site")),
            "hash_type": _clean_category(record.get("hash_type")),
        }
        entities = {
            "endpoint": [_entity_hash(record.get("endpoint"))] if record.get("endpoint") else [],
            "hash": [_entity_hash(record.get("hash"))] if record.get("hash") else [],
        }
    return {"numeric": numeric, "categorical": categorical, "entities": entities}


def _dataset_fingerprint(features: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for item in features:
        digest.update(json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _feature_tokens(features: dict[str, Any]) -> set[str]:
    tokens = {f"c:{key}={value}" for key, value in features["categorical"].items()}
    for key, value in features["numeric"].items():
        if value <= 0:
            bucket = "zero"
        elif value <= 1:
            bucket = "one"
        elif value <= 5:
            bucket = "small"
        elif value <= 15:
            bucket = "medium"
        else:
            bucket = "large"
        tokens.add(f"n:{key}={bucket}")
    return tokens


def _feedback_model(
    connection: sqlite3.Connection, app: str, source_system: str
) -> dict[str, Any] | None:
    rows = connection.execute(
        "SELECT o.features_json, f.label FROM feedback f JOIN observations o "
        "ON o.app=f.app AND o.job_id=f.job_id AND o.record_index=f.record_index "
        "WHERE f.app=? AND f.label IN ('confirmed_threat','false_positive','benign')",
        (app,),
    ).fetchall()
    rows = [row for row in rows if json.loads(row["features_json"]).get("categorical", {}).get("source_system") == source_system]
    positives = [row for row in rows if row["label"] == "confirmed_threat"]
    negatives = [row for row in rows if row["label"] != "confirmed_threat"]
    if len(rows) < 30 or len(positives) < 10 or len(negatives) < 10:
        return None
    counts = {1: Counter(), 0: Counter()}
    for row in rows:
        label = 1 if row["label"] == "confirmed_threat" else 0
        counts[label].update(_feature_tokens(json.loads(row["features_json"])))
    vocabulary = set(counts[0]) | set(counts[1])
    return {
        "samples": len(rows), "positive": len(positives), "negative": len(negatives),
        "counts": counts, "vocabulary": vocabulary,
    }


def _feedback_probability(model: dict[str, Any] | None, features: dict[str, Any]) -> float | None:
    if not model:
        return None
    total = model["samples"]
    class_sizes = {1: model["positive"], 0: model["negative"]}
    vocabulary_size = max(len(model["vocabulary"]), 1)
    scores: dict[int, float] = {}
    for label in (0, 1):
        scores[label] = math.log((class_sizes[label] + 1) / (total + 2))
        denominator = sum(model["counts"][label].values()) + vocabulary_size
        for token in _feature_tokens(features):
            scores[label] += math.log((model["counts"][label][token] + 1) / denominator)
    delta = max(min(scores[0] - scores[1], 60), -60)
    return 1.0 / (1.0 + math.exp(delta))


def _score(connection: sqlite3.Connection, app: str, features: dict[str, Any], feedback_model: dict[str, Any] | None) -> dict[str, Any]:
    contributions: list[tuple[float, str]] = []
    learned_samples = 0
    for key, value in features["numeric"].items():
        row = connection.execute(
            "SELECT n, mean, m2 FROM numeric_stats WHERE app=? AND feature=?", (app, key)
        ).fetchone()
        if not row:
            continue
        learned_samples = max(learned_samples, int(row["n"]))
        if row["n"] >= 20:
            if row["m2"] > 0:
                deviation = math.sqrt(row["m2"] / max(row["n"] - 1, 1))
                z_score = abs(float(value) - row["mean"]) / max(deviation, 1e-9)
                unusual = z_score >= 2.5
                points = min(38.0, 9.0 + (z_score - 2.5) * 7.0)
            else:
                unusual = not math.isclose(float(value), float(row["mean"]), rel_tol=1e-9, abs_tol=1e-9)
                points = 38.0
            if unusual:
                contributions.append((points, f"{FEATURE_LABELS.get(key, key)} غير معتاد مقارنة بالسجل السابق"))
    for key, value in features["categorical"].items():
        total_row = connection.execute(
            "SELECT total FROM categorical_totals WHERE app=? AND feature=?", (app, key)
        ).fetchone()
        total = int(total_row["total"]) if total_row else 0
        learned_samples = max(learned_samples, total)
        if total < 20:
            continue
        count_row = connection.execute(
            "SELECT count FROM categorical_counts WHERE app=? AND feature=? AND value=?",
            (app, key, value),
        ).fetchone()
        count = int(count_row["count"]) if count_row else 0
        if count == 0:
            contributions.append((16.0, f"{FEATURE_LABELS.get(key, key)} ظهر لأول مرة"))
        elif count / total < 0.01:
            contributions.append((9.0, f"{FEATURE_LABELS.get(key, key)} نادر في السجل السابق"))
    for kind, hashes in features["entities"].items():
        if learned_samples < 20:
            continue
        for value_hash in hashes[:3]:
            found = connection.execute(
                "SELECT count FROM entity_counts WHERE app=? AND kind=? AND value_hash=?",
                (app, kind, value_hash),
            ).fetchone()
            if not found:
                label = {"source": "المصدر", "destination": "الوجهة", "endpoint": "الجهاز", "hash": "الهاش"}.get(kind, "المؤشر")
                contributions.append((8.0, f"{label} لم يظهر في التحليلات السابقة"))
                break
    contributions.sort(key=lambda item: item[0], reverse=True)
    anomaly_score = min(100, round(sum(points for points, _ in contributions[:4])))
    probability = _feedback_probability(feedback_model, features)
    combined = anomaly_score if probability is None else round(anomaly_score * 0.75 + probability * 100 * 0.25)
    if learned_samples < 20:
        confidence = "warming_up"
    elif learned_samples < 500:
        confidence = "limited"
    else:
        confidence = "established"
    reasons = [reason for _, reason in contributions[:3]]
    if probability is not None:
        reasons.append(f"مقارنة مع {feedback_model['samples']} حكمًا سابقًا للمحلل")
    if not reasons:
        reasons = ["لم يظهر انحراف بارز عن النمط التاريخي المتاح"]
    return {
        "score": int(combined), "anomaly_score": int(anomaly_score),
        "feedback_probability": round(probability, 4) if probability is not None else None,
        "level": "مرتفع" if combined >= 70 else "ملحوظ" if combined >= 40 else "اعتيادي",
        "confidence": confidence, "mode": "shadow", "reasons": reasons,
        "model_version": MODEL_VERSION, "baseline_samples": learned_samples,
    }


def _learn(connection: sqlite3.Connection, app: str, features: dict[str, Any]) -> None:
    for key, value in features["numeric"].items():
        row = connection.execute(
            "SELECT n, mean, m2 FROM numeric_stats WHERE app=? AND feature=?", (app, key)
        ).fetchone()
        if row:
            n = row["n"] + 1
            delta = float(value) - row["mean"]
            mean = row["mean"] + delta / n
            m2 = row["m2"] + delta * (float(value) - mean)
            connection.execute(
                "UPDATE numeric_stats SET n=?, mean=?, m2=? WHERE app=? AND feature=?",
                (n, mean, m2, app, key),
            )
        else:
            connection.execute(
                "INSERT INTO numeric_stats(app,feature,n,mean,m2) VALUES(?,?,1,?,0)",
                (app, key, float(value)),
            )
    for key, value in features["categorical"].items():
        connection.execute(
            "INSERT INTO categorical_counts(app,feature,value,count) VALUES(?,?,?,1) "
            "ON CONFLICT(app,feature,value) DO UPDATE SET count=count+1", (app, key, value),
        )
        connection.execute(
            "INSERT INTO categorical_totals(app,feature,total) VALUES(?,?,1) "
            "ON CONFLICT(app,feature) DO UPDATE SET total=total+1", (app, key),
        )
    for kind, hashes in features["entities"].items():
        for value_hash in hashes:
            connection.execute(
                "INSERT INTO entity_counts(app,kind,value_hash,count) VALUES(?,?,?,1) "
                "ON CONFLICT(app,kind,value_hash) DO UPDATE SET count=count+1",
                (app, kind, value_hash),
            )


def annotate_analysis(app: str, job_id: str, analysis: dict[str, Any]) -> dict[str, Any]:
    """Score records against the historical baseline, then learn the new file."""
    if app not in VALID_APPS or not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("Invalid learning context")
    records = analysis.get("records") or []
    source_system = _clean_category(
        (analysis.get("metadata") or {}).get("source_system") or "unspecified"
    )
    scope = f"{app}|{source_system}"
    features = [extract_features(app, record) for record in records]
    for item in features:
        item["categorical"]["source_system"] = source_system
    fingerprint = _dataset_fingerprint(features)
    now = datetime.now(timezone.utc).isoformat()
    with LOCK:
        connection = _connect()
        try:
            existing_dataset = connection.execute(
                "SELECT first_job FROM datasets WHERE app=? AND fingerprint=?", (scope, fingerprint)
            ).fetchone()
            learn_dataset = existing_dataset is None
            if learn_dataset:
                connection.execute(
                    "INSERT INTO datasets(app,fingerprint,first_job,created) VALUES(?,?,?,?)",
                    (scope, fingerprint, job_id, now),
                )
            feedback_model = _feedback_model(connection, app, source_system)
            anomalous = 0
            for index, (record, item_features) in enumerate(zip(records, features)):
                existing = connection.execute(
                    "SELECT assessment_json FROM observations WHERE app=? AND job_id=? AND record_index=?",
                    (app, job_id, index),
                ).fetchone()
                if existing:
                    assessment = json.loads(existing["assessment_json"])
                else:
                    assessment = _score(connection, scope, item_features, feedback_model)
                    connection.execute(
                        "INSERT INTO observations(app,job_id,record_index,features_json,assessment_json,learned,created) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (app, job_id, index, json.dumps(item_features, ensure_ascii=False),
                         json.dumps(assessment, ensure_ascii=False), int(learn_dataset), now),
                    )
                    if learn_dataset:
                        _learn(connection, scope, item_features)
                feedback = connection.execute(
                    "SELECT label,note,updated FROM feedback WHERE app=? AND job_id=? AND record_index=?",
                    (app, job_id, index),
                ).fetchone()
                record["ai_assessment"] = assessment
                record["analyst_feedback"] = dict(feedback) if feedback else None
                anomalous += assessment.get("score", 0) >= 40
            connection.commit()
            status = model_status(connection)
            analysis["learning"] = {
                "status": "active", "mode": "shadow", "model_version": MODEL_VERSION,
                "records_assessed": len(records), "notable_records": anomalous,
                "dataset_learned": learn_dataset,
                "duplicate_of": existing_dataset["first_job"] if existing_dataset else None,
                "baseline_observations": status[app]["observations"],
                "feedback_labels": status[app]["feedback"],
                "source_system": source_system,
            }
            return analysis
        finally:
            connection.close()


def save_feedback(app: str, job_id: str, record_index: int, label: str, note: str = "") -> dict[str, Any]:
    if app not in VALID_APPS or label not in VALID_LABELS or not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("Invalid feedback")
    if record_index < 0:
        raise ValueError("Invalid record index")
    note = str(note or "").strip()[:500]
    now = datetime.now(timezone.utc).isoformat()
    with LOCK:
        connection = _connect()
        try:
            exists = connection.execute(
                "SELECT 1 FROM observations WHERE app=? AND job_id=? AND record_index=?",
                (app, job_id, record_index),
            ).fetchone()
            if not exists:
                raise LookupError("Learning observation not found")
            connection.execute(
                "INSERT INTO feedback(app,job_id,record_index,label,note,updated) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(app,job_id,record_index) DO UPDATE SET label=excluded.label,note=excluded.note,updated=excluded.updated",
                (app, job_id, record_index, label, note, now),
            )
            connection.commit()
            return {"label": label, "note": note, "updated": now}
        finally:
            connection.close()


def model_status(connection: sqlite3.Connection | None = None) -> dict[str, Any]:
    owns_connection = connection is None
    connection = connection or _connect()
    try:
        output: dict[str, Any] = {"model_version": MODEL_VERSION, "mode": "shadow"}
        for app in sorted(VALID_APPS):
            observations = connection.execute(
                "SELECT COUNT(*) FROM observations WHERE app=?", (app,)
            ).fetchone()[0]
            learned = connection.execute(
                "SELECT COUNT(*) FROM observations WHERE app=? AND learned=1", (app,)
            ).fetchone()[0]
            labels = dict(connection.execute(
                "SELECT label,COUNT(*) count FROM feedback WHERE app=? GROUP BY label", (app,)
            ).fetchall())
            supervised_ready = labels.get("confirmed_threat", 0) >= 10 and (
                labels.get("false_positive", 0) + labels.get("benign", 0)
            ) >= 10 and sum(labels.values()) >= 30
            output[app] = {
                "observations": observations, "learned_observations": learned,
                "feedback": labels, "feedback_model_ready": supervised_ready,
            }
        output["backfill"] = dict(BACKFILL_STATE)
        return output
    finally:
        if owns_connection:
            connection.close()


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def backfill_workspace(root: Path = ROOT) -> None:
    """Learn completed historical jobs in chronological order and annotate them."""
    jobs: list[tuple[float, str, Path]] = []
    for app in sorted(VALID_APPS):
        for path in (root / app / "storage" / "jobs").glob("*/analysis.json"):
            if re.fullmatch(r"[0-9a-f]{32}", path.parent.name):
                jobs.append((path.stat().st_mtime, app, path))
    jobs.sort(key=lambda item: item[0])
    BACKFILL_STATE.update({"status": "running", "processed_jobs": 0, "total_jobs": len(jobs), "error": None})
    try:
        for _, app, path in jobs:
            try:
                analysis = json.loads(path.read_text(encoding="utf-8"))
                state = analysis.get("analysis", {}).get("status")
                if state in {"queued", "running", "error"}:
                    continue
                annotate_analysis(app, path.parent.name, analysis)
                _atomic_write(path, analysis)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            finally:
                BACKFILL_STATE["processed_jobs"] += 1
        BACKFILL_STATE["status"] = "completed"
    except Exception as exc:
        BACKFILL_STATE.update({"status": "failed", "error": str(exc)[:500]})
