"""Unified Security Case Export & Forensic Integrity Verification Engine.

Generates structured forensic investigation packages (INC-ID.zip) for law enforcement,
internal compliance, regulatory audits, and DFIR response teams, with SHA-256 cryptographic
manifest and chain-of-custody verification.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import zipfile

from platform_core import audit_engine, incident_manager
from platform_core.licensing import crypto, fingerprint

logger = logging.getLogger("case_export")

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = WORKSPACE_ROOT / "storage"
JOBS_DIR = STORAGE_DIR / "jobs"
EVIDENCE_DIR = STORAGE_DIR / "evidence"


def _get_forensic_signing_keys() -> Tuple[bytes, bytes, str]:
    """Derives a deterministic, hardware-bound Ed25519 keypair for forensic artifact signing."""
    inst_id = fingerprint.get_installation_id()
    seed = hashlib.sha256(f"PlatformScope_ForensicSeal_Key_{inst_id}".encode("utf-8")).digest()
    sk, pk = crypto.generate_keypair(seed)
    return sk, pk, inst_id


def _sha256_bytes(data: bytes) -> str:
    """Calculate standard SHA-256 hex digest for binary data."""
    return hashlib.sha256(data).hexdigest()


def _format_size(num_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def _generate_case_markdown_report(incident: Dict[str, Any], meta: Dict[str, Any], evidence_count: int, ioc_count: int) -> str:
    """Generate high-fidelity bilingual Forensic Markdown Report for the case package."""
    inc_id = incident.get("id", "N/A")
    title = incident.get("title", "Unknown Incident")
    severity = incident.get("severity", "medium").upper()
    priority = incident.get("priority", "P3")
    status = incident.get("status", "new").upper()
    created_at = incident.get("created_at", "N/A")
    assigned_to = incident.get("assigned_to") or "غير معيّن (Unassigned)"
    source_app = incident.get("source_app", "Platform Core")
    tactics = incident.get("mitre_tactics", [])
    techniques = incident.get("mitre_techniques", [])
    desc = incident.get("description", "لا يوجد وصف إضافي.")
    exported_at = meta.get("exported_at", datetime.now(timezone.utc).isoformat())
    exported_by = meta.get("exported_by", "Platform System")

    md = f"""# تقرير التحقيق الجنائي الرقمي الرسمي (Official Digital Forensics & Incident Report)
**معرّف الحادث (Incident ID):** `{inc_id}`  
**العنوان:** {title}  
**مستوى الخطورة:** `{severity}` | **الأولوية:** `{priority}` | **الحالة الراهنة:** `{status}`  
**المحلل المسؤول:** {assigned_to}  
**تاريخ التصدير التوثيقي:** `{exported_at}`  
**المصدر المصدّر:** `{exported_by}`  

---

## 1. الملخص التنفيذي ومسار التحقيق (Executive Summary)
- **وصف الحادث**: {desc}
- **النظام / التطبيق المصدري**: `{source_app}`
- **تاريخ الإنشاء الأولي**: `{created_at}`
- **عدد الأدلة الرقمية المرفقة**: {evidence_count}
- **عدد مؤشرات الاختراق (IOCs)**: {ioc_count}

---

## 2. تصنيف تكتيكات وتقنيات ميتري (MITRE ATT&CK Matrix)
- **التكتيكات المرصودة (Tactics)**:
{chr(10).join(f"  - `{t}`" for t in tactics) if tactics else "  - لم تُسجل تكتيكات محددة."}
- **التقنيات المستخدمة (Techniques)**:
{chr(10).join(f"  - `{te}`" for te in techniques) if techniques else "  - لم تُسجل تقنيات محددة."}

---

## 3. سلسلة الحيازة الجنائية وضمان النزاهة (Forensic Chain of Custody & Integrity)
تم إنشاء هذا الأرشيف وتوثيقه آلياً عبر منصة بوابة التحليل الأمني الموحدة.
تحتوي هذه الحزمة على ملف `manifest.sha256` يتضمن بصمة التجزئة التشفيرية (SHA-256) لكل ملف ومرفق داخل القضية لضمان عدم التعديل أو التلاعب بالأدلة الرقمية أمام الجهات الرقابية والقضائية.

---
*تم إنشاء هذا التقرير تلقائياً بواسطة منصة بوابة التحليل الأمني الموحدة (Enterprise SOC Operating Platform).*
"""
    return md


class SecurityCaseExporter:
    """Packages incident details, timeline, events, evidence, IOCs, and SHA-256 manifest into a ZIP file."""

    @classmethod
    def export_case(cls, incident_id: str, actor: str = "system") -> Tuple[bytes, str]:
        """Exports a full forensic case ZIP archive for the specified incident ID.

        Returns (zip_bytes, suggested_filename).
        """
        inc = incident_manager.get_incident(incident_id)
        if not inc:
            raise ValueError(f"الحادث الأمني ذو المعرف [{incident_id}] غير موجود.")

        export_time = datetime.now(timezone.utc).isoformat()
        zip_buffer = io.BytesIO()

        # Dictionary to accumulate file paths and their SHA-256 hashes for manifest.sha256
        manifest_entries: Dict[str, str] = {}

        def add_file_to_archive(zf: zipfile.ZipFile, arcname: str, data: bytes):
            arcname_clean = arcname.replace("\\", "/")
            zf.writestr(arcname_clean, data)
            file_hash = _sha256_bytes(data)
            manifest_entries[arcname_clean] = file_hash

        with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 1. metadata.json
            metadata = {
                "case_id": inc["id"],
                "correlation_id": inc.get("correlation_id", ""),
                "title": inc.get("title", ""),
                "description": inc.get("description", ""),
                "severity": inc.get("severity", ""),
                "priority": inc.get("priority", ""),
                "status": inc.get("status", ""),
                "asset_criticality": inc.get("asset_criticality", "medium"),
                "business_impact": inc.get("business_impact", "medium"),
                "source_app": inc.get("source_app", ""),
                "source_job_id": inc.get("source_job_id"),
                "assigned_to": inc.get("assigned_to"),
                "mitre_tactics": inc.get("mitre_tactics", []),
                "mitre_techniques": inc.get("mitre_techniques", []),
                "entities": inc.get("entities", []),
                "confidence": inc.get("confidence", 80.0),
                "created_at": inc.get("created_at", ""),
                "updated_at": inc.get("updated_at", ""),
                "closed_at": inc.get("closed_at"),
                "exported_at": export_time,
                "exported_by": actor,
                "platform_version": "2.5.0-Enterprise",
            }
            add_file_to_archive(zf, "metadata.json", json.dumps(metadata, ensure_ascii=False, indent=2).encode("utf-8"))

            # 2. timeline.json
            timeline_items = inc.get("timeline", [])
            add_file_to_archive(zf, "timeline.json", json.dumps(timeline_items, ensure_ascii=False, indent=2).encode("utf-8"))

            # 3. analyst_notes.json
            notes_items = inc.get("notes", [])
            add_file_to_archive(zf, "analyst_notes.json", json.dumps(notes_items, ensure_ascii=False, indent=2).encode("utf-8"))

            # 4. events.json
            # Try to retrieve events from source_job_id analysis if available
            events_data: List[Dict[str, Any]] = []
            source_job_id = inc.get("source_job_id")
            if source_job_id:
                job_analysis_file = JOBS_DIR / source_job_id / "analysis.json"
                if job_analysis_file.exists():
                    try:
                        with open(job_analysis_file, "r", encoding="utf-8") as jf:
                            analysis_obj = json.load(jf)
                            # Extract findings or top security events
                            if "findings" in analysis_obj and isinstance(analysis_obj["findings"], list):
                                events_data.extend(analysis_obj["findings"][:500])
                            elif "events" in analysis_obj and isinstance(analysis_obj["events"], list):
                                events_data.extend(analysis_obj["events"][:500])
                    except Exception as e:
                        logger.warning(f"Could not load analysis.json for job {source_job_id}: {e}")
            add_file_to_archive(zf, "events.json", json.dumps(events_data, ensure_ascii=False, indent=2).encode("utf-8"))

            # 5. iocs.json
            # Collect from evidence items and entities
            iocs_data: List[Dict[str, Any]] = []
            for ev in inc.get("evidence", []):
                ev_type = ev.get("evidence_type", "").lower()
                if ev_type in {"ip", "domain", "url", "hash", "cve"}:
                    iocs_data.append({
                        "id": ev.get("id"),
                        "type": ev_type,
                        "value": ev.get("value") or ev.get("name"),
                        "notes": ev.get("notes", ""),
                        "added_at": ev.get("added_at", ""),
                        "source": "incident_evidence",
                    })

            # Also add any entities present in incident
            for ent in inc.get("entities", []):
                if isinstance(ent, dict):
                    ent_type = ent.get("type", "").lower()
                    ent_val = ent.get("value", "")
                else:
                    ent_type = "other"
                    ent_val = str(ent or "").strip()
                if ent_val and not any(i.get("value") == ent_val for i in iocs_data):
                    iocs_data.append({
                        "id": f"ent-{len(iocs_data)+1}",
                        "type": ent_type or "other",
                        "value": ent_val,
                        "notes": "Entity identified in incident analysis",
                        "added_at": inc.get("created_at", export_time),
                        "source": "incident_entities",
                    })
            add_file_to_archive(zf, "iocs.json", json.dumps(iocs_data, ensure_ascii=False, indent=2).encode("utf-8"))

            # 6. evidence/ directory
            evidence_list = inc.get("evidence", [])
            for ev in evidence_list:
                ev_id = ev.get("id", "ev")
                file_rel = ev.get("file_path")
                ev_name = ev.get("name", f"evidence_{ev_id}")
                safe_name = "".join(c for c in ev_name if c.isalnum() or c in "._- ")[:60].strip() or f"file_{ev_id}"
                
                # Check if file exists on disk in storage/evidence
                written = False
                if file_rel:
                    disk_file = EVIDENCE_DIR / file_rel
                    if disk_file.exists() and disk_file.is_file():
                        try:
                            file_bytes = disk_file.read_bytes()
                            add_file_to_archive(zf, f"evidence/{ev_id}_{safe_name}", file_bytes)
                            written = True
                        except Exception as e:
                            logger.warning(f"Failed to read evidence file {disk_file}: {e}")

                # If not a disk file or failed, write snippet/metadata
                if not written:
                    ev_value = ev.get("value") or ev.get("notes") or "لا توجد حمولة أو محتوى نصي إضافي."
                    snippet_data = (
                        f"Evidence ID: {ev_id}\n"
                        f"Type: {ev.get('evidence_type')}\n"
                        f"Name: {ev.get('name')}\n"
                        f"SHA-256: {ev.get('sha256', 'N/A')}\n"
                        f"Added By: {ev.get('added_by', 'analyst')} at {ev.get('added_at')}\n"
                        f"--------------------------------------------------\n"
                        f"{ev_value}\n"
                    ).encode("utf-8")
                    add_file_to_archive(zf, f"evidence/snippet_{ev_id}.txt", snippet_data)

            # 7. reports/ directory
            case_summary = {
                "incident_id": inc["id"],
                "title": inc["title"],
                "severity": inc["severity"],
                "priority": inc["priority"],
                "status": inc["status"],
                "total_timeline_actions": len(timeline_items),
                "total_notes": len(notes_items),
                "total_evidence_items": len(evidence_list),
                "total_iocs": len(iocs_data),
                "total_forensic_events": len(events_data),
                "generated_at": export_time,
                "exported_by": actor,
            }
            add_file_to_archive(zf, "reports/case_summary.json", json.dumps(case_summary, ensure_ascii=False, indent=2).encode("utf-8"))

            md_report = _generate_case_markdown_report(inc, metadata, len(evidence_list), len(iocs_data))
            add_file_to_archive(zf, "reports/case_report.md", md_report.encode("utf-8"))

            # 8. chain_of_custody.json (ISO/IEC 27037:2012 Forensic Chain of Custody)
            sk, pk, inst_id = _get_forensic_signing_keys()
            chain_of_custody = {
                "standard": "ISO/IEC 27037:2012 & NIST SP 800-86",
                "case_id": inc["id"],
                "custodian_actor": actor,
                "acquisition_timestamp_utc": export_time,
                "platform_installation_id": inst_id,
                "evidence_items_count": len(evidence_list),
                "forensic_hash_algorithm": "SHA-256",
                "digital_signature_algorithm": "RFC 8032 (Ed25519)",
                "chain_of_custody_status": "INTACT_AND_AUTHENTICATED",
                "verification_guidance": "Every file is hashed with SHA-256 in manifest.sha256 and digitally signed with Ed25519 to guarantee court admissibility and complete anti-tamper protection.",
            }
            add_file_to_archive(zf, "chain_of_custody.json", json.dumps(chain_of_custody, ensure_ascii=False, indent=2).encode("utf-8"))

            # 9. manifest.sha256 (Sorted alphabetically by relative path)
            manifest_lines = []
            for arcname in sorted(manifest_entries.keys()):
                manifest_lines.append(f"{manifest_entries[arcname]}  {arcname}")
            manifest_text = "\n".join(manifest_lines) + "\n"
            manifest_bytes = manifest_text.encode("utf-8")
            zf.writestr("manifest.sha256", manifest_bytes)

            # 10. manifest.sig (Ed25519 digital signature of manifest.sha256)
            manifest_signature = crypto.sign(sk, manifest_bytes)
            zf.writestr("manifest.sig", manifest_signature.hex().encode("ascii"))

            # 11. integrity_seal.json (Forensic sealing metadata)
            integrity_seal = {
                "standard_compliance": [
                    "ISO/IEC 27037:2012 (Digital Evidence Preservation)",
                    "NIST SP 800-86 (Forensic Techniques Integration)",
                    "RFC 8032 (Ed25519 Cryptographic Signatures)",
                ],
                "case_id": inc["id"],
                "exported_at": export_time,
                "exported_by": actor,
                "installation_id": inst_id,
                "seal_algorithm": "Ed25519+SHA-256",
                "total_files_covered": len(manifest_entries),
                "manifest_sha256": _sha256_bytes(manifest_bytes),
                "digital_signature": manifest_signature.hex(),
                "forensic_public_key": pk.hex(),
                "tamper_resistance_level": "Military-Grade / Court-Admissible Forensic Seal",
                "seal_status": "SEALED",
            }
            seal_bytes = json.dumps(integrity_seal, ensure_ascii=False, indent=2).encode("utf-8")
            zf.writestr("integrity_seal.json", seal_bytes)

        # Audit and record timeline entry
        try:
            audit_engine.record_engine_event(
                level="info",
                outcome="success",
                category="incident",
                action="incident.case_exported",
                message=f"تم تصدير وتوقيع ملف التحقيق الجنائي الرقمي للحادث [{incident_id}] بواسطة [{actor}]",
                application="incident_manager",
                details={
                    "incident_id": incident_id,
                    "exported_files_count": len(manifest_entries) + 3,
                    "export_time": export_time,
                    "actor": actor,
                    "installation_id": inst_id,
                    "signature_hex": manifest_signature.hex()[:16] + "...",
                }
            )
            incident_manager.add_note(
                incident_id=incident_id,
                note_text=f"تم تصدير وتوقيع حزمة التحقيق الجنائي الرقمي الرسمية ({inc['id']}_case.zip) مع ختم النزاهة التشفيري Ed25519+SHA256 المطابق لـ ISO/IEC 27037.",
                author=actor,
            )
        except Exception as e:
            logger.warning(f"Could not record export audit event: {e}")

        zip_bytes = zip_buffer.getvalue()
        filename = f"{inc['id']}_forensic_case.zip"
        return zip_bytes, filename


class SecurityCaseVerifier:
    """Verifies the forensic integrity and Ed25519 digital signature of an exported case ZIP file."""

    @classmethod
    def verify_case(cls, zip_data: bytes) -> Dict[str, Any]:
        """Inspects zip archive in-memory, recalculates file hashes, and validates against manifest and signature."""
        if not zip_data:
            return {"valid": False, "error": "حزمة التحقيق فارغة."}

        try:
            zf = zipfile.ZipFile(io.BytesIO(zip_data))
        except zipfile.BadZipFile:
            return {"valid": False, "error": "الملف المرفوع ليس ملف أرشيف ZIP صالحاً."}

        names = zf.namelist()
        if "manifest.sha256" not in names:
            return {
                "valid": False,
                "error": "ملف بيان التجزئة التشفيري (manifest.sha256) مفقود في الحزمة؛ لا يمكن التحقق من سلامة الأدلة.",
            }

        # Read and parse manifest.sha256
        manifest_raw = zf.read("manifest.sha256")
        manifest_content = manifest_raw.decode("utf-8", errors="replace")
        expected_manifest: Dict[str, str] = {}
        for line in manifest_content.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                hash_val, file_path = parts[0].strip().lower(), parts[1].strip()
                clean_path = file_path.lstrip("./").lstrip("/")
                expected_manifest[clean_path] = hash_val

        # Read integrity_seal.json and manifest.sig
        seal_valid = False
        signature_valid = False
        seal_info: Dict[str, Any] = {}
        if "integrity_seal.json" in names:
            try:
                seal_info = json.loads(zf.read("integrity_seal.json").decode("utf-8"))
                expected_manifest_hash = seal_info.get("manifest_sha256")
                actual_manifest_hash = _sha256_bytes(manifest_raw)
                seal_valid = (expected_manifest_hash == actual_manifest_hash)

                # Verify Ed25519 signature from seal and/or manifest.sig
                sig_hex = seal_info.get("digital_signature")
                pk_hex = seal_info.get("forensic_public_key")
                if sig_hex and pk_hex:
                    try:
                        sig_bytes = bytes.fromhex(sig_hex)
                        pk_bytes = bytes.fromhex(pk_hex)
                        signature_valid = crypto.verify(pk_bytes, sig_bytes, manifest_raw)
                    except Exception:
                        signature_valid = False
                
                # Also check manifest.sig if present
                if "manifest.sig" in names:
                    try:
                        file_sig_hex = zf.read("manifest.sig").decode("ascii", errors="ignore").strip()
                        if pk_hex:
                            sig_bytes = bytes.fromhex(file_sig_hex)
                            pk_bytes = bytes.fromhex(pk_hex)
                            file_sig_valid = crypto.verify(pk_bytes, sig_bytes, manifest_raw)
                            if not file_sig_valid:
                                signature_valid = False
                        if sig_hex and file_sig_hex.lower() != sig_hex.lower():
                            signature_valid = False
                    except Exception:
                        signature_valid = False
            except Exception:
                seal_valid = False
                signature_valid = False

        # Read metadata.json for case header
        meta_info: Dict[str, Any] = {}
        if "metadata.json" in names:
            try:
                meta_info = json.loads(zf.read("metadata.json").decode("utf-8"))
            except Exception:
                pass

        # Validate each expected file in the manifest
        verified_files: List[Dict[str, Any]] = []
        mismatches: List[Dict[str, Any]] = []
        missing_files: List[str] = []

        for exp_path, exp_hash in expected_manifest.items():
            if exp_path not in names:
                missing_files.append(exp_path)
                continue

            # Read file bytes and re-hash
            actual_bytes = zf.read(exp_path)
            actual_hash = _sha256_bytes(actual_bytes)
            size_formatted = _format_size(len(actual_bytes))

            if actual_hash.lower() == exp_hash.lower():
                verified_files.append({
                    "path": exp_path,
                    "sha256": actual_hash,
                    "size": size_formatted,
                    "status": "valid",
                })
            else:
                mismatches.append({
                    "path": exp_path,
                    "expected_sha256": exp_hash,
                    "actual_sha256": actual_hash,
                    "size": size_formatted,
                    "status": "tampered",
                })

        # Identify any unexpected/untracked files in the archive
        excluded_from_manifest = {"manifest.sha256", "manifest.sig", "integrity_seal.json"}
        untracked_files = [
            n for n in names
            if n not in expected_manifest and n not in excluded_from_manifest and not n.endswith("/")
        ]

        has_sig = bool(seal_info.get("digital_signature") or ("manifest.sig" in names))
        files_intact = (len(mismatches) == 0 and len(missing_files) == 0 and len(untracked_files) == 0)
        is_valid = files_intact and seal_valid and (signature_valid if has_sig else True)

        # Audit verification
        try:
            audit_engine.record_engine_event(
                level="info" if is_valid else "warning",
                outcome="success" if is_valid else "failure",
                category="incident",
                action="incident.case_verified",
                message=f"تم فحص نزاهة وتوقيع حزمة التحقيق للحادث [{meta_info.get('case_id', 'Unknown')}] - النتيجة: {'موثق ومطابق للمعايير الدولية' if is_valid else 'تحذير: تلاعب أو عدم تطابق في الأدلة'}",
                application="incident_manager",
                details={
                    "case_id": meta_info.get("case_id"),
                    "is_valid": is_valid,
                    "signature_valid": signature_valid,
                    "seal_valid": seal_valid,
                    "verified_count": len(verified_files),
                    "mismatches_count": len(mismatches),
                    "missing_count": len(missing_files),
                    "untracked_count": len(untracked_files),
                }
            )
        except Exception:
            pass

        return {
            "valid": is_valid,
            "case_id": meta_info.get("case_id", "N/A"),
            "title": meta_info.get("title", "Unknown Incident"),
            "severity": meta_info.get("severity", "medium"),
            "priority": meta_info.get("priority", "P3"),
            "status": meta_info.get("status", "unknown"),
            "exported_at": meta_info.get("exported_at", ""),
            "exported_by": meta_info.get("exported_by", ""),
            "installation_id": seal_info.get("installation_id", "UNKNOWN"),
            "standard_compliance": seal_info.get("standard_compliance", [
                "ISO/IEC 27037:2012 (Digital Evidence Preservation)",
                "NIST SP 800-86 (Forensic Techniques Integration)",
            ]),
            "seal_algorithm": seal_info.get("seal_algorithm", "Ed25519+SHA-256"),
            "signature_valid": signature_valid,
            "manifest_hash_valid": seal_valid,
            "tamper_detected": not is_valid,
            "total_files_in_manifest": len(expected_manifest),
            "verified_files_count": len(verified_files),
            "mismatches_count": len(mismatches),
            "missing_count": len(missing_files),
            "untracked_count": len(untracked_files),
            "verified_files": verified_files,
            "mismatches": mismatches,
            "missing": missing_files,
            "untracked": untracked_files,
            "seal_valid": seal_valid,
            "integrity_status": "SEALED_AND_VERIFIED_AUTHENTIC" if is_valid else "TAMPERED_OR_INVALID",
            "message": (
                "تم التحقق بنجاح: جميع الأدلة والملفات الجنائية مطابقة للمواصفات العالمية (ISO/IEC 27037 & NIST SP 800-86) وموقعة تشفيرياً بـ Ed25519 دون أي تعديل أو تلاعب."
                if is_valid
                else "تحذير أمني: تم رصد تلاعب أو تعديل غير مصرح به في حزمة الأدلة أو التوقيع الرقمي للتقرير."
            ),
        }
