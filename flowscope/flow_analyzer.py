"""Network Flow Analyzer Engine."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
try:
    from .file_parser import ParsedData
except ImportError:
    from file_parser import ParsedData

@dataclass
class FlowRecord:
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    src_port: str = ""
    dst_port: str = ""
    bytes: int = 0
    packets: int = 0
    duration: int = 0
    flags: str = ""
    extracted_ips: set[str] = field(default_factory=set)


def _find_column(headers: list[str], aliases: set[str]) -> int | None:
    for index, header in enumerate(headers):
        clean_header = str(header).strip().lower()
        if clean_header in aliases:
            return index
    return None


def analyze_flow_data(data: ParsedData, progress_callback=None) -> dict[str, Any]:
    """Perform a complete analysis on raw Flow data."""
    headers = data.headers
    
    # We rely on some basic columns for raw flow data
    mapping = {
        "src_ip": _find_column(headers, {"src ip", "source ip", "source address", "عنوان المصدر"}),
        "dst_ip": _find_column(headers, {"dst ip", "destination ip", "destination address", "عنوان الوجهة"}),
        "bytes": _find_column(headers, {"bytes", "octets", "total bytes", "البايتات"}),
        "packets": _find_column(headers, {"packets", "pkts", "total packets", "الحزم"}),
        "protocol": _find_column(headers, {"protocol", "proto", "البروتوكول"}),
        "src_port": _find_column(headers, {"source port", "src port", "sport", "منفذ المصدر"}),
        "dst_port": _find_column(headers, {"destination port", "dst port", "dport", "منفذ الوجهة"}),
    }
    
    if mapping["src_ip"] is None or mapping["dst_ip"] is None:
        raise ValueError("Could not identify Source and Destination IP columns in the Flow data.")
        
    records = []
    unique_ips = set()
    total_bytes = 0
    total_packets = 0
    
    top_talkers_src: dict[str, int] = {}
    top_talkers_dst: dict[str, int] = {}
    port_dist: dict[str, int] = {}
    
    total_rows = len(data.rows)
    for row_index, row in enumerate(data.rows, 1):
        if not any(row):
            continue
            
        def get_val(key: str, default: Any = "") -> Any:
            idx = mapping.get(key)
            if idx is not None and idx < len(row):
                val = row[idx]
                return val if val is not None else default
            return default

        src = str(get_val("src_ip")).strip()
        dst = str(get_val("dst_ip")).strip()
        
        try:
            b = int(float(get_val("bytes", 0)))
        except ValueError:
            b = 0
            
        try:
            p = int(float(get_val("packets", 0)))
        except ValueError:
            p = 0
            
        proto = str(get_val("protocol")).strip()
        sport = str(get_val("src_port")).strip()
        dport = str(get_val("dst_port")).strip()
        
        record = FlowRecord(
            src_ip=src,
            dst_ip=dst,
            protocol=proto,
            src_port=sport,
            dst_port=dport,
            bytes=b,
            packets=p
        )
        
        if src:
            record.extracted_ips.add(src)
            top_talkers_src[src] = top_talkers_src.get(src, 0) + b
        if dst:
            record.extracted_ips.add(dst)
            top_talkers_dst[dst] = top_talkers_dst.get(dst, 0) + b
            
        if dport:
            port_dist[dport] = port_dist.get(dport, 0) + 1
            
        unique_ips.update(record.extracted_ips)
        total_bytes += b
        total_packets += p
        records.append(record)

        if progress_callback and (row_index == total_rows or row_index % 100 == 0):
            ratio = row_index / total_rows if total_rows else 1
            progress_callback(20 + round(70 * ratio), "تحليل تدفقات الشبكة", row_index, total_rows)

    # Convert sizes to readable format for the summary
    def format_bytes(size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

    # Sort top talkers
    top_sources = [{"ip": k, "bytes": v, "formatted": format_bytes(v)} 
                   for k, v in sorted(top_talkers_src.items(), key=lambda item: item[1], reverse=True)[:15]]
    top_destinations = [{"ip": k, "bytes": v, "formatted": format_bytes(v)} 
                        for k, v in sorted(top_talkers_dst.items(), key=lambda item: item[1], reverse=True)[:15]]

    return {
        "metadata": {
            "filename": data.filename,
            "data_type": "network_flows",
            "row_count": len(records),
            "analyzed_at": datetime.now().isoformat(),
        },
        "summary": {
            "records": len(records),
            "unique_ips": len(unique_ips),
            "total_bytes": total_bytes,
            "formatted_bytes": format_bytes(total_bytes),
            "total_packets": total_packets,
        },
        "distributions": {
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_ports": [{"port": k, "count": v} for k, v in sorted(port_dist.items(), key=lambda item: item[1], reverse=True)[:10]]
        },
        "records": [{**r.__dict__, "extracted_ips": list(r.extracted_ips)} for r in records],
        "enrichment": {"status": "not_started"}
    }
