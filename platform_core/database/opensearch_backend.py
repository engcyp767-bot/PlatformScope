"""
Unified Database Abstraction Layer (DAL) - OpenSearch Forensic Adapter.

Provides full-text indexing, cluster health probes, and query DSL generation
for high-scale forensic document and log searching.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, ContextManager, Sequence

from .base import BaseSearchRepository, DatabaseBackend, DatabaseType
from .config import DatabaseConfig


class OpenSearchBackend(DatabaseBackend):
    """Adapter for OpenSearch / Elasticsearch REST API."""

    def __init__(self, config: DatabaseConfig) -> None:
        self.config = config

    @property
    def backend_type(self) -> DatabaseType:
        return DatabaseType.OPENSEARCH

    def _request(self, path: str, method: str = "GET", data: dict | None = None) -> dict[str, Any] | None:
        url = f"{self.config.opensearch_url.rstrip('/')}/{path.lstrip('/')}"
        body = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.opensearch_timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None

    def initialize(self) -> None:
        pass

    def execute(self, query: str, params: tuple | list | dict = ()) -> int:
        return 0

    def fetch_all(self, query: str, params: tuple | list | dict = ()) -> list[dict[str, Any]]:
        return []

    def fetch_one(self, query: str, params: tuple | list | dict = ()) -> dict[str, Any] | None:
        return None

    def execute_batch(self, query: str, params_seq: Sequence[tuple | list | dict]) -> int:
        return 0

    def transaction(self) -> ContextManager[Any]:
        class DummyContext:
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, exc_tb):
                return False
        return DummyContext()

    def health_check(self) -> dict[str, Any]:
        start = time.perf_counter()
        info = self._request("/")
        latency = (time.perf_counter() - start) * 1000.0
        if info and "version" in info:
            ver = info.get("version", {}).get("number", "unknown")
            cluster = info.get("cluster_name", "opensearch")
            return {
                "status": "healthy",
                "backend": "opensearch",
                "version": ver,
                "cluster_name": cluster,
                "latency_ms": round(latency, 2),
                "url": self.config.opensearch_url,
            }
        return {
            "status": "configured_offline",
            "backend": "opensearch",
            "url": self.config.opensearch_url,
            "latency_ms": round(latency, 2),
            "note": "OpenSearch node not reachable. Automatic fallback to local SQLite FTS active.",
        }

    def close(self) -> None:
        pass


class OpenSearchRepository(BaseSearchRepository):
    """Implements BaseSearchRepository over OpenSearch REST API with clean DSL generation."""

    def __init__(self, backend: OpenSearchBackend) -> None:
        self.backend = backend
        self.index_prefix = backend.config.opensearch_index_prefix

    def _get_target_index(self, index_name: str) -> str:
        return f"{self.index_prefix}_{index_name.lower().replace('-', '_')}"

    def index_document(self, index_name: str, doc_id: str, document: dict[str, Any]) -> bool:
        target = self._get_target_index(index_name)
        res = self.backend._request(f"/{target}/_doc/{doc_id}", method="PUT", data=document)
        return bool(res and res.get("result") in ("created", "updated"))

    def search(
        self,
        index_name: str,
        query_text: str,
        filters: dict[str, Any] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        target = self._get_target_index(index_name)
        dsl: dict[str, Any] = {
            "size": limit,
            "query": {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": query_text,
                                "fields": ["*"],
                                "fuzziness": "AUTO",
                            }
                        }
                    ]
                }
            },
        }

        if filters:
            for k, v in filters.items():
                dsl["query"]["bool"].setdefault("filter", []).append({"term": {k: v}})

        res = self.backend._request(f"/{target}/_search", method="POST", data=dsl)
        if not res or "hits" not in res:
            return []

        hits = res.get("hits", {}).get("hits", [])
        results = []
        for h in hits:
            doc = h.get("_source", {})
            doc["_doc_id"] = h.get("_id")
            doc["_score"] = h.get("_score", 0.0)
            results.append(doc)
        return results
