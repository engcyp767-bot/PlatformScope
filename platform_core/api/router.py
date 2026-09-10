"""Unified API Router and OpenAPI Generator for Platform Scope Public API.

Provides structured routing, path parameter extraction, scope & feature gate
enforcement, standardized response envelopes, and OpenAPI 3.0 specification generation.
"""

from __future__ import annotations

import functools
import inspect
import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from platform_core.api.keys import APIKeyManager, APIScope, get_api_key_manager
from platform_core.feature_gate import FeatureGate, FeatureID, get_feature_gate


@dataclass
class APIResponse:
    """Standardized API Response."""
    status_code: int = 200
    data: Any = None
    error: Optional[dict[str, Any]] = None
    meta: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json; charset=utf-8"})

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "success": 200 <= self.status_code < 300,
        }
        if self.data is not None:
            result["data"] = self.data
        if self.error is not None:
            result["error"] = self.error
        meta = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "v1",
            **self.meta,
        }
        result["meta"] = meta
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


def success_response(data: Any = None, meta: Optional[dict[str, Any]] = None, status_code: int = 200) -> APIResponse:
    """Helper for successful responses."""
    return APIResponse(status_code=status_code, data=data, meta=meta or {})


def error_response(
    code: str,
    message: str,
    status_code: int = 400,
    details: Optional[Any] = None,
) -> APIResponse:
    """Helper for error responses."""
    err: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        err["details"] = details
    return APIResponse(status_code=status_code, error=err)


@dataclass
class APIRoute:
    """Represents a single registered API route."""
    method: str
    path_pattern: str  # e.g., "/api/v1/agents/{agent_id}"
    handler: Callable[..., Any]
    required_scope: Optional[str] = None
    required_feature: Optional[FeatureID | str] = None
    summary: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    _regex: re.Pattern = field(init=False)
    _param_names: list[str] = field(init=False)

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        # Convert path pattern /api/v1/items/{item_id} -> regex
        pattern = self.path_pattern
        param_names = []
        for match in re.finditer(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", pattern):
            name = match.group(1)
            param_names.append(name)
            pattern = pattern.replace(f"{{{name}}}", f"(?P<{name}>[^/]+)")
        self._regex = re.compile(f"^{pattern}$")
        self._param_names = param_names

    def match(self, method: str, path: str) -> Optional[dict[str, str]]:
        """Match method and path, returning extracted path params or None."""
        if self.method != method.upper():
            return None
        m = self._regex.match(path)
        if m:
            return m.groupdict()
        return None


class APIRouter:
    """Central API Router for Platform Scope."""

    def __init__(
        self,
        prefix: str = "/api/v1",
        key_manager: Optional[APIKeyManager] = None,
        feature_gate: Optional[FeatureGate] = None,
    ) -> None:
        self.prefix = prefix.rstrip("/")
        self.routes: list[APIRoute] = []
        self._key_manager = key_manager or get_api_key_manager()
        self._feature_gate = feature_gate or get_feature_gate()

    def add_route(
        self,
        method: str,
        path: str,
        handler: Callable[..., Any],
        required_scope: Optional[str] = None,
        required_feature: Optional[FeatureID | str] = None,
        summary: str = "",
        description: str = "",
        tags: Optional[list[str]] = None,
    ) -> APIRoute:
        """Register a new route."""
        full_path = path if path.startswith(self.prefix) else f"{self.prefix}{path}"
        route = APIRoute(
            method=method,
            path_pattern=full_path,
            handler=handler,
            required_scope=required_scope,
            required_feature=required_feature,
            summary=summary,
            description=description,
            tags=tags or [],
        )
        self.routes.append(route)
        return route

    def get(self, path: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._decorator("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._decorator("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._decorator("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self._decorator("DELETE", path, **kwargs)

    def _decorator(self, method: str, path: str, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.add_route(method, path, fn, **kwargs)
            return fn
        return decorator

    def dispatch(
        self,
        method: str,
        raw_url: str,
        headers: Optional[dict[str, str]] = None,
        body_bytes: Optional[bytes] = None,
        auth_context: Optional[dict[str, Any]] = None,
    ) -> APIResponse:
        """Dispatch an incoming HTTP request to the matching registered route."""
        headers = headers or {}
        parsed = urlparse(raw_url)
        path = parsed.path
        query = parse_qs(parsed.query)
        query_params = {k: v[0] if len(v) == 1 else v for k, v in query.items()}

        # Parse JSON body if present
        body: Any = None
        if body_bytes:
            try:
                body = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                return error_response(
                    code="INVALID_JSON",
                    message="Request body must be valid JSON",
                    status_code=400,
                )

        # Find matching route
        matched_route: Optional[APIRoute] = None
        path_params: dict[str, str] = {}

        for route in self.routes:
            params = route.match(method, path)
            if params is not None:
                matched_route = route
                path_params = params
                break

        if not matched_route:
            return error_response(
                code="NOT_FOUND",
                message=f"Endpoint '{method} {path}' not found",
                status_code=404,
            )

        # Check API Key / Authentication if required
        h = {str(k).lower(): str(v) for k, v in headers.items()}
        api_key_header = h.get("x-api-key")
        auth_header = h.get("authorization")
        raw_key = None
        if api_key_header:
            raw_key = api_key_header
        elif auth_header and auth_header.startswith("bearer psk_"):
            raw_key = auth_header.split(" ", 1)[1]
        elif auth_header and auth_header.startswith("Bearer psk_"):
            raw_key = auth_header.split(" ", 1)[1]

        key_record = None
        if raw_key:
            key_record = self._key_manager.validate_key(raw_key, required_scope=matched_route.required_scope)
            if not key_record:
                return error_response(
                    code="UNAUTHORIZED",
                    message="Invalid, expired, or insufficiently scoped API key",
                    status_code=401,
                )
            # Check Rate Limit
            allowed, rem, reset_s = self._key_manager.check_rate_limit(key_record.key_id, key_record.rate_limit_rpm)
            if not allowed:
                resp = error_response(
                    code="RATE_LIMIT_EXCEEDED",
                    message=f"API key rate limit exceeded. Retry in {reset_s}s",
                    status_code=429,
                )
                resp.headers["Retry-After"] = str(reset_s)
                return resp
        elif matched_route.required_scope:
            # Endpoint requires API scope, but no key provided. Check session auth context:
            if not auth_context or not auth_context.get("authenticated"):
                return error_response(
                    code="UNAUTHORIZED",
                    message="Missing API key or valid session authorization",
                    status_code=401,
                )

        # Check Feature Gate
        if matched_route.required_feature:
            feature_name = (
                matched_route.required_feature.value
                if isinstance(matched_route.required_feature, FeatureID)
                else str(matched_route.required_feature)
            )
            denial = self._feature_gate.check_feature(feature_name)
            if denial:
                return error_response(
                    code="FEATURE_LOCKED",
                    message=denial.reason_en,
                    status_code=403,
                    details=denial.to_dict(),
                )

        # Build invocation arguments
        sig = inspect.signature(matched_route.handler)
        kwargs: dict[str, Any] = {}
        for param_name, param in sig.parameters.items():
            if param_name in path_params:
                kwargs[param_name] = path_params[param_name]
            elif param_name == "body":
                kwargs[param_name] = body
            elif param_name == "query":
                kwargs[param_name] = query_params
            elif param_name == "headers":
                kwargs[param_name] = headers
            elif param_name == "auth":
                kwargs[param_name] = {
                    "key_record": key_record.to_dict() if key_record else None,
                    "session": auth_context,
                }
            elif param_name in query_params:
                kwargs[param_name] = query_params[param_name]

        # Execute handler
        try:
            result = matched_route.handler(**kwargs)
            if isinstance(result, APIResponse):
                return result
            if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], int):
                # (status_code, data)
                return success_response(data=result[1], status_code=result[0])
            return success_response(data=result)
        except Exception as e:
            return error_response(
                code="INTERNAL_SERVER_ERROR",
                message=str(e),
                status_code=500,
            )

    def generate_openapi_spec(self, title: str = "Platform Scope Unified API", version: str = "1.0.0") -> dict[str, Any]:
        """Generate an OpenAPI 3.0.3 specification from registered routes."""
        paths: dict[str, Any] = {}

        for route in self.routes:
            p = route.path_pattern
            m = route.method.lower()
            if p not in paths:
                paths[p] = {}

            op: dict[str, Any] = {
                "summary": route.summary or f"{route.method} {p}",
                "description": route.description or "",
                "tags": route.tags or ["General"],
                "responses": {
                    "200": {
                        "description": "Successful operation",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "success": {"type": "boolean"},
                                        "data": {"type": "object"},
                                        "meta": {"type": "object"},
                                    },
                                }
                            }
                        },
                    },
                    "400": {"description": "Bad Request"},
                    "401": {"description": "Unauthorized"},
                    "403": {"description": "Feature locked or forbidden"},
                    "429": {"description": "Rate limit exceeded"},
                    "500": {"description": "Internal Server Error"},
                },
            }

            # Add path parameters
            if route._param_names:
                op["parameters"] = [
                    {
                        "name": pname,
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                    for pname in route._param_names
                ]

            if route.required_scope:
                op["security"] = [{"ApiKeyAuth": [route.required_scope]}]

            paths[p][m] = op

        return {
            "openapi": "3.0.3",
            "info": {
                "title": title,
                "version": version,
                "description": "Unified Security Operations and Endpoint Monitoring API for Platform Scope.",
            },
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                    }
                }
            },
        }


_router_instance: Optional[APIRouter] = None
_router_lock = threading.Lock()


def get_api_router() -> APIRouter:
    """Get or create singleton APIRouter."""
    global _router_instance
    if _router_instance is None:
        with _router_lock:
            if _router_instance is None:
                _router_instance = APIRouter()
    return _router_instance
