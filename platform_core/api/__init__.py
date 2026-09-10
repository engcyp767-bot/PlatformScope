"""Public API module for Platform Scope."""

from platform_core.api.keys import (
    APIKeyManager,
    APIKeyRecord,
    APIScope,
    get_api_key_manager,
)
from platform_core.api.router import (
    APIRoute,
    APIRouter,
    APIResponse,
    error_response,
    get_api_router,
    success_response,
)

__all__ = [
    "APIKeyManager",
    "APIKeyRecord",
    "APIScope",
    "get_api_key_manager",
    "APIRouter",
    "APIRoute",
    "APIResponse",
    "success_response",
    "error_response",
    "get_api_router",
]
