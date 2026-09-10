"""English message templates for platform events."""

MESSAGES_EN: dict[str, str] = {
    "SYS_START": "Unified backend server started successfully on {host}:{port}.",
    "SYS_SHUTDOWN": "Unified backend server shut down successfully.",
    "LOG_LEVEL_CHANGED": "Platform log level changed from {old_level} to {new_level}.",
    "GENERAL_ERROR": "Unhandled exception in platform server: {message}.",
    "SERVICE_STARTED": "Service started successfully on {host}:{port}.",
    "SERVICE_STOPPED": "Service {service} stopped.",
    "DB_CONNECTION_FAILED": "Failed to connect to platform database ({database}).",
    "DB_WRITE_FAILED": "Engine {component} failed to save analysis result to database.",
    "DB_SLOW_QUERY": "Slow database query detected taking {duration_ms} ms.",
    "ANALYSIS_STARTED": "Analysis job {job_id} started via {component}.",
    "ANALYSIS_COMPLETED": "Analysis job {job_id} completed successfully in {duration_ms} ms ({events_processed} events processed).",
    "ANALYSIS_FAILED": "Analysis job {job_id} failed: {reason}.",
    "AUTH_LOGIN_SUCCESS": "User {username} logged in successfully.",
    "AUTH_LOGIN_FAILED": "Login attempt failed for user {username}: {reason}.",
    "AUTH_LOGOUT": "User {username} logged out.",
    "DETECTION_RULE_LOADED": "Successfully loaded {count} detection rules.",
    "DETECTION_MATCH": "Security detection match for job {job_id} via rule {rule_name}.",
    "SIGMA_COMPILATION_ERROR": "Sigma engine failed to compile rule {rule_id}: {error}.",
    "API_REQUEST_PROCESSED": "Processed API request {method} {path} with status {status_code} in {duration_ms} ms.",
    "API_REQUEST_ERROR": "Error processing API request {path}: {error}.",
    "CONFIG_UPDATED": "Platform configuration updated successfully by {username}.",
    "SYSTEM_HEALTH_CHECK": "System health check completed: current status {status}.",
    "QUEUE_OVERFLOW": "Log queue capacity exceeded; applying backpressure drop policy for low-priority messages.",
    "GENERAL_EVENT": "{message}",
}

