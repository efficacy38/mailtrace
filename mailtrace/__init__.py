import logging
import os
import time
from datetime import datetime
from pathlib import Path
from .aggregator import select_aggregator
from .config import Config, load_config
from .graph import MailGraph
from .mcp import create_server, run_server
from .trace import (
    query_logs_by_keywords,
    trace_mail_flow,
    trace_mail_flow_to_file,
)

__all__ = [
    "Config",
    "MailGraph",
    "create_server",
    "load_config",
    "query_logs_by_keywords",
    "run_server",
    "select_aggregator",
    "trace_mail_flow",
    "trace_mail_flow_to_file",
    "query_logs_by_keywords",
    "select_aggregator",
    "health_check",
]

logger = logging.getLogger("mailtrace")


def _make_health_result(
    status: str,
    message: str,
    diagnostics: dict,
    remediation: list[str],
    start_time: float,
) -> dict:
    """Create a standardized health check result dictionary."""
    return {
        "status": status,
        "message": message,
        "diagnostics": diagnostics,
        "remediation": remediation,
        "timestamp": datetime.now(),
        "duration_ms": (time.time() - start_time) * 1000,
    }


def _check_dependencies(diagnostics: dict, start_time: float) -> dict | None:
    """Check if required dependencies are installed. Returns error dict or None."""
    try:
        import opensearchpy  # noqa: F401
        import paramiko  # noqa: F401

        diagnostics["dependencies"] = {
            "opensearchpy": "installed",
            "paramiko": "installed",
        }
        return None
    except ImportError as e:
        return _make_health_result(
            status="unhealthy",
            message=f"Missing dependency: {e}",
            diagnostics={"dependencies": {"error": str(e)}},
            remediation=[
                "Install mailtrace dependencies:",
                "  cd rca-agent/external-tools/mailtrace",
                "  uv add --editable .",
            ],
            start_time=start_time,
        )


def _check_opensearch_connectivity(
    config: Config, diagnostics: dict, start_time: float, timeout: float
) -> dict:
    """Check OpenSearch connectivity and return health result."""
    from opensearchpy import OpenSearch

    os_config = config.opensearch_config
    try:
        client = OpenSearch(
            hosts=[{"host": os_config.host, "port": os_config.port}],
            http_auth=(os_config.username, os_config.password),
            use_ssl=os_config.use_ssl,
            verify_certs=False,
            timeout=timeout,
        )
        info = client.info()
        diagnostics["connectivity"] = {
            "method": "opensearch",
            "host": os_config.host,
            "port": os_config.port,
            "status": "reachable",
            "cluster_name": info.get("cluster_name"),
        }
        return _make_health_result(
            status="healthy",
            message=f"Mailtrace healthy - OpenSearch reachable at {os_config.host}:{os_config.port}",
            diagnostics=diagnostics,
            remediation=[],
            start_time=start_time,
        )
    except Exception as e:
        diagnostics["connectivity"] = {
            "method": "opensearch",
            "host": os_config.host,
            "port": os_config.port,
            "status": "unreachable",
            "error": str(e),
        }
        return _make_health_result(
            status="unhealthy",
            message=f"OpenSearch unreachable: {e}",
            diagnostics=diagnostics,
            remediation=[
                f"Check OpenSearch is running at {os_config.host}:{os_config.port}",
                "Verify credentials in config file",
                "Check network connectivity and firewall rules",
            ],
            start_time=start_time,
        )


def health_check(config_path: str | None = None, timeout: float = 5.0) -> dict:
    """
    Perform health check for mailtrace tool.

    Validates:
    1. Dependencies are importable
    2. Config file exists and is parseable
    3. OpenSearch/SSH connectivity based on method

    Args:
        config_path: Optional path to config file (defaults to config.yaml)
        timeout: Health check timeout in seconds

    Returns:
        Dictionary with health check result containing status, message,
        diagnostics, remediation steps, timestamp, and duration_ms.
    """
    start_time = time.time()
    diagnostics: dict = {}

    # Check dependencies
    dep_error = _check_dependencies(diagnostics, start_time)
    if dep_error:
        return dep_error

    # Validate config file
    config_path = config_path or "config.yaml"
    if not Path(config_path).exists():
        diagnostics["config"] = {"path": config_path, "exists": False}
        return _make_health_result(
            status="unhealthy",
            message=f"Config file not found: {config_path}",
            diagnostics=diagnostics,
            remediation=[
                "Create mailtrace config file:",
                f"  cp {config_path}.example {config_path}",
                "Then edit the file with your settings",
            ],
            start_time=start_time,
        )

    diagnostics["config"] = {"path": config_path, "exists": True}

    # Try loading config
    try:
        config = load_config(config_path)
        diagnostics["config"]["method"] = config.method.value
        diagnostics["config"]["parseable"] = True
    except Exception as e:
        diagnostics["config"]["error"] = str(e)
        return _make_health_result(
            status="unhealthy",
            message=f"Failed to parse config: {e}",
            diagnostics=diagnostics,
            remediation=[
                f"Check config file syntax: {config_path}",
                "Validate YAML format",
                "Check required fields are present",
            ],
            start_time=start_time,
        )

    # Test connectivity based on method
    if config.method.value == "opensearch":
        return _check_opensearch_connectivity(
            config, diagnostics, start_time, timeout
        )

    if config.method.value == "ssh":
        diagnostics["connectivity"] = {
            "method": "ssh",
            "username": config.ssh_config.username,
            "status": "not_tested",
        }
        return _make_health_result(
            status="warning",
            message="Mailtrace configured for SSH - connectivity not tested",
            diagnostics=diagnostics,
            remediation=[
                "SSH connectivity will be tested when querying logs",
                "Ensure SSH credentials and hosts are configured correctly",
            ],
            start_time=start_time,
        )

    return _make_health_result(
        status="warning",
        message=f"Unknown method: {config.method.value}",
        diagnostics=diagnostics,
        remediation=["Check config file method field"],
        start_time=start_time,
    )


def init_logger(config: Config) -> None:
    """Initialize logging for mailtrace and opensearch loggers."""
    if logger.hasHandlers():
        return

    log_level = config.log_level
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Configure mailtrace logger
    logger.propagate = False
    logger.setLevel(log_level)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # Configure opensearch logger
    opensearch_logger = logging.getLogger("opensearch")
    opensearch_logger.propagate = False
    opensearch_logger.setLevel(log_level)
    if not opensearch_logger.hasHandlers():
        opensearch_stream_handler = logging.StreamHandler()
        opensearch_stream_handler.setFormatter(formatter)
        opensearch_logger.addHandler(opensearch_stream_handler)


# Auto-load config when imported as a library (not as CLI)
# This allows library users to have logging configured automatically
config = None
if os.path.exists("config.yaml") and __name__ != "__main__":
    try:
        config = load_config()
        init_logger(config)
    except (ValueError, TypeError):
        # Config file exists but is not for mailtrace - this is fine
        pass
