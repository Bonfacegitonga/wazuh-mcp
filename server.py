# wazuh_mcp_server.py

from typing import Dict, Any, List
from mcp.server.fastmcp import FastMCP
from core.client import WazuhClient
from core.alerts import Alert  

# Initialize MCP app
mcp = FastMCP("wazuh-alerts")

# Singleton Alert instance
alert: Alert = None

def get_alert_instance() -> Alert:
    global alert
    if not alert:
        client = WazuhClient()
        alert = Alert(client)
    return alert


# === Tools ===

@mcp.tool()
def fetch_alerts(
    size: int = 200,
    time_range: str = "24h",
    severity: str = "critical",
    cluster_name: str = "wazuh"
) -> Dict[str, Any]:
    """
    Fetch Wazuh alerts with flexible parameters.

    Args:
        size: Number of results to return (default 200).
        time_range: Time window, e.g. '24h', '7d', '30d'.
        severity: One of 'high', 'critical', 'all'.
        cluster_name: Wazuh cluster name (default 'wazuh').

    Returns:
        Dictionary with alerts and total count.
    """
    a = get_alert_instance()
    raw = a.fetch_alerts(size=size, time_range=time_range, severity=severity, cluster_name=cluster_name)

    # Simplify response for MCP clients
    simplified = [
        {
            "rule_id": hit["_source"].get("rule", {}).get("id"),
            "rule_level": hit["_source"].get("rule", {}).get("level"),
            "agent_name": hit["_source"].get("agent", {}).get("name"),
            "cluster": hit["_source"].get("cluster", {}).get("name"),
            "timestamp": hit["_source"].get("timestamp"),
        }
        for hit in raw.get("hits", {}).get("hits", [])
    ]

    return {
        "alerts": simplified,
        "total": raw.get("hits", {}).get("total", {}).get("value", 0),
    }


@mcp.tool()
def fetch_critical_alerts_24h(size: int = 200) -> Dict[str, Any]:
    """
    Convenience method: Fetch critical alerts from last 24h.
    """
    a = get_alert_instance()
    return fetch_alerts(size=size, time_range="24h", severity="critical")


@mcp.tool()
def fetch_all_alerts_30d(size: int = 1000) -> Dict[str, Any]:
    """
    Convenience method: Fetch all alerts from last 30 days.
    """
    a = get_alert_instance()
    return fetch_alerts(size=size, time_range="30d", severity="all")


@mcp.tool()
def fetch_high_alerts_7d(size: int = 500) -> Dict[str, Any]:
    """
    Convenience method: Fetch high severity alerts from last 7 days.
    """
    a = get_alert_instance()
    return fetch_alerts(size=size, time_range="7d", severity="high")


@mcp.tool()
def get_available_severities() -> List[str]:
    """
    Get list of available severity levels.
    """
    a = get_alert_instance()
    return a.get_available_severities()


# === Entrypoint ===
if __name__ == "__main__":
    mcp.run()
