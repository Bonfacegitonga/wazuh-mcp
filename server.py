# wazuh_mcp_server.py

from typing import Dict, Any, List, Optional
from mcp.server.fastmcp import FastMCP
from core.client import WazuhClient
from core.alerts import Alert  
from core.vulnerabilities import Vulnerability  

# Initialize MCP app
mcp = FastMCP("wazuh-mcp")

# Singleton Alert instance
alert: Alert = None
vuln: Vulnerability = None

def get_alert_instance() -> Alert:
    global alert
    if not alert:
        client = WazuhClient()
        alert = Alert(client)
    return alert

def get_vuln_instance() -> Vulnerability:
    global vuln
    if not vuln:
        client = WazuhClient()
        vuln = Vulnerability(client)
    return vuln

alert = get_alert_instance()
vulns = get_vuln_instance()

# === Vulns Tools ===

@mcp.tool()
def fetch_all_vulnerabilities(
    size: int = 100,
    from_offset: int = 0,
    severity_filter:  Optional[List[str]] = None,
    ) -> Dict[str, Any]:
    """
    MCP Tool: Fetch all vulnerabilities from Wazuh/OpenSearch.

    Args:
        size: Number of results to return (default 100).
        from_offset: Pagination offset (default 0).
        severity_filter: Optional list of severities to filter by 
                         (e.g., ["Critical", "High"]).
                         If None, return all severities.

    Returns:
        Dictionary with:
            - vulnerabilities: list of simplified vulnerability objects
            - total: total number of matching vulnerabilities
            - aggregations: severity counts if enabled in underlying query
    """
    return vulns.fetch_all_vulnerabilities(size=size, from_offset=from_offset, severity_filter=severity_filter)


@mcp.tool()
def fetch_critical_vulnerabilities(size: int = 100) -> Dict[str, Any]:
    """Convenience: critical vulnerabilities. Default size is 100"""
    return vulns.fetch_vulnerabilities(size=size, severity_filter=["Critical"])

@mcp.tool()
def fetch_high_vulnerabilities(size: int = 100) -> Dict[str, Any]:
    """Convenience: Fetch only high vulnerabilities. Default size is 100"""
    return vulns.fetch_all_vulnerabilities(size=size, severity_filter=["High"])


@mcp.tool()
def fetch_medium_vulnerabilities(size: int = 100) -> Dict[str, Any]:
    """Convenience: Fetch only medium vulnerabilities. Default size is 100"""
    return vulns.fetch_all_vulnerabilities(size=size, severity_filter=["Medium"])


@mcp.tool()
def fetch_low_vulnerabilities(size: int = 100) -> Dict[str, Any]:
    """Convenience: Fetch only low vulnerabilities. Default size is 100"""
    return vulns.fetch_vulnerabilities(size=size, severity_filter=["Low"])


@mcp.tool()
def get_vulnerability_severity_counts(cluster_name: str = "wazuh") -> Dict[str, Any]:
    """Get severity counts without documents."""
    raw = vulns.get_vulnerability_severity_counts(cluster_name=cluster_name)
    return raw.get("aggregations", {})


# === Alerts Tools ===

@mcp.tool()
def fetch_alerts(
    size: int = 200,
    time_range: str = "24h",
    severity: str = "critical",
    cluster_name: str = "wazuh"
) -> Dict[str, Any]:
    """
    Unified function to fetch security alerts with flexible filtering.
    
    Args:
        size: Number of results to return (default: 200)
        time_range: Time period to search (default: "24h")
                   - "24h" for critical alerts
                   - "30d" for all alerts  
                   - "7d" for high alerts
                   - Other options: "1h", "6h", "12h", "2d", "3d", "14d", "2w"
        severity: Alert severity level (default: "critical")
                 - "critical" for critical alerts only
                 - "high" for high severity alerts only
                 - "all" for all severity levels
        cluster_name: Name of the Wazuh cluster (default: "wazuh")
    
   
    
    Examples:
        # Replicate fetch_critical_alerts_24h(200)
        fetch_alerts(size=200, time_range="24h", severity="critical")
        
        # Replicate fetch_all_alerts_30d(1000) 
        fetch_alerts(size=1000, time_range="30d", severity="all")
        
        # Replicate fetch_high_alerts_7d(500)
        fetch_alerts(size=500, time_range="7d", severity="high")
        
        # Custom combinations
        fetch_alerts(size=100, time_range="12h", severity="critical")
        fetch_alerts(size=300, time_range="2d", severity="high")
    """
    
    return alert.alerts(
        size=size,
        time_range=time_range,
        severity=severity,
        cluster_name=cluster_name
    )



# === Entrypoint ===
if __name__ == "__main__":
    mcp.run()
