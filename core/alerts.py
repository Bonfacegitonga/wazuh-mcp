from .client import WazuhClient
from typing import  Dict, Any



class Alert:
    """
    Alert class for fetching and managing Wazuh alerts with flexible parameters.
    """
    
    def __init__(self, client: WazuhClient = None):
        """
        Initialize Alert class with optional WazuhClient instance.
        
        Args:
            client: WazuhClient instance. If None, creates a new instance.
        """
        self.client = client or WazuhClient()
        
        # Map severities to rule.level values
        self.severity_map = {
            "high": 10,       # high severity alerts (level >= 10)
            "critical": 15,   # critical alerts (level >= 15)
            "all": None       # no severity filtering
        }
    
    def fetch_alerts(
            self,
            size: int = 200,
            time_range: str = "24h",
            severity: str = "critical",  # options: "high", "critical", "all"
            cluster_name: str = "wazuh"
        ):
        """
        Fetch alerts with flexible parameters:
        - size: number of results (default 200)
        - time_range: e.g., "24h", "7d", "30d" (default 24h)
        - severity: "high" (>=10), "critical" (>=15), "all" (no filter, default critical)
        - cluster_name: cluster to filter by (default "wazuh")
        
        Returns:
            Search results from Wazuh alerts index
        """

        # Base query structure (common to both queries)
        query = {
            "sort": [],
            "size": size,
            "from": 0,
            "aggs": {
                "buckets": {
                    "terms": {
                        "field": "cluster.name",
                        "size": 5,
                        "order": {"_count": "desc"}
                    }
                }
            },
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "data.aws.createdAt", "format": "date_time"},
                {"field": "data.aws.end", "format": "date_time"},
                {"field": "data.aws.resource.instanceDetails.launchTime", "format": "date_time"},
                {"field": "data.aws.service.eventFirstSeen", "format": "date_time"},
                {"field": "data.aws.service.eventLastSeen", "format": "date_time"},
                {"field": "data.aws.start", "format": "date_time"},
                {"field": "data.aws.updatedAt", "format": "date_time"},
                {"field": "data.ms-graph.activityDateTime", "format": "date_time"},
                {"field": "data.ms-graph.complianceGracePeriodExpirationDateTime", "format": "date_time"},
                {"field": "data.ms-graph.createdDateTime", "format": "date_time"},
                {"field": "data.ms-graph.deviceActionResults.lastUpdatedDateTime", "format": "date_time"},
                {"field": "data.ms-graph.deviceActionResults.startDateTime", "format": "date_time"},
                {"field": "data.ms-graph.deviceHealthAttestationState.issuedDateTime", "format": "date_time"},
                {"field": "data.ms-graph.deviceHealthAttestationState.lastUpdateDateTime", "format": "date_time"},
                {"field": "data.ms-graph.easActivationDateTime", "format": "date_time"},
                {"field": "data.ms-graph.enrolledDateTime", "format": "date_time"},
                {"field": "data.ms-graph.exchangeLastSuccessfulSyncDateTime", "format": "date_time"},
                {"field": "data.ms-graph.firstActivityDateTime", "format": "date_time"},
                {"field": "data.ms-graph.lastActivityDateTime", "format": "date_time"},
                {"field": "data.ms-graph.lastSyncDateTime", "format": "date_time"},
                {"field": "data.ms-graph.lastUpdateDateTime", "format": "date_time"},
                {"field": "data.ms-graph.managementCertificateExpirationDate", "format": "date_time"},
                {"field": "data.ms-graph.resolvedDateTime", "format": "date_time"},
                {"field": "data.timestamp", "format": "date_time"},
                {"field": "data.vulnerability.published", "format": "date_time"},
                {"field": "data.vulnerability.updated", "format": "date_time"},
                {"field": "syscheck.mtime_after", "format": "date_time"},
                {"field": "syscheck.mtime_before", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"}
            ],
            "_source": {
                "excludes": ["@timestamp"]
            },
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": f"now-{time_range}",
                                    "lte": "now",
                                    "format": "epoch_millis"
                                }
                            }
                        },
                        {
                            "match_phrase": {
                                "cluster.name": {"query": cluster_name}
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }

        # Apply severity filter if not "all"
        min_level = self.severity_map.get(severity)
        if min_level is not None:
            query["query"]["bool"]["filter"].append(
                {"range": {"rule.level": {"gte": min_level}}}
            )

        return self.client.search_index("wazuh-alerts-*", query)
    
    def alerts(
        self,
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
            Dictionary with aggregated alerts and total count.
        """
        
        raw = self.fetch_alerts(size=size, time_range=time_range, severity=severity, cluster_name=cluster_name)

        # Aggregate alerts per agent + rule + description
        aggregated = {}
        for hit in raw.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            key = (
                src.get("agent", {}).get("name"),
                src.get("rule", {}).get("id"),
                src.get("rule", {}).get("description")
            )

            if key not in aggregated:
                aggregated[key] = {
                    "rule_id": src.get("rule", {}).get("id"),
                    "rule_level": src.get("rule", {}).get("level"),
                    "rule_description": src.get("rule", {}).get("description"),
                    "agent_name": src.get("agent", {}).get("name"),
                    "cluster": src.get("cluster", {}).get("name"),
                    "first_seen": src.get("timestamp"),
                    "last_seen": src.get("timestamp"),
                    "count": 1,
                }
            else:
                aggregated[key]["count"] += 1
                # update last_seen if newer
                if src.get("timestamp") > aggregated[key]["last_seen"]:
                    aggregated[key]["last_seen"] = src.get("timestamp")

        simplified = list(aggregated.values())

        return {
            "alerts": simplified,
            "total": len(simplified),
        }


    def fetch_critical_alerts_24h(self, size: int = 200):
        """
        Fetch critical alerts from last 24 hours (matches your first query).
        
        Args:
            size: Number of results to return
            
        Returns:
            Search results for critical alerts from last 24 hours
        """
        return self.fetch_alerts(
            size=size,
            time_range="24h", 
            severity="critical"
        )

    def fetch_all_alerts_30d(self, size: int = 1000):
        """
        Fetch all alerts from last 30 days (matches your second query).
        
        Args:
            size: Number of results to return
            
        Returns:
            Search results for all alerts from last 30 days
        """
        return self.fetch_alerts(
            size=size,
            time_range="30d",
            severity="all"
        )

    def fetch_high_alerts_7d(self, size: int = 500):
        """
        Fetch high severity alerts from last 7 days.
        
        Args:
            size: Number of results to return
            
        Returns:
            Search results for high severity alerts from last 7 days
        """
        return self.fetch_alerts(
            size=size,
            time_range="7d",
            severity="high"
        )

    def get_available_severities(self):
        """
        Get list of available severity levels.
        
        Returns:
            List of available severity levels
        """
        return list(self.severity_map.keys())

    def get_severity_level(self, severity: str):
        """
        Get the numeric level for a severity string.
        
        Args:
            severity: Severity level string
            
        Returns:
            Numeric level or None for 'all'
        """
        return self.severity_map.get(severity)


if __name__ == "__main__":
    # Create Alert instance
    alert = Alert()
    