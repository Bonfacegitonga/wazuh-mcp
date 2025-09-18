from .client import WazuhClient
from typing import List, Dict, Any, Optional

class Vulnerability:
    """
    Class for fetching and managing Wazuh vulnerability data
    from the OpenSearch/Elasticsearch backend.

    Provides flexible query options with severity filtering, sorting,
    pagination, and severity aggregations.

    Example:
    --------
    v = Vulnerability(client)
    results = v.fetch_vulnerabilities(size=50, severity_filter=["Critical", "High"])
    """

    def __init__(self, client: WazuhClient = None):
        """
        Initialize Vulnerability handler.

        Args:
            client: WazuhClient instance used to query Elasticsearch/OpenSearch.
        """
        self.client = client or WazuhClient()

    def fetch_vulnerabilities(
        self,
        size: int = 100,
        from_offset: int = 0,
        severity_filter: List[str] = None,  # ["Critical", "High", "Medium", "Low"]
        cluster_name: str = "wazuh",
        sort_by: str = "detected_at",  # "detected_at" or "published_at"
        sort_order: str = "desc",      # "desc" or "asc"
        include_aggregations: bool = True
    ) -> Dict[str, Any]:
        """
        Fetch vulnerability data with flexible filtering and sorting.
        """

        # Build the base query structure
        query = {
            "size": size,
            "from": from_offset,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "package.installed", "format": "date_time"},
                {"field": "vulnerability.detected_at", "format": "date_time"},
                {"field": "vulnerability.published_at", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "filter": [
                        {"match_all": {}},
                        {
                            "match_phrase": {
                                "wazuh.cluster.name": {"query": cluster_name}
                            }
                        },
                    ]
                }
            },
            "sort": [{f"vulnerability.{sort_by}": {"order": sort_order}}],
        }

        # Add severity filter if specified
        if severity_filter and isinstance(severity_filter, list):
            severity_should_clauses = [
                {"match_phrase": {"vulnerability.severity": severity}}
                for severity in severity_filter
            ]
            query["query"]["bool"]["should"] = severity_should_clauses
            query["query"]["bool"]["minimum_should_match"] = 1

        # Add aggregations if requested
        if include_aggregations:
            query["aggs"] = {
                "severity_filter": {
                    "filters": {
                        "filters": {
                            sev: {
                                "bool": {
                                    "filter": [
                                        {"match_phrase": {"vulnerability.severity": sev}}
                                    ]
                                }
                            }
                            for sev in ["Critical", "High", "Medium", "Low"]
                        }
                    }
                }
            }

        return self.client.search_index("wazuh-states-vulnerabilities-*", query)


    

    def fetch_all_vulnerabilities(
        self,
        size: int = 100,
        from_offset: int = 0,
        severity_filter:  Optional[List[str]] = None,
        cluster_name: str = "wazuh",
        sort_by: str = "detected_at",
        sort_order: str = "desc",
        include_aggregations: bool = True
    ) -> Dict[str, Any]:
        """
        Fetch vulnerabilities with flexible parameters.
        Deduplicates repeated CVEs per agent.
        Optimized for speed.
        """
        
        raw = self.fetch_vulnerabilities(
            size=size,
            from_offset=from_offset,
            severity_filter=severity_filter,
            cluster_name=cluster_name,
            sort_by=sort_by,
            sort_order=sort_order,
            include_aggregations=include_aggregations
        )

        simplified = []
        seen = set()

        for hit in raw.get("hits", {}).get("hits", []):
            src = hit["_source"]

            vuln = src.get("vulnerability")
            agent = src.get("agent")
            wazuh = src.get("wazuh")
            package = src.get("package")

            cve_id = vuln.get("id") if vuln else None
            agent_id = agent.get("id") if agent else None

            # skip if missing key identifiers
            if not cve_id or not agent_id:
                continue

            key = (agent_id, cve_id)
            if key in seen:
                continue
            seen.add(key)

            simplified.append({
                "cve_id": cve_id,
                "severity": vuln.get("severity") if vuln else None,
                "score": vuln.get("score", {}).get("base") if vuln else None,
                "description": vuln.get("description") if vuln else None,
                "reference": vuln.get("reference") if vuln else None,
                "detected_at": vuln.get("detected_at") if vuln else None,
                "published_at": vuln.get("published_at") if vuln else None,
                "agent_id": agent_id,
                "agent_name": agent.get("name") if agent else None,
                "package_name": package.get("name") if package else None,
                "package_version": package.get("version") if package else None,
                "package_description": package.get("description") if package else None,
                "cluster": wazuh.get("cluster", {}).get("name") if wazuh else None,
            })

        return {
            "vulnerabilities": simplified,
            "total": raw["hits"]["total"]["value"],
            "aggregations": raw.get("aggregations") if include_aggregations else None
        }


   
    def fetch_all_vulnerabilities_with_counts(self, size: int = 100):
        """Fetch all vulnerabilities with severity count aggregations."""
        return self.fetch_vulnerabilities(
            size=size, severity_filter=None, include_aggregations=True
        )

    def get_vulnerability_severity_counts(self, cluster_name: str = "wazuh"):
        """Get only the severity count aggregations without document results."""
        return self.fetch_vulnerabilities(
            size=0, cluster_name=cluster_name, include_aggregations=True
        )



if __name__ == "__main__":
    # Create Alert instance
    vuln = Vulnerability()

    
