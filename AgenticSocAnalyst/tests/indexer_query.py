"""
Phase 3 — Wazuh Indexer (OpenSearch) Alert Query
=================================================
Queries the Wazuh Indexer directly via OpenSearch REST API to retrieve
full alert data with all fields (rule, MITRE, agent, raw event data).

This is the PRIMARY method for retrieving alerts programmatically.
The Wazuh REST API provides agent/rule metadata; the Indexer has the actual alerts.

Usage:
    python tests/indexer_query.py
    python tests/indexer_query.py --min-level 10
    python tests/indexer_query.py --mitre T1078
    python tests/indexer_query.py --agent MAXW --limit 50
    python tests/indexer_query.py --export alerts_export.json

OpenSearch Query DSL: https://opensearch.org/docs/latest/query-dsl/
"""

import argparse
import json
import sys
import urllib3
from datetime import datetime, timedelta, timezone

import requests

# Suppress SSL warnings (self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INDEXER_URL = "https://127.0.0.1:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword"

# Wazuh alert index pattern
ALERT_INDEX = "wazuh-alerts-4.x-*"


class WazuhIndexer:
    """OpenSearch client for querying Wazuh alert indices."""

    def __init__(self, base_url: str, user: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.auth = (user, password)
        self.session = requests.Session()
        self.session.verify = False
        self.session.auth = self.auth
        self.session.headers.update({"Content-Type": "application/json"})

    def health_check(self) -> dict:
        """Check cluster health."""
        resp = self.session.get(f"{self.base_url}/_cluster/health")
        if resp.status_code != 200:
            print(f"[ERROR] Indexer health check failed: {resp.status_code}")
            print(f"        {resp.text[:200]}")
            return {}
        return resp.json()

    def list_indices(self, pattern: str = "wazuh-*") -> list:
        """List all Wazuh-related indices."""
        resp = self.session.get(f"{self.base_url}/_cat/indices/{pattern}?format=json&s=index")
        if resp.status_code != 200:
            return []
        return resp.json()

    def count_alerts(self, index: str = ALERT_INDEX) -> int:
        """Count total alerts in the index."""
        resp = self.session.get(f"{self.base_url}/{index}/_count")
        if resp.status_code != 200:
            return 0
        return resp.json().get("count", 0)

    def search_alerts(
        self,
        limit: int = 20,
        min_level: int = None,
        rule_id: str = None,
        agent_name: str = None,
        mitre_id: str = None,
        search_text: str = None,
        hours_back: int = 24,
        index: str = ALERT_INDEX,
    ) -> list:
        """Search alerts with filters using OpenSearch Query DSL."""

        # Build query
        must_clauses = []

        # Time range filter
        time_from = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
        must_clauses.append({
            "range": {
                "timestamp": {
                    "gte": time_from,
                    "format": "strict_date_optional_time"
                }
            }
        })

        # Minimum alert level
        if min_level:
            must_clauses.append({
                "range": {"rule.level": {"gte": min_level}}
            })

        # Specific rule ID
        if rule_id:
            must_clauses.append({
                "match": {"rule.id": rule_id}
            })

        # Agent name filter
        if agent_name:
            must_clauses.append({
                "match": {"agent.name": agent_name}
            })

        # MITRE ATT&CK technique filter
        if mitre_id:
            must_clauses.append({
                "match": {"rule.mitre.id": mitre_id}
            })

        # Free text search
        if search_text:
            must_clauses.append({
                "query_string": {"query": search_text}
            })

        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": must_clauses
                }
            }
        }

        resp = self.session.post(
            f"{self.base_url}/{index}/_search",
            json=query
        )

        if resp.status_code != 200:
            print(f"[ERROR] Search failed: {resp.status_code}")
            print(f"        {resp.text[:300]}")
            return []

        hits = resp.json().get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]

    def get_alert_summary(self, hours_back: int = 24, index: str = ALERT_INDEX) -> dict:
        """Get aggregated alert summary by rule level and MITRE tactic."""

        time_from = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        query = {
            "size": 0,
            "query": {
                "range": {
                    "timestamp": {
                        "gte": time_from,
                        "format": "strict_date_optional_time"
                    }
                }
            },
            "aggs": {
                "by_level": {
                    "terms": {"field": "rule.level", "size": 20, "order": {"_key": "desc"}}
                },
                "by_description": {
                    "terms": {"field": "rule.description", "size": 25}
                },
                "by_mitre_tactic": {
                    "terms": {"field": "rule.mitre.tactic", "size": 20}
                },
                "by_mitre_technique": {
                    "terms": {"field": "rule.mitre.id", "size": 20}
                },
                "by_agent": {
                    "terms": {"field": "agent.name", "size": 10}
                }
            }
        }

        resp = self.session.post(f"{self.base_url}/{index}/_search", json=query)
        if resp.status_code != 200:
            print(f"[ERROR] Summary query failed: {resp.status_code}")
            return {}

        return resp.json().get("aggregations", {})


def print_section(title: str):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def format_alert(alert: dict, verbose: bool = False) -> str:
    """Format a single alert for display."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {})
    data = alert.get("data", {})

    ts = alert.get("timestamp", "?")[:19]
    level = rule.get("level", "?")
    rule_id = rule.get("id", "?")
    desc = rule.get("description", "?")[:70]
    agent_name = agent.get("name", "?")
    groups = ", ".join(rule.get("groups", []))
    mitre_ids = ", ".join(mitre.get("id", []))
    mitre_tactics = ", ".join(mitre.get("tactic", []))

    lines = [
        f"  [{ts}] Level {level:>2} | Rule {rule_id:<8} | Agent: {agent_name}",
        f"    {desc}",
    ]

    if mitre_ids:
        lines.append(f"    MITRE: {mitre_ids} ({mitre_tactics})")

    if verbose:
        lines.append(f"    Groups: {groups}")
        # Show key data fields
        if data:
            src_ip = data.get("srcip", data.get("src_ip", ""))
            dst_ip = data.get("dstip", data.get("dst_ip", ""))
            user = data.get("srcuser", data.get("win", {}).get("eventdata", {}).get("targetUserName", ""))
            if src_ip:
                lines.append(f"    Source IP: {src_ip}")
            if dst_ip:
                lines.append(f"    Dest IP: {dst_ip}")
            if user:
                lines.append(f"    User: {user}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Wazuh Indexer Alert Query - Phase 3")
    parser.add_argument("--min-level", type=int, help="Minimum alert level (1-15)")
    parser.add_argument("--rule-id", type=str, help="Filter by rule ID")
    parser.add_argument("--agent", type=str, help="Filter by agent name")
    parser.add_argument("--mitre", type=str, help="Filter by MITRE technique ID (e.g. T1078)")
    parser.add_argument("--search", type=str, help="Free text search")
    parser.add_argument("--hours", type=int, default=24, help="Hours to look back (default: 24)")
    parser.add_argument("--limit", type=int, default=20, help="Max results (default: 20)")
    parser.add_argument("--verbose", action="store_true", help="Show full alert details")
    parser.add_argument("--export", type=str, help="Export results to JSON file")
    parser.add_argument("--raw", action="store_true", help="Print raw JSON")
    args = parser.parse_args()

    indexer = WazuhIndexer(INDEXER_URL, INDEXER_USER, INDEXER_PASS)

    # ----- Health Check -----
    print_section("Indexer Health Check")
    health = indexer.health_check()
    if health:
        status = health.get("status", "unknown")
        icon = "[OK]" if status == "green" else ("[!!]" if status == "red" else "[~~]")
        print(f"  {icon} Cluster: {health.get('cluster_name', '?')}")
        print(f"  {icon} Status:  {status}")
        print(f"      Nodes: {health.get('number_of_nodes', '?')}")
        print(f"      Shards: {health.get('active_shards', '?')} active")
    else:
        print("  [ERROR] Cannot connect to indexer!")
        sys.exit(1)

    # ----- Index Info -----
    print_section("Wazuh Indices")
    indices = indexer.list_indices()
    if indices:
        print(f"  {'Index':<50} {'Docs':<12} {'Size'}")
        print(f"  {'-'*50} {'-'*12} {'-'*10}")
        for idx in indices:
            print(
                f"  {idx.get('index', '?'):<50} "
                f"{idx.get('docs.count', '?'):<12} "
                f"{idx.get('store.size', '?')}"
            )
    else:
        print("  No Wazuh indices found!")

    # ----- Alert Count -----
    total = indexer.count_alerts()
    print(f"\n  Total alerts in index: {total}")

    # ----- Alert Summary -----
    print_section("Alert Summary (Last {} Hours)".format(args.hours))
    summary = indexer.get_alert_summary(hours_back=args.hours)

    if summary:
        # By Level
        print("\n  --- By Severity Level ---")
        by_level = summary.get("by_level", {}).get("buckets", [])
        for bucket in by_level:
            level = bucket["key"]
            count = bucket["doc_count"]
            bar = "#" * min(count, 40)
            severity = "CRITICAL" if level >= 12 else "HIGH" if level >= 10 else "MEDIUM" if level >= 7 else "LOW"
            print(f"  Level {level:>2} ({severity:<8}): {count:>5}  {bar}")

        # By MITRE Tactic
        print("\n  --- By MITRE ATT&CK Tactic ---")
        by_tactic = summary.get("by_mitre_tactic", {}).get("buckets", [])
        if by_tactic:
            for bucket in by_tactic:
                print(f"  {bucket['key']:<35} {bucket['doc_count']:>5}")
        else:
            print("  No MITRE-tagged alerts yet")

        # By MITRE Technique
        print("\n  --- By MITRE ATT&CK Technique ---")
        by_technique = summary.get("by_mitre_technique", {}).get("buckets", [])
        if by_technique:
            for bucket in by_technique:
                print(f"  {bucket['key']:<15} {bucket['doc_count']:>5}")
        else:
            print("  No MITRE techniques tagged yet")

        # Top Alert Types
        print("\n  --- Top Alert Types ---")
        by_desc = summary.get("by_description", {}).get("buckets", [])
        for bucket in by_desc[:15]:
            desc = bucket["key"][:65]
            count = bucket["doc_count"]
            print(f"  {count:>5}  {desc}")

    # ----- Detailed Alerts -----
    print_section("Alert Details (Last {} Hours)".format(args.hours))
    alerts = indexer.search_alerts(
        limit=args.limit,
        min_level=args.min_level,
        rule_id=args.rule_id,
        agent_name=args.agent,
        mitre_id=args.mitre,
        search_text=args.search,
        hours_back=args.hours,
    )

    if args.raw:
        print(json.dumps(alerts, indent=2, default=str))
    elif alerts:
        print(f"  Showing {len(alerts)} of {total} total alerts\n")
        for alert in alerts:
            print(format_alert(alert, verbose=args.verbose))
            print()
    else:
        print("  No alerts match your filters")

    # ----- Export -----
    if args.export and alerts:
        with open(args.export, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, default=str)
        print(f"\n  [OK] Exported {len(alerts)} alerts to {args.export}")

    # ----- NormalizedAlert Preview -----
    if alerts:
        print_section("NormalizedAlert Schema Preview (Phase 4)")
        sample = alerts[0]
        rule = sample.get("rule", {})
        agent = sample.get("agent", {})
        data = sample.get("data", {})
        mitre = rule.get("mitre", {})
        win_data = data.get("win", {}).get("eventdata", {})

        normalized = {
            "id": sample.get("id", "auto-generated"),
            "source": "wazuh",
            "vendor": "Wazuh SIEM",
            "timestamp": sample.get("timestamp"),
            "severity_hint": rule.get("level", 0),
            "raw_content": json.dumps(data)[:200] + "..." if data else "",
            "rule_id": rule.get("id"),
            "rule_description": rule.get("description"),
            "src_ip": data.get("srcip") or win_data.get("ipAddress"),
            "dst_ip": data.get("dstip"),
            "username": win_data.get("targetUserName") or data.get("srcuser"),
            "hostname": agent.get("name"),
            "mitre_tactics": mitre.get("tactic", []),
            "mitre_techniques": mitre.get("id", []),
            "investigation_status": "new",
        }

        print("  This is how alerts will look after Phase 4 normalization:\n")
        print(json.dumps(normalized, indent=4, default=str))

    print()


if __name__ == "__main__":
    main()
