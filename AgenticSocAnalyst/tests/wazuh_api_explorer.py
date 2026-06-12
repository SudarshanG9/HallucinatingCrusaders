"""
Phase 3 — Wazuh REST API Explorer
==================================
Connects to the Wazuh Manager REST API, authenticates via JWT,
and queries alerts by severity, rule ID, and time range.

Usage:
    python tests/wazuh_api_explorer.py
    python tests/wazuh_api_explorer.py --min-level 10
    python tests/wazuh_api_explorer.py --rule-id 60122
    python tests/wazuh_api_explorer.py --limit 50 --summary

Wazuh API Docs: https://documentation.wazuh.com/4.7/user-manual/api/reference.html
"""

import argparse
import json
import sys
import urllib3
from datetime import datetime, timedelta

import requests

# Suppress SSL warnings (self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WAZUH_API_URL = "https://127.0.0.1:56000"
API_USER = "wazuh-wui"
API_PASS = "MyS3cr37P450r.*-"


class WazuhAPI:
    """Wazuh REST API client with JWT authentication."""

    def __init__(self, base_url: str, user: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.token = None
        self.session = requests.Session()
        self.session.verify = False  # Self-signed certs

    def authenticate(self) -> str:
        """Get JWT token from Wazuh API."""
        print("[*] Authenticating to Wazuh API...")
        resp = self.session.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.user, self.password),
        )
        if resp.status_code != 200:
            print(f"[ERROR] Authentication failed: {resp.status_code}")
            print(f"        Response: {resp.text[:200]}")
            sys.exit(1)

        data = resp.json()
        self.token = data.get("data", {}).get("token")
        if not self.token:
            print(f"[ERROR] No token in response: {json.dumps(data, indent=2)[:300]}")
            sys.exit(1)

        self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        print("[OK] Authenticated successfully")
        return self.token

    def _get(self, endpoint: str, params: dict = None) -> dict:
        """Make authenticated GET request."""
        if not self.token:
            self.authenticate()

        resp = self.session.get(f"{self.base_url}{endpoint}", params=params)
        if resp.status_code == 401:
            # Token expired, re-authenticate
            self.authenticate()
            resp = self.session.get(f"{self.base_url}{endpoint}", params=params)

        if resp.status_code != 200:
            print(f"[ERROR] API call failed: {resp.status_code} {endpoint}")
            print(f"        {resp.text[:300]}")
            return {}

        return resp.json()

    # ----- Agent Methods -----

    def get_agents(self) -> list:
        """List all registered agents."""
        data = self._get("/agents", params={"limit": 500})
        return data.get("data", {}).get("affected_items", [])

    def get_agent_summary(self) -> dict:
        """Get agent connection status summary."""
        data = self._get("/agents/summary/status")
        return data.get("data", {})

    # ----- Alert Methods -----

    def get_alerts(
        self,
        limit: int = 20,
        offset: int = 0,
        min_level: int = None,
        max_level: int = None,
        rule_id: str = None,
        agent_id: str = None,
        sort: str = "-timestamp",
    ) -> list:
        """Query alerts with filters."""
        # Wazuh 4.7 uses the /alerts endpoint via the manager's log
        # But the primary alert query method is through the Indexer (OpenSearch)
        # For the REST API, we use /manager/logs for system logs
        # and /agents/{id}/config for agent config
        #
        # Alert querying is best done through the Indexer (Phase 3b)
        # Here we query the manager's internal log-based alerts
        params = {"limit": limit, "offset": offset, "sort": sort}
        if min_level:
            params["min_level"] = min_level
        if max_level:
            params["max_level"] = max_level

        data = self._get("/manager/logs", params=params)
        return data.get("data", {}).get("affected_items", [])

    # ----- Rule Methods -----

    def get_rules(self, limit: int = 20, level: str = None, search: str = None) -> list:
        """Query Wazuh rules."""
        params = {"limit": limit}
        if level:
            params["level"] = level
        if search:
            params["search"] = search
        data = self._get("/rules", params=params)
        return data.get("data", {}).get("affected_items", [])

    # ----- System Info -----

    def get_manager_info(self) -> dict:
        """Get Wazuh manager version and status."""
        data = self._get("/manager/info")
        return data.get("data", {}).get("affected_items", [{}])[0] if data else {}

    def get_manager_status(self) -> dict:
        """Get status of all Wazuh manager daemons."""
        data = self._get("/manager/status")
        return data.get("data", {}).get("affected_items", [{}])[0] if data else {}

    def get_stats(self) -> dict:
        """Get alert statistics for today."""
        data = self._get("/manager/stats")
        return data.get("data", {}).get("affected_items", [])

    def get_stats_hourly(self) -> dict:
        """Get hourly alert stats."""
        data = self._get("/manager/stats/hourly")
        return data.get("data", {}).get("affected_items", [])


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(description="Wazuh REST API Explorer - Phase 3")
    parser.add_argument("--min-level", type=int, help="Minimum alert level (1-15)")
    parser.add_argument("--rule-id", type=str, help="Filter by rule ID")
    parser.add_argument("--limit", type=int, default=20, help="Max results (default: 20)")
    parser.add_argument("--summary", action="store_true", help="Show summary only")
    parser.add_argument("--agents", action="store_true", help="Show agent details")
    parser.add_argument("--rules", action="store_true", help="Show available rules")
    parser.add_argument("--stats", action="store_true", help="Show alert statistics")
    args = parser.parse_args()

    api = WazuhAPI(WAZUH_API_URL, API_USER, API_PASS)
    api.authenticate()

    # ----- Manager Info -----
    print_section("Wazuh Manager Info")
    info = api.get_manager_info()
    if info:
        print(f"  Version:  {info.get('version', 'N/A')}")
        print(f"  Type:     {info.get('type', 'N/A')}")
        print(f"  Max agents: {info.get('max_agents', 'N/A')}")

    # ----- Manager Daemon Status -----
    print_section("Manager Daemon Status")
    status = api.get_manager_status()
    if status:
        for daemon, state in sorted(status.items()):
            icon = "[OK]" if state == "running" else "[--]"
            print(f"  {icon} {daemon}: {state}")

    # ----- Agents -----
    print_section("Registered Agents")
    agents = api.get_agents()
    print(f"  Total agents: {len(agents)}")
    print(f"  {'ID':<6} {'Name':<20} {'IP':<16} {'Status':<12} {'OS'}")
    print(f"  {'-'*6} {'-'*20} {'-'*16} {'-'*12} {'-'*25}")
    for agent in agents:
        os_name = agent.get("os", {}).get("name", "N/A") if isinstance(agent.get("os"), dict) else "N/A"
        os_ver = agent.get("os", {}).get("version", "") if isinstance(agent.get("os"), dict) else ""
        print(
            f"  {agent.get('id', '?'):<6} "
            f"{agent.get('name', '?'):<20} "
            f"{agent.get('ip', '?'):<16} "
            f"{agent.get('status', '?'):<12} "
            f"{os_name} {os_ver}"
        )

    # ----- Agent Summary -----
    summary = api.get_agent_summary()
    if summary:
        print(f"\n  Connection Summary:")
        for status_type, count in summary.items():
            print(f"    {status_type}: {count}")

    # ----- Alert Statistics -----
    if args.stats or not (args.agents or args.rules):
        print_section("Alert Statistics (Today)")
        stats = api.get_stats()
        if stats:
            total_alerts = sum(s.get("totalAlerts", 0) for s in stats)
            print(f"  Total alerts today: {total_alerts}")
            # Show hourly breakdown
            for stat in stats[-6:]:  # Last 6 hours
                hour = stat.get("hour", "?")
                count = stat.get("totalAlerts", 0)
                bar = "#" * min(count, 50)
                print(f"  Hour {hour:>2}: {count:>5} {bar}")
        else:
            print("  No stats available yet (alerts may not be indexed)")

    # ----- Rules -----
    if args.rules:
        print_section("High-Severity Rules (Level 10+)")
        rules = api.get_rules(limit=30, level="10-15")
        for rule in rules:
            mitre = rule.get("mitre", {})
            tactics = ", ".join(mitre.get("tactic", [])) if mitre else ""
            print(
                f"  [{rule.get('level', '?'):>2}] "
                f"Rule {rule.get('id', '?'):<8} "
                f"{rule.get('description', '?')[:60]}"
            )
            if tactics:
                print(f"       MITRE: {tactics}")

    # ----- Manager Logs (proxy for alerts) -----
    if not args.summary:
        print_section("Recent Manager Logs")
        params = {"limit": args.limit, "sort": "-timestamp"}
        if args.min_level:
            params["level"] = "ERROR"

        logs = api.get_alerts(limit=args.limit)
        if logs:
            for log in logs[:args.limit]:
                ts = log.get("timestamp", "?")
                tag = log.get("tag", "?")
                level = log.get("level", "?")
                desc = log.get("description", "?")[:80]
                print(f"  [{ts}] [{level}] {tag}: {desc}")
        else:
            print("  No logs found (try the Indexer query for alert data)")

    # ----- Summary -----
    print_section("Quick Reference")
    print(f"  API URL:       {WAZUH_API_URL}")
    print(f"  Dashboard:     https://localhost:443")
    print(f"  Indexer:       https://localhost:9200")
    print(f"  Agent count:   {len(agents)}")
    print(f"  Active agents: {summary.get('active', 0)}")
    print(f"\n  Next: Run tests/indexer_query.py for full alert data via OpenSearch")
    print()


if __name__ == "__main__":
    main()
