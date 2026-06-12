"""Investigation tools for the SOC Analyst pipeline."""

from soc_analyst.agents.tools.threat_intel import check_virustotal, check_abuseipdb, check_otx
from soc_analyst.agents.tools.network_intel import dns_lookup, whois_lookup, geoip_lookup
from soc_analyst.agents.tools.endpoint_intel import get_agent_processes, get_file_integrity_events, get_user_activity
from soc_analyst.agents.tools.cross_vendor_intel import search_okta_user, search_guardduty_ip, search_defender_host, search_all_vendors_for_ip
from soc_analyst.agents.tools.memory_tools import search_past_incidents, get_ip_history, get_user_history

__all__ = [
    "check_virustotal",
    "check_abuseipdb",
    "check_otx",
    "dns_lookup",
    "whois_lookup",
    "geoip_lookup",
    "get_agent_processes",
    "get_file_integrity_events",
    "get_user_activity",
    "search_okta_user",
    "search_guardduty_ip",
    "search_defender_host",
    "search_all_vendors_for_ip",
    "search_past_incidents",
    "get_ip_history",
    "get_user_history",
]

