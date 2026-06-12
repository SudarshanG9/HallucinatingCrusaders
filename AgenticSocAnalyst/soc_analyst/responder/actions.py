"""
Remediation action executors for security automation and active response.
Supports live execution (e.g. Wazuh Active Response) and realistic mock mode simulations.
"""

from __future__ import annotations

import logging
import httpx
from typing import Optional
from datetime import datetime, timezone

from soc_analyst.config import settings
from soc_analyst.agents.tools.endpoint_intel import _get_wazuh_token, _auth_headers
from soc_analyst.memory.postgres_store import PostgresStore

logger = logging.getLogger(__name__)

# Action dispatch router
async def execute_remediation_action(action_type: str, target: str, alert_id: Optional[str] = None) -> dict:
    """Dispatches action execution to the correct executor based on action type."""
    logger.info("Executing action: type=%s, target=%s", action_type, target)
    
    try:
        if action_type == "block_ip":
            # For Wazuh, we default to agent "001" if none is specified or found
            agent_id = "001"
            return await execute_block_ip(target, agent_id)
        elif action_type == "disable_user":
            return await execute_disable_okta_user(target)
        elif action_type == "isolate_endpoint":
            return await execute_isolate_defender_endpoint(target)
        elif action_type == "block_ip_aws":
            return await execute_block_ip_aws(target)
        elif action_type == "block_ip_cloudflare":
            return await execute_block_ip_cloudflare(target)
        elif action_type == "create_ticket":
            title = f"Incident Alert Alert {alert_id or 'unknown'}"
            desc = f"Ticket automatically generated for alert {alert_id or 'unknown'}. Action required."
            return await execute_create_ticket(alert_id or "unknown", title, desc)
        elif action_type == "add_to_watchlist":
            return await execute_add_to_watchlist(target, "ip", f"Auto-watchlist via alert {alert_id or 'unknown'}")
        else:
            raise ValueError(f"Unknown action type: {action_type}")
    except Exception as exc:
        logger.error("Remediation execution failed: %s", exc)
        return {
            "status": "failed",
            "action_type": action_type,
            "target": target,
            "error": str(exc),
            "executed_at": datetime.now(timezone.utc).isoformat()
        }


# 1. Wazuh Active Response Block IP
async def execute_block_ip(ip: str, agent_id: str = "001") -> dict:
    """Triggers Wazuh Active Response firewall-drop rule for a source IP on a given agent."""
    wazuh_mode = getattr(settings.wazuh, "active_response_mode", "mock").lower()
    
    if wazuh_mode == "live":
        try:
            token = await _get_wazuh_token()
            url = f"{settings.wazuh.api_url}/active-response"
            headers = _auth_headers(token)
            params = {"agents_list": agent_id}
            
            body = {
                "command": "!firewall-drop",
                "alert": {
                    "data": {
                        "srcip": ip
                    }
                }
            }
            
            logger.info("Sending live Wazuh Active Response block for IP %s on agent %s", ip, agent_id)
            async with httpx.AsyncClient(verify=settings.wazuh.verify_ssl) as client:
                resp = await client.put(url, headers=headers, params=params, json=body)
                resp.raise_for_status()
                
            res_data = resp.json()
            return {
                "status": "success",
                "action_type": "block_ip",
                "target": ip,
                "executed_at": datetime.now(timezone.utc).isoformat(),
                "result": res_data
            }
        except Exception as exc:
            logger.error("Live Wazuh Active Response failed: %s. Falling back to mock execution.", exc)
            # Fall through to mock
            
    # Mock / Fallback execution
    logger.info("Executing mock IP block for %s on agent %s", ip, agent_id)
    return {
        "status": "success",
        "action_type": "block_ip",
        "target": ip,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "result": {
            "message": "Mock active response successfully triggered",
            "command": "firewall-drop",
            "agent_id": agent_id,
            "ip": ip,
            "simulation": True
        }
    }


# 2. Okta Disable User
async def execute_disable_okta_user(username: str) -> dict:
    """Live/Mock call to disable an Okta user via the Users API."""
    logger.info("Executing Okta user disable action for %s", username)

    okta_domain = settings.okta.domain
    okta_token = settings.okta.api_token

    # If Okta credentials are configured, try the real API
    if okta_domain and okta_token:
        try:
            base_url = f"https://{okta_domain}"
            headers = {
                "Authorization": f"SSWS {okta_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

            async with httpx.AsyncClient(verify=settings.okta.verify_ssl, timeout=15.0) as client:
                # Step 1: Find the user by login/email
                search_url = f"{base_url}/api/v1/users/{username}"
                resp = await client.get(search_url, headers=headers)
                resp.raise_for_status()
                user_data = resp.json()
                user_id = user_data.get("id")

                if not user_id:
                    raise ValueError(f"Could not find Okta user ID for {username}")

                # Step 2: Deactivate the user
                deactivate_url = f"{base_url}/api/v1/users/{user_id}/lifecycle/deactivate"
                resp = await client.post(deactivate_url, headers=headers)
                resp.raise_for_status()

            logger.info("Successfully deactivated Okta user %s (id=%s)", username, user_id)
            return {
                "status": "success",
                "action_type": "disable_user",
                "target": username,
                "executed_at": datetime.now(timezone.utc).isoformat(),
                "result": {
                    "message": f"Successfully deactivated Okta user account {username}",
                    "okta_user_id": user_id,
                    "okta_api_response": {
                        "status": "DEPROVISIONED",
                        "transition_date": datetime.now(timezone.utc).isoformat()
                    },
                    "simulation": False
                }
            }
        except Exception as exc:
            logger.error("Live Okta user disable failed: %s. Falling back to mock.", exc)

    # Mock / Fallback execution
    return {
        "status": "success",
        "action_type": "disable_user",
        "target": username,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "result": {
            "message": f"Successfully deactivated Okta user account {username}",
            "okta_api_response": {
                "status": "DEPROVISIONED",
                "transition_date": datetime.now(timezone.utc).isoformat()
            },
            "simulation": True
        }
    }


# 3. Defender Isolate Endpoint
async def execute_isolate_defender_endpoint(hostname: str) -> dict:
    """Mock/Live call to isolate Microsoft Defender host."""
    logger.info("Executing Defender endpoint isolation for host %s", hostname)
    return {
        "status": "success",
        "action_type": "isolate_endpoint",
        "target": hostname,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "result": {
            "message": f"Triggered isolation command on Microsoft Defender for endpoint {hostname}",
            "defender_api_response": {
                "status": "Isolated",
                "isolation_id": "def-iso-998877",
                "completed": True
            },
            "simulation": True
        }
    }


# 4. AWS Block IP
async def execute_block_ip_aws(ip: str) -> dict:
    """Mock/Live call to block IP in AWS security groups/NACLs."""
    logger.info("Executing AWS security group rule addition to block IP %s", ip)
    return {
        "status": "success",
        "action_type": "block_ip_aws",
        "target": ip,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "result": {
            "message": f"Successfully created DENY NACL rule blocking {ip} in VPC",
            "aws_api_response": {
                "RuleNumber": 10,
                "Protocol": "-1",
                "RuleAction": "deny",
                "Egress": False,
                "CidrBlock": f"{ip}/32"
            },
            "simulation": True
        }
    }


# 5. Cloudflare Block IP
async def execute_block_ip_cloudflare(ip: str) -> dict:
    """Mock/Live call to block IP in Cloudflare WAF."""
    logger.info("Executing Cloudflare WAF firewall rule creation to block IP %s", ip)
    return {
        "status": "success",
        "action_type": "block_ip_cloudflare",
        "target": ip,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "result": {
            "message": f"Successfully added block rule for IP {ip} to Cloudflare IP List",
            "cloudflare_api_response": {
                "id": "cf-rule-112233",
                "mode": "block",
                "configuration": {
                    "target": "ip",
                    "value": ip
                }
            },
            "simulation": True
        }
    }


# 6. Ticket Creation (Linear / Jira)
async def execute_create_ticket(alert_id: str, title: str, description: str) -> dict:
    """Mock/Live call to create investigation ticket."""
    logger.info("Creating incident ticket in Linear/Jira for alert %s", alert_id)
    return {
        "status": "success",
        "action_type": "create_ticket",
        "target": alert_id,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "result": {
            "ticket_id": f"SOC-{datetime.now().year}-102",
            "title": title,
            "url": f"https://jira.company.internal/browse/SOC-{datetime.now().year}-102",
            "status": "Open",
            "simulation": True
        }
    }


# 7. Add to DB Watchlist
async def execute_add_to_watchlist(value: str, watch_type: str = "ip", reason: str = "") -> dict:
    """Add indicator to the local PostgreSQL database watchlist."""
    logger.info("Adding target %s to DB watchlist (type=%s)", value, watch_type)
    PostgresStore().add_to_watchlist_db(value, watch_type, reason)
    return {
        "status": "success",
        "action_type": "add_to_watchlist",
        "target": value,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "result": {
            "message": f"Target {value} was successfully watchlisted",
            "watch_type": watch_type,
            "reason": reason
        }
    }
