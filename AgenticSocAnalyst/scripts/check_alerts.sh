#!/bin/bash
echo "=== Recent Wazuh Alerts (last 200 lines) ==="
echo ""
echo "--- Alert Count by Rule Description ---"
tail -200 /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -oP '"description":"[^"]+"' | sort | uniq -c | sort -rn | head -25
echo ""
echo "--- Alert Count by Level ---"
tail -200 /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -oP '"level":[0-9]+' | sort | uniq -c | sort -rn
echo ""
echo "--- Total Alert Lines ---"
wc -l /var/ossec/logs/alerts/alerts.json 2>/dev/null
echo ""
echo "--- Sample Alert (last one) ---"
tail -1 /var/ossec/logs/alerts/alerts.json 2>/dev/null | python3 -m json.tool 2>/dev/null | head -40
