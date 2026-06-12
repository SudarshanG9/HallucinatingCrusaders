"""Quick smoke test for all mock connectors."""
import asyncio
from datetime import datetime, timezone, timedelta
from soc_analyst.collector.connectors.mock_guardduty import MockGuardDutyConnector
from soc_analyst.collector.connectors.mock_okta import MockOktaConnector
from soc_analyst.collector.connectors.mock_defender import MockDefenderConnector


async def test():
    since = datetime.now(timezone.utc) - timedelta(hours=1)

    g = MockGuardDutyConnector()
    o = MockOktaConnector()
    d = MockDefenderConnector()

    await g.connect()
    await o.connect()
    await d.connect()

    ga = await g.fetch_alerts(since)
    oa = await o.fetch_alerts(since)
    da = await d.fetch_alerts(since)

    print(f"GuardDuty: {len(ga)} alerts")
    print(f"  Sample: sev={ga[0].severity}, rule={ga[0].rule_id}, src={ga[0].src_ip}")

    print(f"Okta: {len(oa)} alerts")
    print(f"  Sample: sev={oa[0].severity}, user={oa[0].username}, rule={oa[0].rule_id}")

    print(f"Defender: {len(da)} alerts")
    print(f"  Sample: sev={da[0].severity}, host={da[0].hostname}, rule={da[0].rule_id}")

    # Test health checks
    for name, conn in [("guardduty", g), ("okta", o), ("defender", d)]:
        h = await conn.health_check()
        print(f"  {name} health: {h['status']}")

    print("All mock connectors OK")


asyncio.run(test())
