"""
PostgreSQL Storage and Query engine for SOC Analyst incident memory.
"""

import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import psycopg2
from psycopg2.extras import Json, RealDictCursor
from psycopg2.pool import ThreadedConnectionPool

from soc_analyst.collector.models import NormalizedAlert, SeverityLevel, InvestigationStatus
from soc_analyst.config import settings

logger = logging.getLogger(__name__)

class PostgresStore:
    """Thread-safe PostgreSQL client using a connection pool.

    Automatically runs partitioning migration for the `alerts` table on startup.
    """

    _instance: Optional["PostgresStore"] = None

    def __new__(cls, *args, **kwargs) -> "PostgresStore":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, dsn: Optional[str] = None) -> None:
        if self._initialized:
            return

        self.dsn = dsn or settings.postgres.dsn
        logger.info("Initializing PostgresStore connection pool...")
        
        try:
            self.pool = ThreadedConnectionPool(
                minconn=2,
                maxconn=15,
                dsn=self.dsn
            )
            self._initialized = True
            logger.info("PostgresStore connection pool created successfully.")
            
            # Run migration on startup
            self.migrate_and_partition()
        except Exception as exc:
            logger.exception("Failed to initialize PostgreSQL connection pool")
            raise RuntimeError(f"Database connection error: {exc}") from exc

    @contextmanager
    def get_conn(self):
        """Context manager to lease a connection from the pool, committing or rolling back on exit."""
        conn = self.pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.putconn(conn)

    def close(self) -> None:
        """Close all connections in the pool."""
        if hasattr(self, "pool") and self.pool:
            self.pool.closeall()
            logger.info("Closed all database connections in PostgresStore pool.")

    def migrate_and_partition(self) -> None:
        """Perform schema migration to partition the alerts table by monthly ranges."""
        logger.info("Checking database schema and partitioning status...")
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                # Ensure watchlist table exists
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS watchlist (
                        id SERIAL PRIMARY KEY,
                        value VARCHAR(256) UNIQUE NOT NULL,
                        watch_type VARCHAR(32) NOT NULL,
                        reason TEXT,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    );
                """)
                
                # Check if alerts table exists
                cur.execute("SELECT EXISTS (SELECT FROM pg_tables WHERE tablename = 'alerts')")
                exists = cur.fetchone()[0]
                if not exists:
                    logger.warning("alerts table does not exist. Please initialize schema first.")
                    return

                # Ensure source and analyst columns exist on the alerts table (either regular or partitioned)
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source VARCHAR(64) DEFAULT 'wazuh' NOT NULL;")
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS analyst_verdict VARCHAR(64);")
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS analyst_reasoning TEXT;")
                cur.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tags TEXT[];")
                
                # Ensure column widths are large enough for other providers (GuardDuty, Defender, etc.)
                cur.execute("DROP VIEW IF EXISTS v_active_alerts CASCADE;")
                cur.execute("DROP VIEW IF EXISTS v_open_investigations CASCADE;")
                cur.execute("DROP VIEW IF EXISTS v_pending_approvals CASCADE;")
                
                cur.execute("ALTER TABLE alerts ALTER COLUMN rule_id TYPE VARCHAR(128);")
                cur.execute("ALTER TABLE alerts ALTER COLUMN agent_id TYPE VARCHAR(128);")
                cur.execute("ALTER TABLE alerts ALTER COLUMN protocol TYPE VARCHAR(64);")

                cur.execute("""
                    CREATE OR REPLACE VIEW v_active_alerts AS
                    SELECT
                        id, timestamp, rule_id, rule_description, rule_level,
                        agent_name, agent_ip, src_ip, username, investigation_status
                    FROM alerts
                    WHERE investigation_status IN ('new', 'triaged')
                    ORDER BY rule_level DESC, timestamp DESC;
                """)
                cur.execute("""
                    CREATE OR REPLACE VIEW v_open_investigations AS
                    SELECT
                        i.id, i.started_at, i.classification, i.severity, i.status,
                        a.rule_description AS trigger_rule,
                        a.agent_name, a.src_ip,
                        ARRAY_LENGTH(i.related_alert_ids, 1) AS related_count
                    FROM investigations i
                    JOIN alerts a ON a.id = i.trigger_alert_id
                    WHERE i.status NOT IN ('closed')
                    ORDER BY i.started_at DESC;
                """)
                cur.execute("""
                    CREATE OR REPLACE VIEW v_pending_approvals AS
                    SELECT
                        r.id, r.action_type, r.target, r.reason,
                        r.created_at, i.severity,
                        a.rule_description
                    FROM response_actions r
                    JOIN investigations i ON i.id = r.investigation_id
                    JOIN alerts a ON a.id = r.alert_id
                    WHERE r.approval_status = 'pending'
                    ORDER BY i.severity DESC, r.created_at ASC;
                """)

                # Check if alerts is already partitioned (relkind = 'p' in pg_class)
                cur.execute("SELECT relkind FROM pg_class WHERE relname = 'alerts'")
                row = cur.fetchone()
                if row and row[0] == 'p':
                    logger.info("alerts table is already partitioned. Creating missing/future partitions...")
                    self._create_standard_partitions(cur)
                    return

                logger.warning("alerts table is a regular table. Initiating migration to partitioned table...")
                
                # 1. Drop foreign key constraints referencing alerts(id)
                # Since alerts will be partitioned on (id, timestamp), other tables can't reference alerts(id) directly
                cur.execute("""
                    ALTER TABLE investigations DROP CONSTRAINT IF EXISTS investigations_trigger_alert_id_fkey;
                    ALTER TABLE response_actions DROP CONSTRAINT IF EXISTS response_actions_alert_id_fkey;
                    ALTER TABLE analyst_notes DROP CONSTRAINT IF EXISTS analyst_notes_alert_id_fkey;
                """)
                logger.info("Dropped foreign key constraints referencing alerts(id)")

                # 2. Rename the old alerts table
                cur.execute("ALTER TABLE alerts RENAME TO alerts_old;")

                # 3. Create the new partitioned table (partitioned by timestamp)
                cur.execute("""
                    CREATE TABLE alerts (
                        id                      VARCHAR(64),
                        wazuh_id                VARCHAR(128),
                        timestamp               TIMESTAMPTZ NOT NULL,
                        source                  VARCHAR(64) DEFAULT 'wazuh' NOT NULL,
                        rule_id                 VARCHAR(128) NOT NULL,
                        rule_description        TEXT NOT NULL,
                        rule_level              SMALLINT NOT NULL,
                        rule_groups             TEXT[],
                        mitre_ids               TEXT[],
                        agent_id                VARCHAR(128),
                        agent_name              VARCHAR(128),
                        agent_ip                VARCHAR(45),
                        src_ip                  VARCHAR(45),
                        dst_ip                  VARCHAR(45),
                        src_port                INTEGER,
                        dst_port                INTEGER,
                        protocol                VARCHAR(64),
                        username                VARCHAR(128),
                        raw_data                JSONB NOT NULL,
                        location                TEXT,
                        investigation_status    VARCHAR(32) DEFAULT 'new'
                                                CHECK (investigation_status IN ('new','triaged','investigating','closed','false_positive','enriched','awaiting_verdict','resolved','escalated')),
                        investigation_id        UUID,
                        analyst_verdict         VARCHAR(64),
                        analyst_reasoning       TEXT,
                        tags                    TEXT[],
                        created_at              TIMESTAMPTZ DEFAULT NOW(),
                        updated_at              TIMESTAMPTZ DEFAULT NOW(),
                        PRIMARY KEY (id, timestamp)
                    ) PARTITION BY RANGE (timestamp);
                """)
                logger.info("Created new range-partitioned alerts table.")

                # 4. Bind the triggers for updated_at
                cur.execute("""
                    CREATE TRIGGER alerts_updated_at
                        BEFORE UPDATE ON alerts
                        FOR EACH ROW EXECUTE FUNCTION update_updated_at();
                """)

                # 5. Create default partitions (previous, current, and future months)
                self._create_standard_partitions(cur)

                # Check if there is data in alerts_old to pull in
                cur.execute("SELECT COUNT(*) FROM alerts_old")
                old_count = cur.fetchone()[0]
                if old_count > 0:
                    logger.info("Migrating %d records from alerts_old to partitioned alerts table...", old_count)
                    
                    # Create partitions dynamically for all timestamps present in alerts_old
                    cur.execute("SELECT MIN(timestamp), MAX(timestamp) FROM alerts_old")
                    min_ts, max_ts = cur.fetchone()
                    if min_ts and max_ts:
                        curr = min_ts
                        while curr <= max_ts:
                            self._create_partition_for_date(cur, curr)
                            # Increment by ~28 days to shift to next month safely
                            curr += timedelta(days=28)

                    # Copy data
                    cur.execute("""
                        INSERT INTO alerts (
                            id, wazuh_id, timestamp, source, rule_id, rule_description, rule_level,
                            rule_groups, mitre_ids, agent_id, agent_name, agent_ip, src_ip,
                            dst_ip, src_port, dst_port, protocol, username, raw_data, location,
                            investigation_status, investigation_id, created_at, updated_at
                        )
                        SELECT 
                            id, wazuh_id, timestamp, 'wazuh' AS source, rule_id, rule_description, rule_level,
                            rule_groups, mitre_ids, agent_id, agent_name, agent_ip, src_ip,
                            dst_ip, src_port, dst_port, protocol, username, raw_data, location,
                            investigation_status, investigation_id, created_at, updated_at
                        FROM alerts_old;
                    """)

                # 6. Clean up old table using CASCADE since views depend on it
                cur.execute("DROP TABLE alerts_old CASCADE;")
                logger.info("Dropped alerts_old table via CASCADE.")

                # Recreate dependent views on the new partitioned table
                cur.execute("""
                    CREATE OR REPLACE VIEW v_active_alerts AS
                    SELECT
                        id, timestamp, rule_id, rule_description, rule_level,
                        agent_name, agent_ip, src_ip, username, investigation_status
                    FROM alerts
                    WHERE investigation_status IN ('new', 'triaged')
                    ORDER BY rule_level DESC, timestamp DESC;
                """)
                cur.execute("""
                    CREATE OR REPLACE VIEW v_open_investigations AS
                    SELECT
                        i.id, i.started_at, i.classification, i.severity, i.status,
                        a.rule_description AS trigger_rule,
                        a.agent_name, a.src_ip,
                        ARRAY_LENGTH(i.related_alert_ids, 1) AS related_count
                    FROM investigations i
                    JOIN alerts a ON a.id = i.trigger_alert_id
                    WHERE i.status NOT IN ('closed')
                    ORDER BY i.started_at DESC;
                """)
                cur.execute("""
                    CREATE OR REPLACE VIEW v_pending_approvals AS
                    SELECT
                        r.id, r.action_type, r.target, r.reason,
                        r.created_at, i.severity,
                        a.rule_description
                    FROM response_actions r
                    JOIN investigations i ON i.id = r.investigation_id
                    JOIN alerts a ON a.id = r.alert_id
                    WHERE r.approval_status = 'pending'
                    ORDER BY i.severity DESC, r.created_at ASC;
                """)
                logger.info("Re-created database views v_active_alerts, v_open_investigations, and v_pending_approvals.")

                # 7. Re-create indexes
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp        ON alerts (timestamp DESC);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule_level       ON alerts (rule_level DESC);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule_id          ON alerts (rule_id);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_agent_name       ON alerts (agent_name);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip           ON alerts (src_ip);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status           ON alerts (investigation_status);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_raw_data         ON alerts USING GIN (raw_data);")
                logger.info("Re-created indexes on partitioned alerts table.")


    def _create_standard_partitions(self, cur) -> None:
        """Create partitions for the previous, current, and next month."""
        now = datetime.now(timezone.utc)
        months = [
            now - timedelta(days=30),  # Previous
            now,                       # Current
            now + timedelta(days=30)   # Next
        ]
        for dt in months:
            self._create_partition_for_date(cur, dt)

    def _create_partition_for_date(self, cur, dt: datetime) -> None:
        """Construct monthly partition dynamically for a given datetime."""
        # Normalize to start of month
        start_date = datetime(dt.year, dt.month, 1, tzinfo=timezone.utc)
        if dt.month == 12:
            end_date = datetime(dt.year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            end_date = datetime(dt.year, dt.month + 1, 1, tzinfo=timezone.utc)

        partition_name = f"alerts_y{dt.year}m{dt.month:02d}"
        
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {partition_name}
            PARTITION OF alerts
            FOR VALUES FROM ('{start_date.isoformat()}') TO ('{end_date.isoformat()}');
        """)

    def _parse_normalized_alert_fields(self, alert: NormalizedAlert) -> dict:
        """Safely parse rule metadata and agent info from alert and raw_content."""
        res = {
            "wazuh_id": None,
            "rule_id": alert.rule_id or "0",
            "rule_level": 3,
            "rule_groups": [],
            "mitre_ids": [],
            "agent_id": None,
            "agent_name": alert.hostname or "unknown",
            "agent_ip": alert.src_ip,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "location": None
        }

        # Parse rule severity level and groups if raw_content contains them
        if alert.raw_content:
            try:
                data = json.loads(alert.raw_content)
                res["wazuh_id"] = data.get("id")
                
                # Rule Details
                rule = data.get("rule", {})
                if rule:
                    res["rule_id"] = str(rule.get("id", res["rule_id"]))
                    res["rule_level"] = int(rule.get("level", 3))
                    res["rule_groups"] = rule.get("groups", [])
                    
                    mitre = rule.get("mitre", {})
                    if mitre:
                        res["mitre_ids"] = mitre.get("id", [])

                # Agent Details
                agent = data.get("agent", {})
                if agent:
                    res["agent_id"] = agent.get("id")
                    res["agent_name"] = agent.get("name", res["agent_name"])
                    res["agent_ip"] = agent.get("ip", res["agent_ip"])

                # Network Details
                net_data = data.get("data", {})
                if isinstance(net_data, dict):
                    win_event = net_data.get("win", {}).get("eventdata", {})
                    if win_event:
                        res["src_port"] = win_event.get("sourcePort") or win_event.get("srcPort")
                        res["dst_port"] = win_event.get("destPort") or win_event.get("destort") or win_event.get("destinationPort")
                        res["protocol"] = win_event.get("protocol")
                    else:
                        res["src_port"] = net_data.get("src_port") or net_data.get("srcport")
                        res["dst_port"] = net_data.get("dst_port") or net_data.get("dstport")
                        res["protocol"] = net_data.get("protocol")

                    if res["src_port"]:
                        res["src_port"] = int(res["src_port"])
                    if res["dst_port"]:
                        res["dst_port"] = int(res["dst_port"])

                res["location"] = data.get("location")
            except Exception:
                pass

        # Fallback mappings using severity
        if res["rule_level"] == 3:
            severity_map = {
                SeverityLevel.INFO: 1,
                SeverityLevel.LOW: 3,
                SeverityLevel.MEDIUM: 7,
                SeverityLevel.HIGH: 10,
                SeverityLevel.CRITICAL: 13
            }
            res["rule_level"] = severity_map.get(alert.severity, 3)

        return res

    # ------------------------------------------------------------------
    # Data Operations
    # ------------------------------------------------------------------

    def save_alert(self, alert: NormalizedAlert) -> None:
        """Insert or update a normalized alert in PostgreSQL database."""
        parsed = self._parse_normalized_alert_fields(alert)
        
        # In Pydantic NormalizedAlert, raw_content is a string JSON
        try:
            raw_json = json.loads(alert.raw_content) if alert.raw_content else {}
        except Exception:
            raw_json = {"raw_content_string": alert.raw_content}

        with self.get_conn() as conn:
            with conn.cursor() as cur:
                # Ensure the partition for this alert's timestamp exists before inserting
                self._create_partition_for_date(cur, alert.timestamp)
                
                cur.execute("""
                    INSERT INTO alerts (
                        id, wazuh_id, timestamp, source, rule_id, rule_description, rule_level,
                        rule_groups, mitre_ids, agent_id, agent_name, agent_ip, src_ip,
                        dst_ip, src_port, dst_port, protocol, username, raw_data, location,
                        investigation_status, analyst_verdict, analyst_reasoning, tags,
                        created_at, updated_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()
                    )
                    ON CONFLICT (id, timestamp) DO UPDATE SET
                        investigation_status = EXCLUDED.investigation_status,
                        analyst_verdict = EXCLUDED.analyst_verdict,
                        analyst_reasoning = EXCLUDED.analyst_reasoning,
                        tags = EXCLUDED.tags,
                        updated_at = NOW();
                """, (
                    alert.id,
                    parsed["wazuh_id"],
                    alert.timestamp,
                    alert.source,
                    parsed["rule_id"],
                    alert.rule_description or "No description",
                    parsed["rule_level"],
                    parsed["rule_groups"],
                    parsed["mitre_ids"] or alert.mitre_techniques,
                    parsed["agent_id"],
                    parsed["agent_name"],
                    parsed["agent_ip"],
                    alert.src_ip,
                    alert.dst_ip,
                    parsed["src_port"],
                    parsed["dst_port"],
                    parsed["protocol"],
                    alert.username,
                    Json(raw_json),
                    parsed["location"],
                    alert.investigation_status.value,
                    alert.analyst_verdict,
                    alert.analyst_reasoning,
                    alert.tags
                ))

    def update_alert(self, alert_id: str, **fields) -> Optional[NormalizedAlert]:
        """Update mutable fields on an alert in Postgres by looking up its partition key first."""
        # Find the alert timestamp first
        ts = None
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT timestamp FROM alerts WHERE id = %s LIMIT 1", (alert_id,))
                row = cur.fetchone()
                if not row:
                    return None
                ts = row[0]

                # Construct dynamic update
                update_cols = []
                params = []
                for k, v in fields.items():
                    # Handle enum fields
                    if hasattr(v, "value"):
                        val = v.value
                    else:
                        val = v
                    update_cols.append(f"{k} = %s")
                    params.append(val)
                
                params.extend([alert_id, ts])
                
                query = f"""
                    UPDATE alerts 
                    SET {", ".join(update_cols)}, updated_at = NOW() 
                    WHERE id = %s AND timestamp = %s;
                """
                cur.execute(query, params)
                
        # Fetch back the updated record (after committing transaction)
        return self.get_alert_by_id(alert_id)

    def get_alert_by_id(self, alert_id: str) -> Optional[NormalizedAlert]:
        """Query a single alert by ID from PostgreSQL."""
        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, source, timestamp, rule_description, src_ip, dst_ip, username, agent_name as hostname,
                           mitre_ids as mitre_techniques, investigation_status, raw_data, rule_id, rule_level,
                           analyst_verdict, analyst_reasoning, tags, created_at, updated_at
                    FROM alerts
                    WHERE id = %s
                    LIMIT 1
                """, (alert_id,))
                row = cur.fetchone()
                if not row:
                    return None
                
                # Reconstruct Pydantic object
                return self._row_to_alert(row)

    def _row_to_alert(self, row: dict) -> NormalizedAlert:
        # Map DB row back to Pydantic NormalizedAlert
        severity_value = 1
        level = row.get("rule_level", 3)
        if level >= 12:
            severity_value = 5
        elif level >= 9:
            severity_value = 4
        elif level >= 5:
            severity_value = 3
        elif level >= 3:
            severity_value = 2

        # Convert raw_data back to string JSON
        raw_data = row.get("raw_data")
        if isinstance(raw_data, dict):
            raw_str = json.dumps(raw_data)
        else:
            raw_str = str(raw_data or "")

        # Find vendor name from source
        source = row.get("source", "wazuh")
        vendor = "Wazuh"
        if "okta" in source:
            vendor = "Okta"
        elif "guardduty" in source:
            vendor = "AWS"
        elif "defender" in source:
            vendor = "Microsoft"

        return NormalizedAlert(
            id=row["id"],
            source=source,
            vendor=vendor,
            timestamp=row["timestamp"],
            received_at=row.get("created_at") or datetime.now(timezone.utc),
            severity=SeverityLevel(severity_value),
            raw_content=raw_str,
            rule_id=row.get("rule_id"),
            rule_description=row.get("rule_description"),
            src_ip=row.get("src_ip"),
            dst_ip=row.get("dst_ip"),
            username=row.get("username"),
            hostname=row.get("hostname"),
            mitre_techniques=row.get("mitre_techniques") or [],
            investigation_status=InvestigationStatus(row.get("investigation_status") or "new"),
            analyst_verdict=row.get("analyst_verdict"),
            analyst_reasoning=row.get("analyst_reasoning"),
            tags=row.get("tags") or []
        )

    def get_alerts(
        self, 
        limit: int = 50, 
        offset: int = 0, 
        source: Optional[str] = None, 
        min_severity: Optional[int] = None, 
        max_severity: Optional[int] = None, 
        status: Optional[str] = None,
        sort_by: str = "timestamp"
    ) -> List[NormalizedAlert]:
        """Fetch filtered and paginated alerts from database."""
        conditions = []
        params = []

        if source:
            conditions.append("source = %s")
            params.append(source)
        if status:
            conditions.append("investigation_status = %s")
            params.append(status)
        if min_severity is not None:
            # Map normalized severity levels to rule levels
            min_rule = 1
            if min_severity == 2: min_rule = 3
            elif min_severity == 3: min_rule = 5
            elif min_severity == 4: min_rule = 9
            elif min_severity == 5: min_rule = 12
            conditions.append("rule_level >= %s")
            params.append(min_rule)
        if max_severity is not None:
            max_rule = 15
            if max_severity == 1: max_rule = 2
            elif max_severity == 2: max_rule = 4
            elif max_severity == 3: max_rule = 8
            elif max_severity == 4: max_rule = 11
            conditions.append("rule_level <= %s")
            params.append(max_rule)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        order_col = "timestamp" if sort_by == "timestamp" else "rule_level"
        
        query = f"""
            SELECT id, source, timestamp, rule_description, src_ip, dst_ip, username, agent_name as hostname,
                   mitre_ids as mitre_techniques, investigation_status, raw_data, rule_id, rule_level,
                   analyst_verdict, analyst_reasoning, tags, created_at, updated_at
            FROM alerts
            {where_clause}
            ORDER BY {order_col} DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])

        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
                return [self._row_to_alert(row) for row in rows]

    def get_alerts_count(
        self, 
        source: Optional[str] = None, 
        min_severity: Optional[int] = None, 
        max_severity: Optional[int] = None, 
        status: Optional[str] = None
    ) -> int:
        """Get total matching alerts count from PostgreSQL."""
        conditions = []
        params = []

        if source:
            conditions.append("source = %s")
            params.append(source)
        if status:
            conditions.append("investigation_status = %s")
            params.append(status)
        if min_severity is not None:
            min_rule = 1
            if min_severity == 2: min_rule = 3
            elif min_severity == 3: min_rule = 5
            elif min_severity == 4: min_rule = 9
            elif min_severity == 5: min_rule = 12
            conditions.append("rule_level >= %s")
            params.append(min_rule)
        if max_severity is not None:
            max_rule = 15
            if max_severity == 1: max_rule = 2
            elif max_severity == 2: max_rule = 4
            elif max_severity == 3: max_rule = 8
            elif max_severity == 4: max_rule = 11
            conditions.append("rule_level <= %s")
            params.append(max_rule)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT COUNT(*) FROM alerts {where_clause}"

        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchone()[0]

    # ------------------------------------------------------------------
    # Correlation & History Queries
    # ------------------------------------------------------------------

    def get_ip_history(self, ip: str, days: int = 30) -> List[dict]:
        """Fetch alert history for a specific IP address within the last N days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, timestamp, source, rule_description, rule_level, investigation_status
                    FROM alerts
                    WHERE (src_ip = %s OR dst_ip = %s) AND timestamp >= %s
                    ORDER BY timestamp DESC
                    LIMIT 100;
                """, (ip, ip, cutoff))
                return cur.fetchall()

    def get_user_history(self, username: str, days: int = 30) -> List[dict]:
        """Fetch alert history for a specific username within the last N days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, timestamp, source, rule_description, rule_level, investigation_status
                    FROM alerts
                    WHERE username = %s AND timestamp >= %s
                    ORDER BY timestamp DESC
                    LIMIT 100;
                """, (username, cutoff))
                return cur.fetchall()

    # ------------------------------------------------------------------
    # Investigation Persistence
    # ------------------------------------------------------------------

    def save_investigation(
        self,
        inv_id: str,
        trigger_alert_id: str,
        classification: str,
        severity: str,
        summary: str,
        attack_type: str,
        mitre_tactics: List[str],
        mitre_techniques: List[str],
        related_alert_ids: List[str],
        status: str,
        threat_intel: dict,
        network_intel: dict,
        endpoint_intel: dict,
        report_markdown: str,
        report_json: dict
    ) -> None:
        """Upsert a security investigation record."""
        # Find trigger alert first (it might not exist or we need its ID)
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                # Check classification constraint
                valid_classifications = ["false_positive", "suspicious", "confirmed_threat", "unknown"]
                if classification not in valid_classifications:
                    classification = "unknown"
                
                # Check status constraint
                valid_statuses = ["in_progress", "awaiting_response", "closed", "escalated"]
                if status not in valid_statuses:
                    status = "in_progress"

                # Check severity constraint
                valid_severities = ["Low", "Medium", "High", "Critical"]
                # Capitalize first letter of severity
                severity = severity.capitalize()
                if severity not in valid_severities:
                    severity = "Medium"

                cur.execute("""
                    INSERT INTO investigations (
                        id, trigger_alert_id, classification, severity, summary, attack_type,
                        mitre_tactics, mitre_techniques, related_alert_ids, status,
                        threat_intel_results, network_intel_results, endpoint_intel_results,
                        report_markdown, report_json, started_at, updated_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()
                    )
                    ON CONFLICT (id) DO UPDATE SET
                        classification = EXCLUDED.classification,
                        severity = EXCLUDED.severity,
                        summary = EXCLUDED.summary,
                        attack_type = EXCLUDED.attack_type,
                        mitre_tactics = EXCLUDED.mitre_tactics,
                        mitre_techniques = EXCLUDED.mitre_techniques,
                        related_alert_ids = EXCLUDED.related_alert_ids,
                        status = EXCLUDED.status,
                        threat_intel_results = EXCLUDED.threat_intel_results,
                        network_intel_results = EXCLUDED.network_intel_results,
                        endpoint_intel_results = EXCLUDED.endpoint_intel_results,
                        report_markdown = EXCLUDED.report_markdown,
                        report_json = EXCLUDED.report_json,
                        completed_at = CASE WHEN EXCLUDED.status = 'closed' THEN NOW() ELSE investigations.completed_at END,
                        updated_at = NOW();
                """, (
                    inv_id,
                    trigger_alert_id,
                    classification,
                    severity,
                    summary,
                    attack_type,
                    mitre_tactics,
                    mitre_techniques,
                    related_alert_ids,
                    status,
                    Json(threat_intel),
                    Json(network_intel),
                    Json(endpoint_intel),
                    report_markdown,
                    Json(report_json)
                ))

    def get_investigation_by_alert_id(self, alert_id: str) -> Optional[dict]:
        """Fetch investigation related to a specific alert ID."""
        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM investigations
                    WHERE trigger_alert_id = %s OR %s = ANY(related_alert_ids)
                    ORDER BY started_at DESC
                    LIMIT 1;
                """, (alert_id, alert_id))
                row = cur.fetchone()
                return dict(row) if row else None

    # ------------------------------------------------------------------
    # Incident Memory (IOC Lookup Cache)
    # ------------------------------------------------------------------

    def save_incident_memory(
        self,
        investigation_id: str,
        ioc_type: str,
        ioc_value: str,
        context: Optional[dict] = None,
        tags: Optional[List[str]] = None,
        reputation_score: Optional[float] = None,
        reputation_data: Optional[dict] = None
    ) -> None:
        """Upsert an IOC reputation/history entry in incident_memory."""
        if not ioc_value:
            return

        valid_types = ["ip", "domain", "hash", "username", "hostname", "url"]
        if ioc_type not in valid_types:
            logger.warning("Attempted to save unsupported IOC type '%s' to incident_memory", ioc_type)
            return

        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO incident_memory (
                        investigation_id, ioc_type, ioc_value, context, tags,
                        reputation_score, reputation_data, first_seen, last_seen, occurrence_count
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), 1
                    )
                    ON CONFLICT (ioc_type, ioc_value) DO UPDATE SET
                        last_seen = NOW(),
                        occurrence_count = incident_memory.occurrence_count + 1,
                        reputation_score = COALESCE(EXCLUDED.reputation_score, incident_memory.reputation_score),
                        reputation_data = COALESCE(EXCLUDED.reputation_data, incident_memory.reputation_data),
                        tags = ARRAY(SELECT DISTINCT unnest(array_cat(incident_memory.tags, EXCLUDED.tags)));
                """, (
                    investigation_id,
                    ioc_type,
                    ioc_value,
                    Json(context or {}),
                    tags or [],
                    reputation_score,
                    Json(reputation_data or {})
                ))

    # ------------------------------------------------------------------
    # Response Actions & Watchlist
    # ------------------------------------------------------------------

    def save_response_action(self, action: dict) -> str:
        """Insert a response action record into the database."""
        action_id = action.get("id") or str(uuid.uuid4())
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO response_actions (
                        id, investigation_id, alert_id, action_type, target, reason,
                        requires_approval, approval_status, approved_by, approval_notes,
                        executed, executed_at, execution_result, error_message, created_at, updated_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()
                    );
                """, (
                    action_id,
                    action.get("investigation_id"),
                    action.get("alert_id"),
                    action.get("action_type"),
                    action.get("target"),
                    action.get("reason"),
                    action.get("requires_approval", True),
                    action.get("approval_status", "pending"),
                    action.get("approved_by"),
                    action.get("approval_notes"),
                    action.get("executed", False),
                    action.get("executed_at"),
                    Json(action.get("execution_result") or {}),
                    action.get("error_message")
                ))
        return action_id

    def update_response_action(self, action_id: str, **fields) -> Optional[dict]:
        """Update fields on a response action."""
        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                update_cols = []
                params = []
                for k, v in fields.items():
                    update_cols.append(f"{k} = %s")
                    if k == "execution_result" and isinstance(v, dict):
                        params.append(Json(v))
                    else:
                        params.append(v)
                
                params.append(action_id)
                query = f"""
                    UPDATE response_actions
                    SET {", ".join(update_cols)}, updated_at = NOW()
                    WHERE id = %s
                    RETURNING *;
                """
                cur.execute(query, params)
                row = cur.fetchone()
                if row:
                    return dict(row)
                return None

    def get_response_action_by_id(self, action_id: str) -> Optional[dict]:
        """Retrieve a single response action by ID."""
        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM response_actions WHERE id = %s;
                """, (action_id,))
                row = cur.fetchone()
                return dict(row) if row else None

    def get_pending_response_actions(self) -> List[dict]:
        """Retrieve all pending response actions."""
        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM response_actions
                    WHERE approval_status = 'pending'
                    ORDER BY created_at ASC;
                """)
                return [dict(row) for row in cur.fetchall()]

    def get_response_actions_audit(self) -> List[dict]:
        """Retrieve all response actions for auditing."""
        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM response_actions
                    ORDER BY created_at DESC;
                """)
                return [dict(row) for row in cur.fetchall()]

    def add_to_watchlist_db(self, value: str, watch_type: str, reason: str) -> None:
        """Add an entry to the watchlist table."""
        with self.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO watchlist (value, watch_type, reason, created_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (value) DO UPDATE SET
                        reason = EXCLUDED.reason,
                        created_at = NOW();
                """, (value, watch_type, reason))

    def get_watchlist(self) -> List[dict]:
        """Retrieve all watchlist items."""
        with self.get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM watchlist ORDER BY created_at DESC;")
                return [dict(row) for row in cur.fetchall()]

