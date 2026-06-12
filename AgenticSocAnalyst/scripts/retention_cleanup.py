#!/usr/bin/env python3
"""
Daily Data Retention and Cleanup maintenance script.

Tasks:
1. Vaccum and optimize Postgres database tables.
2. Ensure partitions exist for the current and next month.
3. Drop Postgres range partitions older than 180 days.
4. Purge old rows in non-partitioned tables (investigations, responses, analyst notes, memory cache).
5. Purge ChromaDB vector incident documents older than 90 days.
"""

import sys
import os
import logging
from datetime import datetime, timezone, timedelta

# Append project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_analyst.memory.postgres_store import PostgresStore
from soc_analyst.memory.vector_store import VectorStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)
logger = logging.getLogger("retention_cleanup")


def get_partition_end_date(year: int, month: int) -> datetime:
    """Return the exclusive end boundary date for a monthly partition."""
    if month == 12:
        return datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    return datetime(year, month + 1, 1, tzinfo=timezone.utc)


def run_postgres_cleanup(pg: PostgresStore, retention_days: int = 180) -> None:
    """Run database optimization, partition rotation, and log purging."""
    logger.info("Starting PostgreSQL database maintenance...")
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
    
    with pg.get_conn() as conn:
        # Run VACUUM (needs autocommit/cannot run inside transaction block)
        conn.autocommit = True
        with conn.cursor() as cur:
            logger.info("Running VACUUM ANALYZE on all tables...")
            try:
                cur.execute("VACUUM ANALYZE alerts;")
                cur.execute("VACUUM ANALYZE investigations;")
                cur.execute("VACUUM ANALYZE response_actions;")
                cur.execute("VACUUM ANALYZE incident_memory;")
                cur.execute("VACUUM ANALYZE analyst_notes;")
                logger.info("VACUUM ANALYZE completed successfully.")
            except Exception as exc:
                logger.error("VACUUM failed: %s (continuing with cleanup)", exc)

        # Restore transaction mode
        conn.autocommit = False
        with conn.cursor() as cur:
            # 1. Create next month's partition (Rotation)
            next_month = datetime.now(timezone.utc) + timedelta(days=30)
            logger.info("Creating partition for next month (%d-%02d)...", next_month.year, next_month.month)
            pg._create_partition_for_date(cur, next_month)

            # 2. Query and drop partitions older than retention window
            logger.info("Checking for monthly partitions older than %d days...", retention_days)
            cur.execute("""
                SELECT c.relname
                FROM pg_inherits i
                JOIN pg_class c ON c.oid = i.inhrelid
                JOIN pg_class p ON p.oid = i.inhparent
                WHERE p.relname = 'alerts';
            """)
            partitions = [r[0] for r in cur.fetchall()]
            
            dropped_count = 0
            for part in partitions:
                # Expected format: alerts_yYYYYmMM
                if part.startswith("alerts_y") and "m" in part:
                    try:
                        # Extract year and month
                        parts = part.replace("alerts_y", "").split("m")
                        year = int(parts[0])
                        month = int(parts[1])
                        
                        end_date = get_partition_end_date(year, month)
                        if end_date < cutoff_date:
                            logger.info("Partition %s (ends %s) is older than cutoff (%s). Dropping partition...", 
                                        part, end_date.date(), cutoff_date.date())
                            cur.execute(f"DROP TABLE {part};")
                            dropped_count += 1
                    except Exception as exc:
                        logger.error("Failed to check/drop partition %s: %s", part, exc)
            
            logger.info("Dropped %d old partition table(s).", dropped_count)

            # 3. Purge older records from non-partitioned tables
            logger.info("Purging logs older than %s from auxiliary tables...", cutoff_date.date())
            
            cur.execute("DELETE FROM investigations WHERE started_at < %s;", (cutoff_date,))
            inv_purged = cur.rowcount
            
            cur.execute("DELETE FROM response_actions WHERE created_at < %s;", (cutoff_date,))
            resp_purged = cur.rowcount
            
            cur.execute("DELETE FROM analyst_notes WHERE created_at < %s;", (cutoff_date,))
            notes_purged = cur.rowcount

            cur.execute("DELETE FROM incident_memory WHERE last_seen < %s;", (cutoff_date,))
            mem_purged = cur.rowcount
            
            logger.info("Purged auxiliary records: %d investigations, %d responses, %d analyst notes, %d incident memories.",
                        inv_purged, resp_purged, notes_purged, mem_purged)


def run_chroma_cleanup(v_store: VectorStore, retention_days: int = 90) -> None:
    """Purge vector incident documents older than retention window."""
    logger.info("Starting ChromaDB vector store maintenance...")
    try:
        purged = v_store.delete_old_incidents(days=retention_days)
        logger.info("Successfully purged %d incident reports older than %d days from ChromaDB.", purged, retention_days)
    except Exception as exc:
        logger.error("Failed to run ChromaDB cleanup: %s", exc)


def main():
    logger.info("=" * 60)
    logger.info("  SOC Analyst Storage & Retention Cleanup Maintenance  ")
    logger.info("=" * 60)
    
    try:
        pg = PostgresStore()
        run_postgres_cleanup(pg, retention_days=180)
    except Exception as exc:
        logger.error("Postgres cleanup failed: %s", exc)
        
    try:
        v_store = VectorStore()
        run_chroma_cleanup(v_store, retention_days=90)
    except Exception as exc:
        logger.error("Vector store cleanup failed: %s", exc)

    logger.info("Cleanup script finished.")


if __name__ == "__main__":
    main()
