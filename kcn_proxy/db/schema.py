"""Database schema for solo mining statistics"""

import aiosqlite
import logging
from pathlib import Path

logger = logging.getLogger("Database")

DB_PATH = Path("./data/mining.db")


async def init_database():
    """Initialize the SQLite database with required tables"""

    # Ensure data directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(DB_PATH) as db:
        # Blocks found table
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain TEXT NOT NULL,
                height INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                worker TEXT NOT NULL,
                miner_software TEXT,
                difficulty REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                accepted BOOLEAN NOT NULL DEFAULT 1
            )
        """
        )

        # Create index for fast queries
        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_blocks_timestamp 
            ON blocks(timestamp DESC)
        """
        )

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_blocks_chain 
            ON blocks(chain)
        """
        )

        # Share statistics (aggregated per minute to keep it light)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS share_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                worker TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                shares_submitted INTEGER DEFAULT 0,
                shares_accepted INTEGER DEFAULT 0,
                shares_rejected INTEGER DEFAULT 0,
                avg_difficulty REAL
            )
        """
        )

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_share_stats_timestamp 
            ON share_stats(timestamp DESC)
        """
        )

        # Best shares tracking (top performing shares for insights)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS best_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                worker TEXT NOT NULL,
                chain TEXT NOT NULL,
                block_height INTEGER,
                share_difficulty REAL NOT NULL,
                target_difficulty REAL NOT NULL,
                difficulty_ratio REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                miner_software TEXT
            )
        """
        )

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_best_shares_difficulty 
            ON best_shares(chain, share_difficulty DESC)
        """
        )

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_best_shares_timestamp 
            ON best_shares(timestamp DESC)
        """
        )

        # Connection events (for uptime tracking)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                worker TEXT NOT NULL,
                miner_software TEXT,
                event_type TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )
        """
        )

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_connections_timestamp 
            ON connections(timestamp DESC)
        """
        )

        # Difficulty history (for network trend analysis)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS difficulty_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain TEXT NOT NULL,
                difficulty REAL NOT NULL,
                timestamp INTEGER NOT NULL
            )
        """
        )

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_difficulty_history_chain_timestamp
            ON difficulty_history(chain, timestamp DESC)
        """
        )

        # Hashrate history (for performance tracking)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS hashrate_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hashrate_hs REAL NOT NULL,
                timestamp INTEGER NOT NULL
            )
        """
        )

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_hashrate_history_timestamp
            ON hashrate_history(timestamp DESC)
        """
        )

        # Miner sessions tracking (for last-seen monitoring)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS miner_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                worker_name TEXT NOT NULL UNIQUE,
                miner_software TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                is_connected BOOLEAN DEFAULT 1
            )
        """
        )

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_miner_sessions_last_seen
            ON miner_sessions(last_seen DESC)
        """
        )

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_miner_sessions_connected
            ON miner_sessions(is_connected)
        """
        )

        await db.commit()
        logger.info(f"Database initialized at {DB_PATH}")

        # Perform startup cleanup
        await cleanup_on_startup()


async def cleanup_on_startup():
    """Clean up database on startup - clear stale connections and old share stats"""
    import time

    async with aiosqlite.connect(DB_PATH) as db:
        # Clear connection events from previous sessions
        # Keep only the last 7 days of connection history
        week_ago = int(time.time()) - (7 * 24 * 3600)

        cursor = await db.execute(
            "SELECT COUNT(*) FROM connections WHERE timestamp < ?", (week_ago,)
        )
        old_connections = (await cursor.fetchone())[0]

        if old_connections > 0:
            await db.execute("DELETE FROM connections WHERE timestamp < ?", (week_ago,))
            logger.info(f"Cleaned up {old_connections} old connection events")

        # Clean up old share stats - keep only last 24 hours for hashrate calculation
        # Hashrate needs 5-minute window, but keep 24h for dashboard stats
        day_ago = int(time.time()) - (24 * 3600)

        cursor = await db.execute(
            "SELECT COUNT(*) FROM share_stats WHERE timestamp < ?", (day_ago,)
        )
        old_shares = (await cursor.fetchone())[0]

        if old_shares > 0:
            await db.execute("DELETE FROM share_stats WHERE timestamp < ?", (day_ago,))
            logger.info(f"Cleaned up {old_shares} old share stat entries")

        # Mark any "connected" entries without corresponding "disconnected" as stale
        # This handles cases where proxy was killed without clean disconnection
        await db.execute(
            """
            INSERT INTO connections (worker, miner_software, event_type, timestamp)
            SELECT DISTINCT worker, miner_software, 'disconnected_cleanup', ?
            FROM connections c1
            WHERE c1.event_type = 'connected'
            AND NOT EXISTS (
                SELECT 1 FROM connections c2 
                WHERE c2.worker = c1.worker 
                AND c2.event_type = 'disconnected' 
                AND c2.timestamp > c1.timestamp
            )
            """,
            (int(time.time()),),
        )

        cleanup_count = db.total_changes
        if cleanup_count > 0:
            logger.info(f"Marked {cleanup_count} stale connections as disconnected")

        await db.commit()


async def cleanup_old_data():
    """Periodic cleanup function - can be called regularly to maintain database size"""
    import time

    async with aiosqlite.connect(DB_PATH) as db:
        # Keep blocks indefinitely - they're rare and valuable
        # Keep connections for 7 days
        # Keep share stats for 24 hours

        week_ago = int(time.time()) - (7 * 24 * 3600)
        day_ago = int(time.time()) - (24 * 3600)

        # Clean connections
        await db.execute("DELETE FROM connections WHERE timestamp < ?", (week_ago,))
        connections_cleaned = db.total_changes

        # Clean share stats
        await db.execute("DELETE FROM share_stats WHERE timestamp < ?", (day_ago,))
        shares_cleaned = db.total_changes

        await db.commit()

        if connections_cleaned > 0 or shares_cleaned > 0:
            logger.info(
                f"Periodic cleanup: {connections_cleaned} connections, {shares_cleaned} share stats"
            )


async def log_block_found(
    chain: str,
    height: int,
    block_hash: str,
    worker: str,
    miner_software: str,
    difficulty: float,
    timestamp: int,
    accepted: bool = True,
):
    """Log a block find to the database"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO blocks 
            (chain, height, block_hash, worker, miner_software, difficulty, timestamp, accepted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                chain,
                height,
                block_hash,
                worker,
                miner_software,
                difficulty,
                timestamp,
                accepted,
            ),
        )
        await db.commit()


async def log_connection_event(
    worker: str, miner_software: str, event_type: str, timestamp: int
):
    """Log a miner connection/disconnection event"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO connections (worker, miner_software, event_type, timestamp)
            VALUES (?, ?, ?, ?)
        """,
            (worker, miner_software, event_type, timestamp),
        )
        await db.commit()


async def update_share_stats(
    worker: str, timestamp: int, accepted: bool, difficulty: float
):
    """Update aggregated share statistics (called periodically, not per share)"""
    # Round timestamp to minute
    minute_timestamp = (timestamp // 60) * 60

    async with aiosqlite.connect(DB_PATH) as db:
        # Check if entry exists for this worker/minute
        cursor = await db.execute(
            """
            SELECT id, shares_submitted, shares_accepted, shares_rejected, avg_difficulty
            FROM share_stats
            WHERE worker = ? AND timestamp = ?
        """,
            (worker, minute_timestamp),
        )

        row = await cursor.fetchone()

        if row:
            # Update existing entry
            row_id, submitted, acc, rej, avg_diff = row
            new_submitted = submitted + 1
            new_accepted = acc + (1 if accepted else 0)
            new_rejected = rej + (0 if accepted else 1)
            # Running average of difficulty
            new_avg_diff = ((avg_diff * submitted) + difficulty) / new_submitted

            await db.execute(
                """
                UPDATE share_stats
                SET shares_submitted = ?,
                    shares_accepted = ?,
                    shares_rejected = ?,
                    avg_difficulty = ?
                WHERE id = ?
            """,
                (new_submitted, new_accepted, new_rejected, new_avg_diff, row_id),
            )
        else:
            # Create new entry
            await db.execute(
                """
                INSERT INTO share_stats 
                (worker, timestamp, shares_submitted, shares_accepted, shares_rejected, avg_difficulty)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    worker,
                    minute_timestamp,
                    1,  # shares_submitted (always 1 for new entry)
                    1 if accepted else 0,  # shares_accepted
                    0 if accepted else 1,  # shares_rejected
                    difficulty,  # avg_difficulty
                ),
            )

        await db.commit()


async def get_recent_blocks(limit: int = 50, offset: int = 0):
    """Get recent blocks found with pagination support"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get total count
        count_cursor = await db.execute("SELECT COUNT(*) as total FROM blocks")
        count_row = await count_cursor.fetchone()
        total_count = count_row["total"] if count_row else 0

        # Get paginated results
        cursor = await db.execute(
            """
            SELECT * FROM blocks
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """,
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return {
            "blocks": [dict(row) for row in rows],
            "total": total_count,
        }


async def get_blocks_by_chain(chain: str, limit: int = 10):
    """Get recent blocks for a specific chain"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT * FROM blocks
            WHERE chain = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """,
            (chain, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_stats_summary(hours: int = 24):
    """Get summary statistics for the dashboard"""
    import time

    cutoff = int(time.time()) - (hours * 3600)

    async with aiosqlite.connect(DB_PATH) as db:
        # Total blocks found in period
        cursor = await db.execute(
            """
            SELECT chain, COUNT(*) as count
            FROM blocks
            WHERE timestamp > ? AND accepted = 1
            GROUP BY chain
        """,
            (cutoff,),
        )
        blocks_by_chain = {row[0]: row[1] for row in await cursor.fetchall()}

        # Share acceptance rate
        cursor = await db.execute(
            """
            SELECT 
                SUM(shares_accepted) as accepted,
                SUM(shares_rejected) as rejected
            FROM share_stats
            WHERE timestamp > ?
        """,
            (cutoff,),
        )
        row = await cursor.fetchone()
        accepted = row[0] or 0
        rejected = row[1] or 0
        total_shares = accepted + rejected
        acceptance_rate = (accepted / total_shares * 100) if total_shares > 0 else None

        # All-time accepted blocks by chain (kept indefinitely)
        cursor = await db.execute(
            """
            SELECT chain, COUNT(*) as count
            FROM blocks
            WHERE accepted = 1
            GROUP BY chain
        """
        )
        blocks_all_time_rows = await cursor.fetchall()
        blocks_all_time = {row[0]: row[1] for row in blocks_all_time_rows}

        # Determine shares since last found (accepted) block (any chain)
        cursor = await db.execute(
            """
            SELECT timestamp FROM blocks
            WHERE accepted = 1
            ORDER BY timestamp DESC
            LIMIT 1
        """
        )
        last_block_row = await cursor.fetchone()
        shares_since_last_block = None
        last_block_time = None
        if last_block_row:
            last_block_time = last_block_row[0]
            cursor = await db.execute(
                """
                SELECT COALESCE(SUM(shares_accepted + shares_rejected),0)
                FROM share_stats
                WHERE timestamp > ?
            """,
                (last_block_time,),
            )
            shares_since_last_block = (await cursor.fetchone())[0] or 0

        return {
            "blocks": blocks_by_chain,
            "total_blocks": sum(blocks_by_chain.values()),
            "acceptance_rate": acceptance_rate,
            "total_shares": total_shares,
            "hours": hours,
            "shares_since_last_block": shares_since_last_block,
            "last_block_time": last_block_time,
            "blocks_all_time": blocks_all_time,
            "total_blocks_all_time": sum(blocks_all_time.values()),
        }


async def get_recent_share_stats(worker: str = None, minutes: int = 10):
    """Get recent share statistics for hashrate verification"""
    import time

    cutoff = int(time.time()) - (minutes * 60)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        if worker:
            cursor = await db.execute(
                """
                SELECT * FROM share_stats
                WHERE worker = ? AND timestamp > ?
                ORDER BY timestamp DESC
            """,
                (worker, cutoff),
            )
        else:
            cursor = await db.execute(
                """
                SELECT * FROM share_stats
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            """,
                (cutoff,),
            )

        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def record_best_share(
    worker: str,
    chain: str,
    block_height: int,
    share_difficulty: float,
    target_difficulty: float,
    timestamp: int,
    miner_software: str = None,
):
    """Record a potential best share if it qualifies"""
    try:
        difficulty_ratio = share_difficulty / target_difficulty

        async with aiosqlite.connect(DB_PATH) as db:
            # Check if this share qualifies for top 10 for this chain
            cursor = await db.execute(
                """
                SELECT COUNT(*) FROM best_shares 
                WHERE chain = ? AND share_difficulty > ?
                """,
                (chain, share_difficulty),
            )
            better_shares = (await cursor.fetchone())[0]

            cursor = await db.execute(
                """
                SELECT COUNT(*) FROM best_shares WHERE chain = ?
                """,
                (chain,),
            )
            total_shares = (await cursor.fetchone())[0]

            # Only store if it's in top 10 or we have less than 10 shares
            if better_shares < 10:
                await db.execute(
                    """
                    INSERT INTO best_shares 
                    (worker, chain, block_height, share_difficulty, target_difficulty, 
                     difficulty_ratio, timestamp, miner_software)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        worker,
                        chain,
                        block_height,
                        share_difficulty,
                        target_difficulty,
                        difficulty_ratio,
                        timestamp,
                        miner_software,
                    ),
                )

                # Keep only top 10 shares per chain
                if total_shares >= 10:
                    await db.execute(
                        """
                        DELETE FROM best_shares 
                        WHERE chain = ? AND id NOT IN (
                            SELECT id FROM best_shares 
                            WHERE chain = ? 
                            ORDER BY share_difficulty DESC 
                            LIMIT 10
                        )
                        """,
                        (chain, chain),
                    )

                await db.commit()
                logger.info(
                    f"Recorded best share: {worker} found {share_difficulty:.2e} difficulty share "
                    f"({difficulty_ratio:.2f}x target) on {chain}"
                )

    except Exception as e:
        logger.error(f"Error recording best share: {e}")


async def get_best_shares(chain: str = None, limit: int = 10):
    """Get best shares, optionally filtered by chain"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        if chain:
            cursor = await db.execute(
                """
                SELECT * FROM best_shares
                WHERE chain = ?
                ORDER BY share_difficulty DESC
                LIMIT ?
                """,
                (chain, limit),
            )
        else:
            cursor = await db.execute(
                """
                SELECT * FROM best_shares
                ORDER BY share_difficulty DESC
                LIMIT ?
                """,
                (limit,),
            )

        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_unified_best_shares(limit: int = 10):
    """Get unified best shares for merged mining - shows KCN, LCN ratios for the same shares"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get shares grouped by timestamp and worker, showing all chain ratios
        cursor = await db.execute(
            """
            SELECT 
                l.worker,
                l.share_difficulty,
                l.timestamp,
                l.miner_software,
                l.difficulty_ratio as kcn_ratio,
                m.difficulty_ratio as lcn_ratio
            FROM best_shares l
            LEFT JOIN best_shares m ON l.timestamp = m.timestamp AND l.worker = m.worker AND m.chain = 'LCN'
            WHERE l.chain = 'KCN'
            ORDER BY l.share_difficulty DESC
            LIMIT ?
            """,
            (limit,),
        )

        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def record_difficulty_snapshot(chain: str, difficulty: float):
    """Record a difficulty snapshot for history tracking"""
    import time

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO difficulty_history (chain, difficulty, timestamp)
            VALUES (?, ?, ?)
            """,
            (chain, difficulty, int(time.time())),
        )
        await db.commit()


async def get_difficulty_history(chain: str, hours: int = 24):
    """Get difficulty history for a specific chain within the last N hours

    For longer time ranges, data is downsampled to show meaningful trends:
    - 24h: 15-minute aggregates (~96 points)
    - 7d: 30-minute aggregates (~336 points)
    - 30d: 2-hour aggregates (~360 points)

    Also filters out zero/null values when not actively mining.
    """
    import time

    cutoff = int(time.time()) - (hours * 3600)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT timestamp, difficulty
            FROM difficulty_history
            WHERE chain = ? AND timestamp > ? AND difficulty > 0
            ORDER BY timestamp ASC
            """,
            (chain, cutoff),
        )
        rows = await cursor.fetchall()

        # Determine aggregation bucket size based on time range
        if hours <= 24:
            # 24h: aggregate into 15-minute buckets (~96 points)
            bucket_seconds = 900
        elif hours <= 7 * 24:
            # 7d: aggregate into ~30-minute buckets (~336 points)
            bucket_seconds = 1800
        else:
            # 30d+: aggregate into ~2-hour buckets (~360 points)
            bucket_seconds = 7200

        # Aggregate data into buckets
        from collections import defaultdict

        buckets = defaultdict(list)

        for row in rows:
            # Put each data point into its bucket
            bucket_idx = row["timestamp"] // bucket_seconds
            buckets[bucket_idx].append(row["difficulty"])

        # Calculate average difficulty for each bucket
        result = []
        for bucket_idx in sorted(buckets.keys()):
            difficulties = buckets[bucket_idx]
            if difficulties:
                avg_difficulty = sum(difficulties) / len(difficulties)
                timestamp = bucket_idx * bucket_seconds
                result.append({"timestamp": timestamp, "difficulty": avg_difficulty})

        return result


async def record_hashrate_snapshot(hashrate_hs: float):
    """Record a hashrate snapshot for history tracking"""
    import time

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO hashrate_history (hashrate_hs, timestamp)
            VALUES (?, ?)
            """,
            (hashrate_hs, int(time.time())),
        )
        await db.commit()


async def get_hashrate_history(hours: int = 24):
    """Get hashrate history for the last N hours

    For longer time ranges, data is downsampled to show meaningful trends:
    - 24h: 15-minute aggregates (~96 points)
    - 7d: 30-minute aggregates (~336 points)
    - 30d: 2-hour aggregates (~360 points)

    Also filters out zero values when not actively mining.
    """
    import time

    cutoff = int(time.time()) - (hours * 3600)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT timestamp, hashrate_hs
            FROM hashrate_history
            WHERE timestamp > ? AND hashrate_hs > 0
            ORDER BY timestamp ASC
            """,
            (cutoff,),
        )
        rows = await cursor.fetchall()

        # Determine aggregation bucket size based on time range
        if hours <= 24:
            # 24h: aggregate into 15-minute buckets (~96 points)
            bucket_seconds = 900
        elif hours <= 7 * 24:
            # 7d: aggregate into ~30-minute buckets (~336 points)
            bucket_seconds = 1800
        else:
            # 30d+: aggregate into ~2-hour buckets (~360 points)
            bucket_seconds = 7200

        # Aggregate data into buckets
        from collections import defaultdict

        buckets = defaultdict(list)

        for row in rows:
            # Put each data point into its bucket
            bucket_idx = row["timestamp"] // bucket_seconds
            buckets[bucket_idx].append(row["hashrate_hs"])

        # Calculate average hashrate for each bucket
        result = []
        for bucket_idx in sorted(buckets.keys()):
            hashrates = buckets[bucket_idx]
            if hashrates:
                avg_hashrate = sum(hashrates) / len(hashrates)
                timestamp = bucket_idx * bucket_seconds
                result.append({"timestamp": timestamp, "hashrate_hs": avg_hashrate})

        return result


async def record_miner_session(worker_name: str, miner_software: str = None):
    """Record or update a miner session"""
    import time

    current_time = int(time.time())

    async with aiosqlite.connect(DB_PATH) as db:
        # Try to update existing record
        cursor = await db.execute(
            """
            UPDATE miner_sessions
            SET last_seen = ?, is_connected = 1, miner_software = COALESCE(?, miner_software)
            WHERE worker_name = ?
            """,
            (current_time, miner_software, worker_name),
        )

        # If no rows were updated, insert new record
        if cursor.rowcount == 0:
            await db.execute(
                """
                INSERT INTO miner_sessions (worker_name, miner_software, first_seen, last_seen, is_connected)
                VALUES (?, ?, ?, ?, 1)
                """,
                (worker_name, miner_software, current_time, current_time),
            )

        await db.commit()


async def get_connected_miners(offset: int = 0, limit: int = 20):
    """Get connected miners with pagination"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get total count
        cursor = await db.execute(
            "SELECT COUNT(*) as count FROM miner_sessions WHERE is_connected = 1"
        )
        row = await cursor.fetchone()
        total = row["count"]

        # Get paginated results
        cursor = await db.execute(
            """
            SELECT worker_name, miner_software, first_seen, last_seen, is_connected
            FROM miner_sessions
            WHERE is_connected = 1
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return {
            "miners": [dict(row) for row in rows],
            "total": total,
            "offset": offset,
            "limit": limit,
        }


async def get_disconnected_miners(hours: int = 24, offset: int = 0, limit: int = 20):
    """Get recently disconnected miners with pagination"""
    import time

    cutoff = int(time.time()) - (hours * 3600)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get total count
        cursor = await db.execute(
            "SELECT COUNT(*) as count FROM miner_sessions WHERE is_connected = 0 AND last_seen > ?",
            (cutoff,),
        )
        row = await cursor.fetchone()
        total = row["count"]

        # Get paginated results
        cursor = await db.execute(
            """
            SELECT worker_name, miner_software, first_seen, last_seen, is_connected
            FROM miner_sessions
            WHERE is_connected = 0 AND last_seen > ?
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            (cutoff, limit, offset),
        )
        rows = await cursor.fetchall()
        return {
            "miners": [dict(row) for row in rows],
            "total": total,
            "offset": offset,
            "limit": limit,
        }


async def delete_miner_session(worker_name: str):
    """Delete a miner session record"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM miner_sessions WHERE worker_name = ?", (worker_name,)
        )
        await db.commit()


async def mark_miner_disconnected(worker_name: str):
    """Mark a miner as disconnected"""
    import time

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            UPDATE miner_sessions
            SET is_connected = 0, last_seen = ?
            WHERE worker_name = ?
            """,
            (int(time.time()), worker_name),
        )
        await db.commit()
