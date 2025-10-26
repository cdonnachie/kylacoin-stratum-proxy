"""
Share feed manager for real-time share tracking and WebSocket broadcasting.
Maintains a circular buffer of recent shares and broadcasts to connected clients.
"""

import time
import json
import asyncio
from collections import deque
from typing import Optional, List, Dict, Any


class ShareFeedManager:
    """
    Manages a circular buffer of recent shares and WebSocket connections.
    Broadcasts new shares to all connected clients in real-time.
    """

    def __init__(self, max_shares: int = 1000):
        """
        Initialize the share feed manager.

        Args:
            max_shares: Maximum number of shares to keep in buffer (default: 1000)
        """
        self.max_shares = max_shares
        self.shares: deque = deque(maxlen=max_shares)
        self.connected_clients: set = set()
        self._lock = None  # Lazy-initialized in async context
        self._client_queue_size = 500  # Increased from 100 to handle slower clients

    async def _get_lock(self) -> asyncio.Lock:
        """Get or create the lock in the current event loop."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def add_share(
        self,
        worker: str,
        share_difficulty: float,
        sent_difficulty: float,
        is_block: bool,
        accepted: bool,
        kcn_difficulty: float,
        lcn_difficulty: float,
        chain: Optional[str] = None,
        miner_software: Optional[str] = None,
        is_kcn_block: bool = False,
        is_lcn_block: bool = False,
    ) -> Dict[str, Any]:
        """
        Add a new share to the feed and broadcast to connected clients (non-blocking).

        This method is designed to be fire-and-forget:
        - Adds share to buffer immediately (synchronous operation, no lock wait)
        - Schedules WebSocket broadcast as background task (non-blocking)
        - Returns immediately without waiting for broadcast

        Args:
            worker: Worker identifier
            share_difficulty: Actual difficulty of the share
            sent_difficulty: Difficulty sent to miner
            is_block: Whether this is a block submission
            accepted: Whether the share was accepted
            kcn_difficulty: KCN network difficulty
            lcn_difficulty: LCN network difficulty
            chain: Chain (KCN/LCN) if applicable
            miner_software: Miner software name
            is_kcn_block: Whether this share met KCN target
            is_lcn_block: Whether this share met LCN target

        Returns:
            Share record as dict (immediately, before broadcast)
        """
        share = {
            "id": len(self.shares),
            "timestamp": int(time.time()),
            "worker": worker,
            "share_difficulty": round(share_difficulty, 8),
            "sent_difficulty": round(sent_difficulty, 8),
            "difficulty_ratio": (
                round(share_difficulty / sent_difficulty, 4)
                if sent_difficulty > 0
                else 0
            ),
            "is_block": is_block,
            "accepted": accepted,
            "kcn_difficulty": round(kcn_difficulty, 8),
            "lcn_difficulty": round(lcn_difficulty, 8),
            "is_kcn_block": is_kcn_block,
            "is_lcn_block": is_lcn_block,
            "chain": chain or "N/A",
            "miner_software": miner_software or "Unknown",
        }

        # Add to buffer synchronously (no lock needed for deque append operations)
        self.shares.append(share)

        # Schedule broadcast and database storage as background tasks (non-blocking, fire-and-forget)
        if self.connected_clients:
            asyncio.create_task(self._broadcast(share))

        # Store to database asynchronously (non-blocking)
        asyncio.create_task(self._store_share_to_db(share))

        return share

    async def _broadcast(self, share: Dict[str, Any]) -> None:
        """Broadcast a share to all connected WebSocket clients (non-blocking).

        This method:
        - Serializes share to JSON once
        - Sends to all queues without awaiting
        - Removes slow clients that have full queues
        - Uses minimal locking
        """
        if not self.connected_clients:
            return

        message = json.dumps(share)
        disconnected = set()

        # Send to all clients without waiting (fire-and-forget)
        for queue in list(self.connected_clients):
            try:
                # Non-blocking queue put - raises QueueFull if queue is full
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # Client is too slow - mark for removal
                disconnected.add(queue)
            except Exception:
                # Any other error - mark for removal (client dead)
                disconnected.add(queue)

        # Remove slow/dead clients (only if we have any to remove)
        if disconnected:
            try:
                lock = await self._get_lock()
                async with lock:
                    self.connected_clients -= disconnected
            except Exception:
                # Even if removal fails, the broadcast succeeded for responsive clients
                pass

    async def _store_share_to_db(self, share: Dict[str, Any]) -> None:
        """Store a share to the database asynchronously (non-blocking).

        This runs in the background and doesn't block share processing.
        If database is disabled or fails, the share still stays in memory and broadcasts.
        """
        try:
            import aiosqlite
            from pathlib import Path

            db_path = Path("data/mining.db")
            if not db_path.exists():
                # Database not enabled, silently skip
                return

            async with aiosqlite.connect(str(db_path)) as db:
                await db.execute(
                    """
                    INSERT INTO shares (
                        worker, share_difficulty, sent_difficulty, difficulty_ratio,
                        is_block, is_kcn_block, is_lcn_block, accepted,
                        kcn_difficulty, lcn_difficulty, chain, miner_software, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        share["worker"],
                        share["share_difficulty"],
                        share["sent_difficulty"],
                        share["difficulty_ratio"],
                        share["is_block"],
                        share.get("is_kcn_block", False),
                        share.get("is_lcn_block", False),
                        share["accepted"],
                        share["kcn_difficulty"],
                        share["lcn_difficulty"],
                        share.get("chain", "N/A"),
                        share.get("miner_software", "Unknown"),
                        share["timestamp"],
                    ),
                )
                await db.commit()
        except Exception as e:
            # Silently fail - database storage is non-critical
            # The share is still in memory and broadcasts to WebSocket clients
            pass

    async def get_shares(
        self,
        limit: int = 100,
        offset: int = 0,
        worker: Optional[str] = None,
        accepted_only: bool = False,
        blocks_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Retrieve shares from database (if available) or buffer with optional filtering.

        Attempts to load from database first for historical data, then falls back to
        in-memory buffer for real-time shares.

        Args:
            limit: Max shares to return (default: 100)
            offset: Skip this many shares from the end (0=most recent)
            worker: Filter by worker (optional)
            accepted_only: Only return accepted shares
            blocks_only: Only return blocks

        Returns:
            Dict with 'shares' list and 'total' count
        """
        # Try to load from database first if available
        try:
            import aiosqlite
            from pathlib import Path

            db_path = Path("data/mining.db")
            if db_path.exists():
                async with aiosqlite.connect(str(db_path)) as db:
                    # Build query for shares table
                    query = "SELECT * FROM shares WHERE 1=1"
                    params = []

                    if worker:
                        query += " AND worker = ?"
                        params.append(worker)
                    if accepted_only:
                        query += " AND accepted = 1"
                    if blocks_only:
                        query += " AND is_block = 1"

                    # Order by timestamp descending (newest first)
                    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                    params.extend([limit, offset])

                    async with db.execute(query, params) as cursor:
                        rows = await cursor.fetchall()

                        # Count total matching records
                        count_query = "SELECT COUNT(*) FROM shares WHERE 1=1"
                        count_params = []
                        if worker:
                            count_query += " AND worker = ?"
                            count_params.append(worker)
                        if accepted_only:
                            count_query += " AND accepted = 1"
                        if blocks_only:
                            count_query += " AND is_block = 1"

                        async with db.execute(
                            count_query, count_params
                        ) as count_cursor:
                            total = (await count_cursor.fetchone())[0]

                        # Convert rows to share dicts (if table exists and has data)
                        if rows:
                            shares = []
                            for row in rows:
                                share = {
                                    "id": row[0],
                                    "worker": row[1],
                                    "share_difficulty": row[2],
                                    "sent_difficulty": row[3],
                                    "difficulty_ratio": row[4],
                                    "is_block": row[5],
                                    "is_kcn_block": row[6],
                                    "is_lcn_block": row[7],
                                    "accepted": row[8],
                                    "kcn_difficulty": row[9],
                                    "lcn_difficulty": row[10],
                                    "chain": row[11],
                                    "miner_software": row[12],
                                    "timestamp": row[13],
                                }
                                shares.append(share)

                            return {
                                "shares": shares,
                                "total": total,
                                "limit": limit,
                                "offset": offset,
                                "source": "database",
                            }
        except Exception:
            # If database query fails, fall back to in-memory buffer
            pass

        # Fall back to in-memory buffer
        lock = await self._get_lock()
        async with lock:
            shares_list = list(self.shares)

        # Filter
        filtered = shares_list
        if worker:
            filtered = [s for s in filtered if s["worker"] == worker]
        if accepted_only:
            filtered = [s for s in filtered if s["accepted"]]
        if blocks_only:
            filtered = [s for s in filtered if s["is_block"]]

        # Sort by timestamp descending (newest first)
        filtered.sort(key=lambda x: x["timestamp"], reverse=True)

        # Paginate
        total = len(filtered)
        result = filtered[offset : offset + limit]

        return {
            "shares": result,
            "total": total,
            "limit": limit,
            "offset": offset,
            "source": "memory",
        }

    async def register_client(self, queue: asyncio.Queue) -> None:
        """Register a new WebSocket client for share broadcasts."""
        lock = await self._get_lock()
        async with lock:
            self.connected_clients.add(queue)

    async def unregister_client(self, queue: asyncio.Queue) -> None:
        """Unregister a disconnected WebSocket client."""
        lock = await self._get_lock()
        async with lock:
            self.connected_clients.discard(queue)

    async def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about shares (from database if available, else from buffer).

        Queries the database for accurate all-time statistics. Falls back to in-memory
        buffer if database is not available.
        """
        try:
            import aiosqlite
            from pathlib import Path

            db_path = Path("data/mining.db")
            if db_path.exists():
                async with aiosqlite.connect(str(db_path)) as db:
                    # Query all-time statistics from database
                    async with db.execute(
                        "SELECT COUNT(*), SUM(CASE WHEN accepted=1 THEN 1 ELSE 0 END), "
                        "SUM(CASE WHEN accepted=0 THEN 1 ELSE 0 END), "
                        "SUM(CASE WHEN is_block=1 THEN 1 ELSE 0 END) FROM shares"
                    ) as cursor:
                        row = await cursor.fetchone()
                        if row and row[0] > 0:
                            return {
                                "total_shares": row[0] or 0,
                                "accepted_shares": row[1] or 0,
                                "rejected_shares": row[2] or 0,
                                "blocks": row[3] or 0,
                                "connected_clients": len(self.connected_clients),
                                "source": "database",
                            }
        except Exception:
            # Fall back to in-memory buffer if database query fails
            pass

        # Fall back to in-memory buffer
        lock = await self._get_lock()
        async with lock:
            if not self.shares:
                return {
                    "total_shares": 0,
                    "accepted_shares": 0,
                    "rejected_shares": 0,
                    "blocks": 0,
                    "connected_clients": len(self.connected_clients),
                    "source": "memory",
                }

            shares_list = list(self.shares)
            accepted = sum(1 for s in shares_list if s["accepted"])
            rejected = sum(1 for s in shares_list if not s["accepted"])
            blocks = sum(1 for s in shares_list if s["is_block"])

            return {
                "total_shares": len(shares_list),
                "accepted_shares": accepted,
                "rejected_shares": rejected,
                "blocks": blocks,
                "connected_clients": len(self.connected_clients),
                "source": "memory",
            }


# Global instance
_share_feed_manager: Optional[ShareFeedManager] = None


def get_share_feed_manager() -> ShareFeedManager:
    """Get or create the global share feed manager instance."""
    global _share_feed_manager
    if _share_feed_manager is None:
        _share_feed_manager = ShareFeedManager(max_shares=1000)
    return _share_feed_manager
