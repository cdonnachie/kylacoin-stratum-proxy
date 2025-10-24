"""In-memory block tracking for when database is disabled"""

from collections import deque
from typing import Dict, List, Any
import time
import threading


class InMemoryBlockTracker:
    """Tracks recent blocks in memory when database is not available"""

    def __init__(self, max_blocks_per_chain: int = 50):
        """
        Initialize the block tracker.

        Args:
            max_blocks_per_chain: Maximum number of blocks to keep per chain (KCN/LCN)
        """
        self.max_blocks_per_chain = max_blocks_per_chain
        self.blocks_kcn: deque = deque(maxlen=max_blocks_per_chain)
        self.blocks_lcn: deque = deque(maxlen=max_blocks_per_chain)
        self.lock = threading.Lock()

    def add_block(
        self,
        chain: str,
        height: int,
        block_hash: str,
        worker: str,
        timestamp: int,
        accepted: bool = True,
        difficulty: float = 0.0,
    ) -> None:
        """
        Add a block to the in-memory tracker.

        Args:
            chain: Chain name (KCN or LCN)
            height: Block height
            block_hash: Block hash
            worker: Worker/miner name that found the block
            timestamp: Unix timestamp
            accepted: Whether block was accepted
            difficulty: Block difficulty
        """
        block_data = {
            "id": None,  # No database ID
            "chain": chain.upper(),
            "height": height,
            "hash": block_hash,
            "worker": worker,
            "timestamp": timestamp,
            "accepted": accepted,
            "difficulty": difficulty,
        }

        with self.lock:
            if chain.upper() == "KCN":
                self.blocks_kcn.appendleft(block_data)
            elif chain.upper() == "LCN":
                self.blocks_lcn.appendleft(block_data)

    def get_blocks_by_chain(self, chain: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent blocks for a specific chain.

        Args:
            chain: Chain name (KCN or LCN)
            limit: Maximum number of blocks to return

        Returns:
            List of block dictionaries, sorted newest first
        """
        with self.lock:
            if chain.upper() == "KCN":
                blocks = list(self.blocks_kcn)
            elif chain.upper() == "LCN":
                blocks = list(self.blocks_lcn)
            else:
                return []

        return blocks[:limit]

    def get_all_blocks(self, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """
        Get all blocks across both chains with pagination.

        Args:
            limit: Maximum number of blocks to return
            offset: Number of blocks to skip

        Returns:
            Dictionary with 'blocks' list and 'total' count
        """
        with self.lock:
            all_blocks = list(self.blocks_kcn) + list(self.blocks_lcn)

        # Sort by timestamp descending (newest first)
        all_blocks.sort(key=lambda b: b["timestamp"], reverse=True)

        # Apply pagination
        total = len(all_blocks)
        blocks = all_blocks[offset : offset + limit]

        return {"blocks": blocks, "total": total}

    def get_total_blocks(self) -> Dict[str, int]:
        """Get total block counts by chain"""
        with self.lock:
            return {
                "KCN": len(self.blocks_kcn),
                "LCN": len(self.blocks_lcn),
                "total": len(self.blocks_kcn) + len(self.blocks_lcn),
            }

    def clear(self) -> None:
        """Clear all tracked blocks"""
        with self.lock:
            self.blocks_kcn.clear()
            self.blocks_lcn.clear()


# Global instance
_block_tracker: InMemoryBlockTracker | None = None


def get_block_tracker() -> InMemoryBlockTracker:
    """Get or create the global block tracker instance"""
    global _block_tracker
    if _block_tracker is None:
        _block_tracker = InMemoryBlockTracker(max_blocks_per_chain=50)
    return _block_tracker
