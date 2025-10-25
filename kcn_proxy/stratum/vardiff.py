import time
import asyncio
import logging
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class MinerState:
    difficulty: float
    shares: Deque[tuple[float, float]]  # (timestamp, difficulty_at_submit)
    last_retarget: float
    ema_interval: Optional[float] = None  # EMA of inter-share time


class VarDiffManager:
    """Adaptive per-miner difficulty targeting a desired share interval.

    This implementation is lightweight and runs entirely in-memory. It is invoked
    synchronously from the share submission hot path but uses an asyncio.Lock to
    avoid race conditions in multi-task scenarios.
    """

    def __init__(
        self,
        target_share_time: float = 15.0,
        min_difficulty: float = 16.0,
        max_difficulty: float = 2_000_000.0,
        retarget_shares: int = 20,
        retarget_time: float = 300.0,
        max_window_shares: int = 120,
        down_step: float = 0.5,
        up_step: float = 2.0,
        ema_alpha: float = 0.3,
        inactivity_lower: float = 90.0,
        inactivity_drop_factor: float = 0.5,
        inactivity_multiples: float = 6.0,
        state_path: str | None = None,
        warm_start_minutes: int = 0,
    ):
        self.target = target_share_time
        self.min_diff = min_difficulty
        self.max_diff = max_difficulty
        self.retarget_shares = retarget_shares
        self.retarget_time = retarget_time
        self.max_window_shares = max_window_shares
        self.down_step = down_step
        self.up_step = up_step
        self.ema_alpha = ema_alpha
        self.inactivity_lower = inactivity_lower
        self.inactivity_drop_factor = inactivity_drop_factor
        self.inactivity_multiples = inactivity_multiples
        self.state_path = state_path
        self.warm_start_minutes = warm_start_minutes
        self._lock = asyncio.Lock()
        self.miners: Dict[str, MinerState] = {}
        if self.state_path:
            self._load_state()

    async def _init_miner(self, miner_id: str):
        self.miners[miner_id] = MinerState(
            difficulty=self.min_diff,
            shares=deque(maxlen=self.max_window_shares),
            last_retarget=time.time(),
        )

    async def get_difficulty(self, miner_id: str) -> float:
        async with self._lock:
            if miner_id not in self.miners:
                await self._init_miner(miner_id)
            st = self.miners[miner_id]
            # Inactivity auto-reduce
            if st.shares:
                last_share_ts = st.shares[-1][0]
                # Immediate drop if exceeding inactivity_multiples * target
                idle = time.time() - last_share_ts
                if (
                    idle
                    > max(
                        self.inactivity_lower, self.inactivity_multiples * self.target
                    )
                    and st.difficulty > self.min_diff
                ):
                    st.difficulty = max(
                        self.min_diff, st.difficulty * self.inactivity_drop_factor
                    )
                    st.last_retarget = time.time()
                    st.shares.clear()
            return st.difficulty

    async def record_share(
        self,
        miner_id: str,
        share_difficulty: float | None = None,
        ts: float | None = None,
    ):
        now = ts or time.time()
        async with self._lock:
            if miner_id not in self.miners:
                await self._init_miner(miner_id)
            st = self.miners[miner_id]
            diff_used = share_difficulty or st.difficulty
            # Update EMA of inter-arrival
            if st.shares:
                delta = now - st.shares[-1][0]
                if st.ema_interval is None:
                    st.ema_interval = delta
                else:
                    st.ema_interval = (
                        self.ema_alpha * delta + (1 - self.ema_alpha) * st.ema_interval
                    )
            st.shares.append((now, diff_used))
            self._maybe_retarget(st)

    def _maybe_retarget(self, st: MinerState):
        now = time.time()
        share_count = len(st.shares)
        elapsed = now - st.last_retarget
        if share_count < 2:
            return
        if share_count < self.retarget_shares and elapsed < self.retarget_time:
            return
        first_ts = st.shares[0][0]
        last_ts = st.shares[-1][0]
        window_time = last_ts - first_ts
        if window_time <= 0:
            return
        avg_interval = window_time / (share_count - 1)
        blended = (
            0.5 * avg_interval + 0.5 * st.ema_interval
            if st.ema_interval is not None
            else avg_interval
        )
        ratio = self.target / blended
        new_diff = st.difficulty * ratio
        # Clamp step size
        if ratio > self.up_step:
            new_diff = st.difficulty * self.up_step
        elif ratio < self.down_step:
            new_diff = st.difficulty * self.down_step
        # Enforce bounds
        new_diff = max(self.min_diff, min(self.max_diff, new_diff))
        # External clamp: always prevent assigning a per-miner difficulty above the
        # current advertised chain difficulty (if available). A share whose difficulty
        # exceeds the block target adds no value; clamping keeps semantics intuitive.
        try:
            from ..state.template import global_state as _gs  # type: ignore

            if _gs and getattr(_gs, "advertised_diff", None):
                # Only clamp if manager was constructed with a relatively low max and
                # difficulty overshoots chain difficulty (safety guard). The chain diff
                # is the diff1-scaled current network difficulty.
                chain_diff = getattr(_gs, "advertised_diff", None)
                if chain_diff:
                    headroom = getattr(self, "chain_headroom", 0.9)
                    cap = chain_diff * headroom
                    if new_diff > cap:
                        new_diff = cap
        except Exception as e:
            logger.debug("Error adjusting difficulty for chain headroom: %s", e)

        # Apply only if material (>5%) change
        if abs(new_diff - st.difficulty) / max(st.difficulty, 1e-12) >= 0.05:
            st.difficulty = new_diff
            st.last_retarget = now
            st.shares.clear()
            st.ema_interval = None

    async def tick(self):
        async with self._lock:
            now = time.time()
            for st in self.miners.values():
                if (
                    not st.shares
                    and now - st.last_retarget > self.inactivity_lower
                    and st.difficulty > self.min_diff
                ):
                    st.difficulty = max(
                        self.min_diff, st.difficulty * self.inactivity_drop_factor
                    )
                    st.last_retarget = now
        # Persist periodically (lightweight)
        if self.state_path:
            self._save_state()

    # --- Persistence & Introspection ---
    def _save_state(self):
        try:
            import json, os

            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            data = {
                "target": self.target,
                "miners": {
                    k: {
                        "difficulty": v.difficulty,
                        "last_retarget": v.last_retarget,
                        "ema_interval": v.ema_interval,
                    }
                    for k, v in self.miners.items()
                },
                "ts": time.time(),
            }
            with open(self.state_path, "w") as f:
                json.dump(data, f)
        except Exception as e:
            logger.debug("Failed to save vardiff state: %s", e)

    def _load_state(self):
        try:
            import json, os

            if not os.path.exists(self.state_path):
                return
            with open(self.state_path, "r") as f:
                data = json.load(f)
            miners = data.get("miners", {})
            now = time.time()
            for k, vd in miners.items():
                self.miners[k] = MinerState(
                    difficulty=float(vd.get("difficulty", self.min_diff)),
                    shares=deque(maxlen=self.max_window_shares),
                    last_retarget=vd.get("last_retarget", now),
                    ema_interval=vd.get("ema_interval"),
                )
        except Exception as e:
            logger.debug("Failed to load vardiff state: %s", e)

    def export_state(self) -> dict:
        return {
            "target": self.target,
            "config": {
                "min": self.min_diff,
                "max": self.max_diff,
                "retarget_shares": self.retarget_shares,
                "retarget_time": self.retarget_time,
                "up_step": self.up_step,
                "down_step": self.down_step,
                "ema_alpha": self.ema_alpha,
                "inactivity_lower": self.inactivity_lower,
                "inactivity_multiples": self.inactivity_multiples,
            },
            "miners": {
                k: {
                    "difficulty": round(v.difficulty, 6),
                    "ema_interval": v.ema_interval,
                    "last_retarget": v.last_retarget,
                    "share_count_window": len(v.shares),
                }
                for k, v in self.miners.items()
            },
            "timestamp": time.time(),
        }

    async def all_intervals(self) -> dict:
        """Return snapshot of per-miner interval metrics without blocking long."""
        out = {}
        async with self._lock:
            for k, v in self.miners.items():
                share_count = len(v.shares)
                avg_interval = None
                if share_count >= 2:
                    first = v.shares[0][0]
                    last = v.shares[-1][0]
                    span = last - first
                    if span > 0:
                        avg_interval = span / (share_count - 1)
                ema_interval = v.ema_interval
                if avg_interval and ema_interval:
                    blended = 0.5 * avg_interval + 0.5 * ema_interval
                else:
                    blended = ema_interval or avg_interval
                out[k] = {
                    "share_count": share_count,
                    "avg_interval": avg_interval,
                    "ema_interval": ema_interval,
                    "blended_interval": blended,
                }
        return out


# Singleton (optional) created on-demand by server if vardiff enabled
vardiff_manager: VarDiffManager | None = None
