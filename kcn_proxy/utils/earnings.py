"""Mining earnings and revenue calculations"""

import logging
from typing import Dict, Optional

logger = logging.getLogger("EarningsCalc")

# Default block rewards (in coins) - will be overridden by daemon values
KCN_BLOCK_REWARD = 1.0  # KCN block reward (fetched from daemon at runtime)
LCN_BLOCK_REWARD = 1.0  # LCN block reward (fetched from daemon at runtime)


class EarningsCalculator:
    """Calculate mining earnings and expected revenue"""

    @staticmethod
    def calculate_expected_blocks_per_day(
        hashrate_hs: float, network_difficulty: float
    ) -> float:
        """
        Calculate expected blocks per day.

        The formula is based on:
        - Average time between blocks = (difficulty * 2^32) / hashrate_hs
        - Blocks per second = hashrate_hs / (difficulty * 2^32)
        - Blocks per day = (blocks per second) * 86400

        Args:
            hashrate_hs: Your hashrate in H/s
            network_difficulty: Current network difficulty

        Returns:
            Expected number of blocks per day (float)
        """
        if hashrate_hs <= 0 or network_difficulty <= 0:
            return 0.0

        # 2^32 = 4294967296
        TWO_POW_32 = 4294967296

        # Blocks per second = hashrate / (difficulty * 2^32)
        blocks_per_second = hashrate_hs / (network_difficulty * TWO_POW_32)

        # Blocks per day
        blocks_per_day = blocks_per_second * 86400

        return blocks_per_day

    @staticmethod
    def calculate_daily_earnings(
        hashrate_hs: float,
        kcn_difficulty: float,
        lcn_difficulty: float,
        kcn_price_btc: Optional[float] = None,
        kcn_price_usd: Optional[float] = None,
        lcn_price_btc: Optional[float] = None,
        lcn_price_usd: Optional[float] = None,
        kcn_block_reward: Optional[float] = None,
        lcn_block_reward: Optional[float] = None,
    ) -> Dict[str, any]:
        """
        Calculate estimated daily earnings.

        For merged mining (AuxPoW), both chains receive the same hashrate,
        so blocks can be found on both chains.

        Args:
            hashrate_hs: Your total hashrate in H/s
            kcn_difficulty: Current KCN network difficulty
            lcn_difficulty: Current LCN network difficulty
            kcn_price_btc: KCN price in BTC (optional)
            kcn_price_usd: KCN price in USD (optional)
            lcn_price_btc: LCN price in BTC (optional)
            lcn_price_usd: LCN price in USD (optional)
            kcn_block_reward: KCN block reward in coins (fetched from daemon)
            lcn_block_reward: LCN block reward in coins (fetched from daemon)

        Returns:
            Dictionary with earnings estimates
        """
        # Use provided block rewards or defaults
        kcn_reward = kcn_block_reward if kcn_block_reward else KCN_BLOCK_REWARD
        lcn_reward = lcn_block_reward if lcn_block_reward else LCN_BLOCK_REWARD
        # Calculate expected blocks per day for each chain
        kcn_blocks_per_day = EarningsCalculator.calculate_expected_blocks_per_day(
            hashrate_hs, kcn_difficulty
        )
        lcn_blocks_per_day = EarningsCalculator.calculate_expected_blocks_per_day(
            hashrate_hs, lcn_difficulty
        )

        # Total coins expected per day (using actual block rewards)
        kcn_coins_per_day = kcn_blocks_per_day * kcn_reward
        lcn_coins_per_day = lcn_blocks_per_day * lcn_reward

        result = {
            "hashrate_hs": hashrate_hs,
            "kcn_difficulty": kcn_difficulty,
            "lcn_difficulty": lcn_difficulty,
            "kcn_block_reward": round(kcn_reward, 8),
            "lcn_block_reward": round(lcn_reward, 8),
            "kcn_blocks_per_day": round(kcn_blocks_per_day, 6),
            "lcn_blocks_per_day": round(lcn_blocks_per_day, 6),
            "kcn_coins_per_day": round(kcn_coins_per_day, 8),
            "lcn_coins_per_day": round(lcn_coins_per_day, 8),
            "total_coins_per_day": round(kcn_coins_per_day + lcn_coins_per_day, 8),
        }

        # Add BTC/USD values if prices available
        if kcn_price_btc:
            kcn_btc_per_day = kcn_coins_per_day * kcn_price_btc
            result["kcn_btc_per_day"] = round(kcn_btc_per_day, 8)

        if kcn_price_usd:
            kcn_usd_per_day = kcn_coins_per_day * kcn_price_usd
            result["kcn_usd_per_day"] = round(kcn_usd_per_day, 2)

        # Note: LCN has no exchanges, so no price conversions for LCN
        if lcn_price_btc:
            lcn_btc_per_day = lcn_coins_per_day * lcn_price_btc
            result["lcn_btc_per_day"] = round(lcn_btc_per_day, 8)

        if lcn_price_usd:
            lcn_usd_per_day = lcn_coins_per_day * lcn_price_usd
            result["lcn_usd_per_day"] = round(lcn_usd_per_day, 2)

        # Total earnings: KCN + LCN (now both have prices)
        total_usd_per_day = 0.0
        if kcn_price_usd:
            total_usd_per_day += kcn_coins_per_day * kcn_price_usd
        if lcn_price_usd:
            total_usd_per_day += lcn_coins_per_day * lcn_price_usd

        if total_usd_per_day > 0:
            result["total_usd_per_day"] = round(total_usd_per_day, 2)
        else:
            result["total_usd_per_day"] = None

        # Calculate weekly/monthly estimates
        result["kcn_coins_per_week"] = round(kcn_coins_per_day * 7, 8)
        result["lcn_coins_per_week"] = round(lcn_coins_per_day * 7, 8)
        result["total_coins_per_week"] = round(
            (kcn_coins_per_day + lcn_coins_per_day) * 7, 8
        )

        if kcn_price_usd:
            kcn_usd_per_week = kcn_coins_per_day * kcn_price_usd * 7
            result["kcn_usd_per_week"] = round(kcn_usd_per_week, 2)

        if lcn_price_usd:
            lcn_usd_per_week = lcn_coins_per_day * lcn_price_usd * 7
            result["lcn_usd_per_week"] = round(lcn_usd_per_week, 2)

        total_usd_per_week = 0.0
        if kcn_price_usd:
            total_usd_per_week += kcn_coins_per_day * kcn_price_usd * 7
        if lcn_price_usd:
            total_usd_per_week += lcn_coins_per_day * lcn_price_usd * 7

        if total_usd_per_week > 0:
            result["total_usd_per_week"] = round(total_usd_per_week, 2)
        else:
            result["total_usd_per_week"] = None

        return result

    @staticmethod
    def format_earnings_display(
        earnings_data: Dict[str, any], aux_enabled: bool = True
    ) -> str:
        """
        Format earnings data for display.

        Args:
            earnings_data: Dictionary from calculate_daily_earnings()
            aux_enabled: Whether AuxPoW (merged mining) is enabled

        Returns:
            Formatted string for display
        """
        mode = "AuxPoW (KCN+LCN)" if aux_enabled else "KCN only"

        lines = [f"Mining Mode: {mode}"]
        lines.append(f"Hashrate: {earnings_data['hashrate_hs']:.2f} H/s")
        lines.append("")

        if aux_enabled:
            lines.append("Expected Daily Earnings:")
            lines.append(f"  KCN: {earnings_data['kcn_coins_per_day']:.8f} coins")
            lines.append(f"  LCN: {earnings_data['lcn_coins_per_day']:.8f} coins")
            lines.append(f"  Total: {earnings_data['total_coins_per_day']:.8f} coins")

            if "total_usd_per_day" in earnings_data:
                lines.append(f"  Value: ${earnings_data['total_usd_per_day']:.2f} USD")
        else:
            lines.append("Expected Daily Earnings:")
            lines.append(f"  KCN: {earnings_data['kcn_coins_per_day']:.8f} coins")
            if "kcn_usd_per_day" in earnings_data:
                lines.append(f"  Value: ${earnings_data['kcn_usd_per_day']:.2f} USD")

        return "\n".join(lines)
