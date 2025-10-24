"""Price tracking from CoinGecko API"""

import aiohttp
import asyncio
import logging
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("PriceTracker")

# CoinGecko API endpoints
COINGECKO_URL = "https://api.coingecko.com/api/v3"
KCN_COINGECKO_ID = "kylacoin"
LCN_COINGECKO_ID = "lyncoin"


class PriceTracker:
    """Tracks cryptocurrency prices from CoinGecko"""

    def __init__(self):
        self.last_kcn_price: Optional[float] = None
        self.last_kcn_price_usd: Optional[float] = None
        self.last_lcn_price: Optional[float] = None
        self.last_lcn_price_usd: Optional[float] = None
        self.last_update_time: float = 0
        self.update_interval: float = 3600  # 1 hour (60 * 60 seconds)

        # Block reward caching (same 1-hour interval as prices)
        self.last_kcn_block_reward: Optional[float] = None
        self.last_lcn_block_reward: Optional[float] = None
        self.last_block_reward_update: float = 0

    async def get_current_prices(self) -> Dict[str, Optional[float]]:
        """
        Fetch current prices from CoinGecko with caching.

        Returns cached prices if cache is still fresh (< update_interval old).
        Only fetches from API if cache has expired.

        Fetches both KCN and LCN prices.

        Returns:
            Dictionary with keys: kcn_price, kcn_price_usd, lcn_price, lcn_price_usd, timestamp
        """
        # Check if cache is still fresh
        current_time = time.time()
        if (
            self.last_kcn_price is not None
            and current_time - self.last_update_time < self.update_interval
        ):
            logger.debug(
                f"Using cached prices (age: {current_time - self.last_update_time:.0f}s)"
            )
            return {
                "kcn_price": self.last_kcn_price,
                "kcn_price_usd": self.last_kcn_price_usd,
                "lcn_price": self.last_lcn_price,
                "lcn_price_usd": self.last_lcn_price_usd,
                "timestamp": int(self.last_update_time),
            }

        # Cache expired or no cache yet, fetch fresh prices
        try:
            async with aiohttp.ClientSession() as session:
                # Fetch both KCN and LCN prices
                kcn_price, kcn_price_usd = await self._fetch_price(
                    session, KCN_COINGECKO_ID
                )
                lcn_price, lcn_price_usd = await self._fetch_price(
                    session, LCN_COINGECKO_ID
                )

                # Update cached values
                if kcn_price is not None:
                    self.last_kcn_price = kcn_price
                    self.last_kcn_price_usd = kcn_price_usd
                if lcn_price is not None:
                    self.last_lcn_price = lcn_price
                    self.last_lcn_price_usd = lcn_price_usd

                self.last_update_time = time.time()
                logger.debug(
                    f"Updated price cache: KCN {kcn_price} BTC (${kcn_price_usd} USD), LCN {lcn_price} BTC (${lcn_price_usd} USD)"
                )

                return {
                    "kcn_price": kcn_price,
                    "kcn_price_usd": kcn_price_usd,
                    "lcn_price": lcn_price,
                    "lcn_price_usd": lcn_price_usd,
                    "timestamp": int(self.last_update_time),
                }
        except Exception as e:
            logger.warning(f"Failed to fetch prices from CoinGecko: {e}")
            # Return cached values on error
            return {
                "kcn_price": self.last_kcn_price,
                "kcn_price_usd": self.last_kcn_price_usd,
                "lcn_price": self.last_lcn_price,
                "lcn_price_usd": self.last_lcn_price_usd,
                "timestamp": int(self.last_update_time),
            }

    async def _fetch_price(
        self, session: aiohttp.ClientSession, coin_id: str
    ) -> Tuple[Optional[float], Optional[float]]:
        """
        Fetch price for a single coin from CoinGecko.

        Args:
            session: aiohttp session
            coin_id: CoinGecko coin ID (e.g., 'kylacoin')

        Returns:
            Tuple of (BTC price, USD price) or (None, None) on error
        """
        try:
            url = f"{COINGECKO_URL}/simple/price"
            params = {
                "ids": coin_id,
                "vs_currencies": "btc,usd",
                "include_market_cap": "false",
                "include_24hr_vol": "false",
                "include_last_updated_at": "false",
            }

            async with session.get(
                url, params=params, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if coin_id in data:
                        price_data = data[coin_id]
                        btc_price = price_data.get("btc")
                        usd_price = price_data.get("usd")
                        logger.debug(f"{coin_id}: {btc_price} BTC, ${usd_price} USD")
                        return btc_price, usd_price
                else:
                    logger.warning(f"CoinGecko returned status {resp.status}")
                    return None, None
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching price for {coin_id}")
            return None, None
        except Exception as e:
            logger.warning(f"Error fetching price for {coin_id}: {e}")
            return None, None

    async def get_block_rewards(self) -> Dict[str, Optional[float]]:
        """
        Fetch block rewards from both chains via RPC with caching.

        Returns cached rewards if cache is still fresh (< 1 hour old).
        Only fetches from RPC if cache has expired.

        KCN uses 12 decimal places (1e12), LCN uses 8 decimal places (1e8).

        Returns:
            Dictionary with keys: kcn_block_reward, lcn_block_reward, timestamp
        """
        from ..config import Settings

        current_time = time.time()

        # Check if cache is still fresh
        if (
            self.last_kcn_block_reward is not None
            and self.last_lcn_block_reward is not None
            and current_time - self.last_block_reward_update < self.update_interval
        ):
            logger.debug(
                f"Using cached block rewards (age: {current_time - self.last_block_reward_update:.0f}s)"
            )
            return {
                "kcn_block_reward": self.last_kcn_block_reward,
                "lcn_block_reward": self.last_lcn_block_reward,
                "timestamp": int(self.last_block_reward_update),
            }

        logger.debug("Fetching block rewards from RPC endpoints")
        settings = Settings()
        kcn_reward = 1.0  # Default fallback
        lcn_reward = 1.0  # Default fallback

        try:
            async with aiohttp.ClientSession() as session:
                # Get KCN block reward
                try:
                    kcn_payload = {
                        "jsonrpc": "1.0",
                        "id": "getblocktemplate",
                        "method": "getblocktemplate",
                        "params": [{"rules": ["segwit"]}],
                    }
                    kcn_url = f"http://{settings.rpcuser}:{settings.rpcpass}@{settings.rpcip}:{settings.rpcport}"
                    async with session.post(
                        kcn_url,
                        json=kcn_payload,
                        timeout=aiohttp.ClientTimeout(total=2),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if "result" in data and data["result"]:
                                coinbasevalue = data["result"].get("coinbasevalue", 0)
                                kcn_reward = coinbasevalue / 1e12
                                logger.debug(
                                    f"KCN block reward: {kcn_reward} coins (coinbasevalue: {coinbasevalue})"
                                )
                except Exception as e:
                    logger.warning(f"Could not fetch KCN block reward: {e}")

                # Get LCN block reward
                try:
                    lcn_url = f"http://{settings.aux_rpcuser}:{settings.aux_rpcpass}@{settings.aux_rpcip}:{settings.aux_rpcport}"
                    lcn_payload = {
                        "jsonrpc": "1.0",
                        "id": "getblocktemplate_lcn",
                        "method": "getblocktemplate",
                        "params": [{"rules": ["segwit"]}],
                    }
                    async with session.post(
                        lcn_url,
                        json=lcn_payload,
                        timeout=aiohttp.ClientTimeout(total=2),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if "result" in data and data["result"]:
                                coinbasevalue = data["result"].get("coinbasevalue", 0)
                                lcn_reward = coinbasevalue / 1e8
                                logger.debug(
                                    f"LCN block reward: {lcn_reward} coins (coinbasevalue: {coinbasevalue})"
                                )
                except Exception as e:
                    logger.warning(f"Could not fetch LCN block reward: {e}")

        except Exception as e:
            logger.warning(f"Error fetching block rewards: {e}")

        # Cache the results
        self.last_kcn_block_reward = kcn_reward
        self.last_lcn_block_reward = lcn_reward
        self.last_block_reward_update = current_time

        return {
            "kcn_block_reward": kcn_reward,
            "lcn_block_reward": lcn_reward,
            "timestamp": int(current_time),
        }

    def get_cached_block_rewards(self) -> Dict[str, Optional[float]]:
        """Get last cached block rewards without making RPC calls"""
        return {
            "kcn_block_reward": self.last_kcn_block_reward,
            "lcn_block_reward": self.last_lcn_block_reward,
            "timestamp": int(self.last_block_reward_update),
        }

    def get_cached_prices(self) -> Dict[str, Optional[float]]:
        """Get last cached prices without making API call"""
        return {
            "kcn_price": self.last_kcn_price,
            "kcn_price_usd": self.last_kcn_price_usd,
            "lcn_price": self.last_lcn_price,
            "lcn_price_usd": self.last_lcn_price_usd,
            "timestamp": int(self.last_update_time),
        }


# Global instance
_price_tracker: Optional[PriceTracker] = None


def get_price_tracker() -> PriceTracker:
    """Get or create the global price tracker instance"""
    global _price_tracker
    if _price_tracker is None:
        _price_tracker = PriceTracker()
    return _price_tracker
