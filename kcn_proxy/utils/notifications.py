"""Notification system for block finds via Discord and Telegram"""

import aiohttp
import logging
from typing import Optional
from datetime import datetime

logger = logging.getLogger("Notifications")


class NotificationManager:
    """Handles notifications for block finds via multiple services"""

    def __init__(
        self,
        discord_webhook: Optional[str] = None,
        telegram_bot_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
    ):
        self.discord_webhook = discord_webhook
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id

        # Log which notification services are enabled
        services = []
        if self.discord_webhook:
            services.append("Discord")
        if self.telegram_bot_token and self.telegram_chat_id:
            services.append("Telegram")

        if services:
            logger.info("Notifications enabled: %s", ", ".join(services))
        else:
            logger.info("No notification services configured")

    async def notify_block_found(
        self,
        chain: str,
        height: int,
        block_hash: str,
        worker: str,
        difficulty: float,
        miner_software: Optional[str] = None,
    ):
        """Send notifications for a block find"""

        # Try Discord webhook
        if self.discord_webhook:
            try:
                await self._send_discord_block(
                    chain, height, block_hash, worker, difficulty, miner_software
                )
            except Exception as e:
                logger.error("Discord notification failed: %s", e)

        # Try Telegram
        if self.telegram_bot_token and self.telegram_chat_id:
            try:
                await self._send_telegram_block(
                    chain, height, block_hash, worker, difficulty, miner_software
                )
            except Exception as e:
                logger.error("Telegram notification failed: %s", e)

    async def notify_miner_connected(
        self,
        worker: str,
        miner_software: Optional[str] = None,
    ):
        """Send notifications for miner connection"""

        # Try Discord webhook
        if self.discord_webhook:
            try:
                await self._send_discord_connection(
                    worker, miner_software, connected=True
                )
            except Exception as e:
                logger.error("Discord notification failed: %s", e)

        # Try Telegram
        if self.telegram_bot_token and self.telegram_chat_id:
            try:
                await self._send_telegram_connection(
                    worker, miner_software, connected=True
                )
            except Exception as e:
                logger.error("Telegram notification failed: %s", e)

    async def notify_miner_disconnected(
        self,
        worker: str,
        miner_software: Optional[str] = None,
    ):
        """Send notifications for miner disconnection"""

        # Try Discord webhook
        if self.discord_webhook:
            try:
                await self._send_discord_connection(
                    worker, miner_software, connected=False
                )
            except Exception as e:
                logger.error("Discord notification failed: %s", e)

        # Try Telegram
        if self.telegram_bot_token and self.telegram_chat_id:
            try:
                await self._send_telegram_connection(
                    worker, miner_software, connected=False
                )
            except Exception as e:
                logger.error("Telegram notification failed: %s", e)

    async def _send_discord_block(
        self,
        chain: str,
        height: int,
        block_hash: str,
        worker: str,
        difficulty: float,
        miner_software: Optional[str],
    ):
        """Send Discord webhook notification with rich embed for block finds"""

        # Determine color based on chain
        color = (
            0x00FF00 if chain == "KCN" else 0xFF6B00
        )  # Green for KCN, Orange for LCN

        # Build embed fields
        fields = [
            {"name": "Block Height", "value": f"`{height:,}`", "inline": True},
            {"name": "Difficulty", "value": f"`{difficulty:.6f}`", "inline": True},
            {"name": "Chain", "value": f"`{chain}`", "inline": True},
            {
                "name": "Block Hash",
                "value": f"`{block_hash[:16]}...{block_hash[-16:]}`",
                "inline": False,
            },
            {"name": "Worker", "value": f"`{worker}`", "inline": False},
        ]

        # Add miner software if available
        if miner_software:
            fields.append(
                {
                    "name": "Miner Software",
                    "value": f"`{miner_software}`",
                    "inline": False,
                }
            )

        embed = {
            "title": f"🎉 {chain} Block Found!",
            "description": f"A new {chain} block has been mined!",
            "color": color,
            "fields": fields,
            "footer": {"text": "KCN-LCN Stratum Proxy"},
            "timestamp": datetime.utcnow().isoformat(),
        }

        payload = {"embeds": [embed], "username": "Mining Bot"}

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.discord_webhook,
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as response:
                if response.status != 204:
                    error_text = await response.text()
                    raise Exception(
                        f"Discord webhook failed: {response.status} - {error_text}"
                    )

        logger.info("Discord notification sent for %s block %d", chain, height)

    async def _send_discord_connection(
        self,
        worker: str,
        miner_software: Optional[str],
        connected: bool,
    ):
        """Send Discord webhook notification for miner connection/disconnection"""

        # Blue for connection, gray for disconnection
        color = 0x0099FF if connected else 0x808080
        icon = "🟢" if connected else "🔴"
        status = "Connected" if connected else "Disconnected"

        # Build embed fields
        fields = [
            {"name": "Worker", "value": f"`{worker}`", "inline": True},
        ]

        # Add miner software if available
        if miner_software:
            fields.append(
                {
                    "name": "Miner Software",
                    "value": f"`{miner_software}`",
                    "inline": True,
                }
            )

        embed = {
            "title": f"{icon} Miner {status}",
            "description": f"A miner has {status.lower()}.",
            "color": color,
            "fields": fields,
            "footer": {"text": "KCN-LCN Stratum Proxy"},
            "timestamp": datetime.utcnow().isoformat(),
        }

        payload = {"embeds": [embed], "username": "Mining Bot"}

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.discord_webhook,
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as response:
                if response.status != 204:
                    error_text = await response.text()
                    raise Exception(
                        f"Discord webhook failed: {response.status} - {error_text}"
                    )

        logger.info("Discord notification sent for miner %s", status.lower())

    async def _send_telegram_block(
        self,
        chain: str,
        height: int,
        block_hash: str,
        worker: str,
        difficulty: float,
        miner_software: Optional[str],
    ):
        """Send Telegram notification for block finds"""

        # Build message with Markdown formatting
        message = f"🎉 *{chain} Block Found!*\n\n"
        message += f"*Block Height:* `{height:,}`\n"
        message += f"*Difficulty:* `{difficulty:.6f}`\n"
        message += f"*Block Hash:*\n`{block_hash}`\n\n"
        message += f"*Worker:* `{worker}`\n"

        if miner_software:
            message += f"*Miner:* `{miner_software}`"

        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(
                        f"Telegram API failed: {response.status} - {error_text}"
                    )

        logger.info("Telegram notification sent for %s block %d", chain, height)

    async def _send_telegram_connection(
        self,
        worker: str,
        miner_software: Optional[str],
        connected: bool,
    ):
        """Send Telegram notification for miner connection/disconnection"""

        icon = "🟢" if connected else "🔴"
        status = "Connected" if connected else "Disconnected"

        # Build message with Markdown formatting
        message = f"{icon} *Miner {status}*\n\n"
        message += f"*Worker:* `{worker}`\n"

        if miner_software:
            message += f"*Miner Software:* `{miner_software}`"

        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(
                        f"Telegram API failed: {response.status} - {error_text}"
                    )

        logger.info("Telegram notification sent for miner %s", status.lower())
