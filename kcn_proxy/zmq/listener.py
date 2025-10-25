import asyncio
import zmq
import zmq.asyncio
from typing import Callable, Optional
import logging


class ZMQListener:
    """
    ZeroMQ listener for blockchain event notifications.

    Listens for block hash notifications from cryptocurrency nodes and triggers
    callbacks when new blocks are detected. Supports both KCN and LCN nodes.
    """

    def __init__(self, name: str, zmq_endpoint: str, on_block_callback: Callable):
        """
        Initialize ZMQ listener.

        Args:
            name: Human-readable name for this listener (e.g., "KCN", "LCN")
            zmq_endpoint: ZMQ endpoint URL (e.g., "tcp://127.0.0.1:28332")
            on_block_callback: Async function to call when new block is received
        """
        self.name = name
        self.zmq_endpoint = zmq_endpoint
        self.on_block_callback = on_block_callback
        self.context = None
        self.socket = None
        self.logger = logging.getLogger(f"ZMQ-{name}")
        self._running = False
        self._task = None

    async def start(self):
        """Start listening for ZMQ block notifications"""
        if self._running:
            self.logger.warning(f"{self.name} ZMQ listener already running")
            return

        try:
            # Create ZMQ context and socket
            self.context = zmq.asyncio.Context()
            self.socket = self.context.socket(zmq.SUB)

            # Subscribe to block hash notifications
            self.socket.setsockopt(zmq.SUBSCRIBE, b"hashblock")

            # Set socket options for better reliability
            self.socket.setsockopt(zmq.RCVTIMEO, 5000)  # 5 second receive timeout
            self.socket.setsockopt(zmq.LINGER, 1000)  # 1 second linger on close
            self.socket.setsockopt(zmq.RECONNECT_IVL, 1000)
            self.socket.setsockopt(zmq.RECONNECT_IVL_MAX, 10000)

            # Connect to the blockchain node
            self.socket.connect(self.zmq_endpoint)

            self.logger.debug(
                f"Connected to {self.name} ZMQ endpoint: {self.zmq_endpoint}"
            )
            self._running = True

            # Start the listening task
            self._task = asyncio.create_task(self._listen_loop())
            await self._task

        except Exception as e:
            self.logger.error(f"Failed to start {self.name} ZMQ listener: {e}")
            await self.stop()
            raise

    async def _listen_loop(self):
        """Main listening loop for ZMQ messages"""
        consecutive_errors = 0
        max_consecutive_errors = 5

        while self._running:
            try:
                # Receive multipart message: [topic, data, sequence]
                parts = await self.socket.recv_multipart()

                if len(parts) >= 2:
                    topic = parts[0]
                    block_hash = parts[1]
                    sequence = parts[2] if len(parts) > 2 else b""

                    if topic == b"hashblock":
                        block_hash_hex = block_hash.hex()
                        seq_num = int.from_bytes(sequence, "little") if sequence else 0

                        self.logger.info(
                            f"New {self.name} block received: {block_hash_hex} (seq: {seq_num})"
                        )

                        # Reset error counter on successful message
                        consecutive_errors = 0

                        # Trigger callback asynchronously
                        try:
                            await self.on_block_callback(block_hash_hex)
                        except Exception as callback_error:
                            self.logger.error(
                                f"Error in {self.name} block callback: {callback_error}"
                            )
                    else:
                        self.logger.debug(
                            f"Ignoring {self.name} ZMQ message with topic: {topic}"
                        )
                else:
                    self.logger.warning(f"Received malformed {self.name} ZMQ message")

            except zmq.Again:
                # Timeout - this is normal, just continue
                continue

            except zmq.ZMQError as e:
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    self.logger.error(
                        f"{self.name} ZMQ listener: Too many consecutive errors ({consecutive_errors}), stopping"
                    )
                    break
                else:
                    self.logger.warning(
                        f"{self.name} ZMQ error (attempt {consecutive_errors}/{max_consecutive_errors}): {e}"
                    )
                    await asyncio.sleep(
                        min(consecutive_errors * 0.5, 5.0)
                    )  # Exponential backoff

            except Exception as e:
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    self.logger.error(
                        f"{self.name} ZMQ listener: Unexpected error, stopping: {e}"
                    )
                    break
                else:
                    self.logger.error(
                        f"{self.name} ZMQ unexpected error (attempt {consecutive_errors}/{max_consecutive_errors}): {e}"
                    )
                    await asyncio.sleep(min(consecutive_errors, 5.0))

        self.logger.info(f"{self.name} ZMQ listening loop ended")

    async def stop(self):
        """Stop the ZMQ listener gracefully"""
        if not self._running:
            return

        self.logger.info(f"Stopping {self.name} ZMQ listener...")
        self._running = False

        # Cancel the listening task
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        # Close socket and context
        if self.socket:
            self.socket.close()
            self.socket = None

        if self.context:
            self.context.term()
            self.context = None

        self.logger.info(f"{self.name} ZMQ listener stopped")

    @property
    def is_running(self) -> bool:
        """Check if the listener is currently running"""
        return self._running and self._task and not self._task.done()

    def __repr__(self):
        return f"ZMQListener(name='{self.name}', endpoint='{self.zmq_endpoint}', running={self._running})"


class DualZMQListener:
    """
    Manages both KCN and LCN ZMQ listeners for dual-chain mining.

    Coordinates listening to both parent chain (KCN) and auxiliary chain (LCN)
    block notifications for optimal AuxPoW mining efficiency.
    """

    def __init__(
        self,
        kcn_endpoint: Optional[str],
        lcn_endpoint: Optional[str],
        on_kcn_block: Optional[Callable],
        on_lcn_block: Optional[Callable],
    ):
        """
        Initialize dual ZMQ listener.

        Args:
            kcn_endpoint: KCN ZMQ endpoint URL (None to disable KCN listening)
            lcn_endpoint: LCN ZMQ endpoint URL (None to disable LCN listening)
            on_kcn_block: Callback for KCN block notifications
            on_lcn_block: Callback for LCN block notifications
        """
        self.kcn_listener = None
        self.lcn_listener = None
        self.logger = logging.getLogger("DualZMQ")

        # Create listeners if endpoints are provided
        if kcn_endpoint and on_kcn_block:
            self.kcn_listener = ZMQListener("KCN", kcn_endpoint, on_kcn_block)

        if lcn_endpoint and on_lcn_block:
            self.lcn_listener = ZMQListener("LCN", lcn_endpoint, on_lcn_block)

        if not self.kcn_listener and not self.lcn_listener:
            self.logger.warning("No ZMQ listeners configured")

    async def start(self):
        """Start both listeners concurrently"""
        tasks = []

        if self.kcn_listener:
            self.logger.debug("Starting KCN ZMQ listener...")
            tasks.append(asyncio.create_task(self.kcn_listener.start()))

        if self.lcn_listener:
            self.logger.debug("Starting LCN ZMQ listener...")
            tasks.append(asyncio.create_task(self.lcn_listener.start()))

        if tasks:
            self.logger.debug(f"Starting {len(tasks)} ZMQ listener(s)...")
            # Run both listeners concurrently, but handle exceptions independently
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Log any exceptions that occurred
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    listener_name = "KCN" if i == 0 and self.kcn_listener else "LCN"
                    self.logger.error(f"{listener_name} ZMQ listener failed: {result}")
        else:
            self.logger.warning("No ZMQ listeners to start")

    async def stop(self):
        """Stop both listeners"""
        tasks = []

        if self.kcn_listener:
            tasks.append(asyncio.create_task(self.kcn_listener.stop()))

        if self.lcn_listener:
            tasks.append(asyncio.create_task(self.lcn_listener.stop()))

        if tasks:
            self.logger.info("Stopping ZMQ listeners...")
            await asyncio.gather(*tasks, return_exceptions=True)
            self.logger.info("All ZMQ listeners stopped")

    @property
    def is_running(self) -> bool:
        """Check if any listener is currently running"""
        kcn_running = self.kcn_listener.is_running if self.kcn_listener else False
        lcn_running = self.lcn_listener.is_running if self.lcn_listener else False
        return kcn_running or lcn_running

    def get_status(self) -> dict:
        """Get status of both listeners"""
        return {
            "kcn": {
                "configured": self.kcn_listener is not None,
                "running": self.kcn_listener.is_running if self.kcn_listener else False,
                "endpoint": (
                    self.kcn_listener.zmq_endpoint if self.kcn_listener else None
                ),
            },
            "lcn": {
                "configured": self.lcn_listener is not None,
                "running": self.lcn_listener.is_running if self.lcn_listener else False,
                "endpoint": (
                    self.lcn_listener.zmq_endpoint if self.lcn_listener else None
                ),
            },
        }

    def __repr__(self):
        status = self.get_status()
        return f"DualZMQListener(kcn_running={status['kcn']['running']}, lcn_running={status['lcn']['running']})"
