from dataclasses import dataclass
import os
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()


@dataclass
class Settings:
    # Initialize with None to force reading from environment in __post_init__
    ip: str = "0.0.0.0"
    port: int = 0
    rpcip: str = ""
    rpcport: int = 0
    rpcuser: str = ""
    rpcpass: str = ""
    aux_rpcip: str = ""
    aux_rpcport: int = 0
    aux_rpcuser: str = ""
    aux_rpcpass: str = ""
    aux_address: str = ""
    proxy_signature: str = ""
    use_easier_target: bool = False
    testnet: bool = False
    jobs: bool = False
    verbose: bool = False
    debug_shares: bool = False
    enable_zmq: bool = False
    kcn_zmq_endpoint: str = ""
    lcn_zmq_endpoint: str = ""
    share_difficulty_divisor: float = 1000.0
    discord_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    def __post_init__(self):
        """Load settings from environment variables at instance creation time"""
        self.port = int(os.getenv("STRATUM_PORT", "54321"))
        self.rpcip = os.getenv("KCN_RPC_HOST", os.getenv("KCN_RPC_IP", "kylacoin"))
        self.rpcport = int(os.getenv("KCN_RPC_PORT", "5110"))
        self.rpcuser = os.getenv("KCN_RPC_USER", "")
        self.rpcpass = os.getenv("KCN_RPC_PASS", "")
        self.aux_rpcip = os.getenv("LCN_RPC_HOST", os.getenv("LCN_RPC_IP", "lyncoin"))
        self.aux_rpcport = int(os.getenv("LCN_RPC_PORT", "5053"))
        self.aux_rpcuser = os.getenv("LCN_RPC_USER", "")
        self.aux_rpcpass = os.getenv("LCN_RPC_PASS", "")
        self.aux_address = os.getenv("LCN_WALLET_ADDRESS", "")
        self.proxy_signature = os.getenv("PROXY_SIGNATURE", "/kcn-lcn-stratum-proxy/")
        self.use_easier_target = (
            os.getenv("USE_EASIER_TARGET", "true").lower() == "true"
        )
        self.testnet = os.getenv("TESTNET", "false").lower() == "true"
        self.jobs = os.getenv("SHOW_JOBS", "false").lower() == "true"
        self.verbose = os.getenv("VERBOSE", "false").lower() == "true"
        self.debug_shares = os.getenv("DEBUG_SHARES", "false").lower() == "true"
        # ZMQ Configuration - read at instance creation time
        self.enable_zmq = os.getenv("ENABLE_ZMQ", "true").lower() == "true"
        self.kcn_zmq_endpoint = os.getenv("KCN_ZMQ_ENDPOINT", "tcp://kylacoin:28332")
        self.lcn_zmq_endpoint = os.getenv("LCN_ZMQ_ENDPOINT", "tcp://lyncoin:28433")
        # Share difficulty divisor: share_diff = network_diff / divisor
        # Higher value = easier shares = more frequent submissions
        # 1.0 = only blocks, 1000.0 = balanced, 10000.0 = very frequent
        self.share_difficulty_divisor = float(
            os.getenv("SHARE_DIFFICULTY_DIVISOR", "1000.0")
        )
        # Notification settings
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK_URL", "")
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")

    @property
    def node_url(self) -> str:
        return f"http://{self.rpcuser}:{self.rpcpass}@{self.rpcip}:{self.rpcport}"

    @property
    def aux_url(self) -> str | None:
        if (
            self.aux_rpcuser
            and self.aux_rpcpass
            and self.aux_rpcip
            and self.aux_rpcport
        ):
            return f"http://{self.aux_rpcuser}:{self.aux_rpcpass}@{self.aux_rpcip}:{self.aux_rpcport}"
        return None
