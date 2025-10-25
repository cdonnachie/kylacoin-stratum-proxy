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
    log_level: str = "INFO"
    verbose: bool = False  # Deprecated: use log_level instead
    enable_zmq: bool = False
    kcn_zmq_endpoint: str = ""
    lcn_zmq_endpoint: str = ""
    share_difficulty_divisor: float = 1000.0
    discord_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    enable_dashboard: bool = False
    dashboard_port: int = 8080
    enable_database: bool = False
    # Variable difficulty (per-miner) settings
    enable_vardiff: bool = False
    vardiff_target_interval: float = 15.0
    # Adjusted defaults for KCN/LCN low absolute difficulty regime
    vardiff_min_difficulty: float = 0.00001
    vardiff_max_difficulty: float = 0.1
    vardiff_retarget_shares: int = 20
    vardiff_retarget_time: float = 300.0
    vardiff_up_step: float = 2.0
    vardiff_down_step: float = 0.5
    vardiff_ema_alpha: float = 0.3
    vardiff_inactivity_lower: float = 90.0
    vardiff_inactivity_multiples: float = 6.0
    vardiff_inactivity_drop_factor: float = 0.5
    vardiff_state_path: str = "data/vardiff_state.json"
    vardiff_warm_start_minutes: int = 60
    vardiff_chain_headroom: float = (
        0.9  # fraction of chain difficulty used as upper cap
    )

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

        # Log level configuration (LOG_LEVEL takes precedence over VERBOSE)
        log_level_env = os.getenv("LOG_LEVEL", "").upper()
        if log_level_env:
            self.log_level = log_level_env
        else:
            # Fallback: check VERBOSE for backwards compatibility
            self.verbose = os.getenv("VERBOSE", "false").lower() == "true"
            self.log_level = "DEBUG" if self.verbose else "INFO"

        # ZMQ Configuration - read at instance creation time
        self.enable_zmq = os.getenv("ENABLE_ZMQ", "true").lower() == "true"
        self.kcn_zmq_endpoint = os.getenv("KCN_ZMQ_ENDPOINT", "tcp://kylacoin:29332")
        self.lcn_zmq_endpoint = os.getenv("LCN_ZMQ_ENDPOINT", "tcp://lyncoin:29433")
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
        # Dashboard settings
        self.enable_dashboard = os.getenv("ENABLE_DASHBOARD", "false").lower() == "true"
        self.dashboard_port = int(os.getenv("DASHBOARD_PORT", "8080"))
        self.enable_database = os.getenv("ENABLE_DATABASE", "false").lower() == "true"
        # VarDiff settings
        self.enable_vardiff = os.getenv("ENABLE_VARDIFF", "false").lower() == "true"
        try:
            self.vardiff_target_interval = float(
                os.getenv("VARDIFF_TARGET_SHARE_TIME", "15.0")
            )
        except ValueError:
            self.vardiff_target_interval = 15.0
        # Extended vardiff tunables
        self.vardiff_min_difficulty = float(
            os.getenv("VARDIFF_MIN_DIFFICULTY", "0.00001")
        )
        self.vardiff_max_difficulty = float(os.getenv("VARDIFF_MAX_DIFFICULTY", "0.1"))
        self.vardiff_retarget_shares = int(os.getenv("VARDIFF_RETARGET_SHARES", "20"))
        self.vardiff_retarget_time = float(os.getenv("VARDIFF_RETARGET_TIME", "300.0"))
        self.vardiff_up_step = float(os.getenv("VARDIFF_UP_STEP", "2.0"))
        self.vardiff_down_step = float(os.getenv("VARDIFF_DOWN_STEP", "0.5"))
        self.vardiff_ema_alpha = float(os.getenv("VARDIFF_EMA_ALPHA", "0.3"))
        self.vardiff_inactivity_lower = float(
            os.getenv("VARDIFF_INACTIVITY_LOWER", "90.0")
        )
        self.vardiff_inactivity_multiples = float(
            os.getenv("VARDIFF_INACTIVITY_MULTIPLES", "6.0")
        )
        self.vardiff_inactivity_drop_factor = float(
            os.getenv("VARDIFF_INACTIVITY_DROP_FACTOR", "0.5")
        )
        self.vardiff_state_path = os.getenv(
            "VARDIFF_STATE_PATH", "data/vardiff_state.json"
        )
        self.vardiff_warm_start_minutes = int(
            os.getenv("VARDIFF_WARM_START_MINUTES", "60")
        )
        try:
            self.vardiff_chain_headroom = float(
                os.getenv("VARDIFF_CHAIN_HEADROOM", "0.9")
            )
            if self.vardiff_chain_headroom <= 0 or self.vardiff_chain_headroom > 1:
                self.vardiff_chain_headroom = 0.9
        except ValueError:
            self.vardiff_chain_headroom = 0.9

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
