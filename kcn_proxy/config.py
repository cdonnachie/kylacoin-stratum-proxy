from dataclasses import dataclass
import os


@dataclass
class Settings:
    ip: str = "0.0.0.0"
    port: int = int(os.getenv("STRATUM_PORT", "54321"))
    rpcip: str = os.getenv("KCN_RPC_IP", "kylacoin")
    rpcport: int = int(os.getenv("KCN_RPC_PORT", "5110"))
    rpcuser: str = os.getenv("KCN_RPC_USER", "")
    rpcpass: str = os.getenv("KCN_RPC_PASS", "")
    aux_rpcip: str = os.getenv("LCN_RPC_IP", "lyncoin")
    aux_rpcport: int = int(os.getenv("LCN_RPC_PORT", "19332"))
    aux_rpcuser: str = os.getenv("LCN_RPC_USER", "")
    aux_rpcpass: str = os.getenv("LCN_RPC_PASS", "")
    aux_address: str = os.getenv("LCN_WALLET_ADDRESS", "")
    proxy_signature: str = os.getenv("PROXY_SIGNATURE", "/kcn-lcn-stratum-proxy/")
    use_easier_target: bool = os.getenv("USE_EASIER_TARGET", "true").lower() == "true"
    testnet: bool = os.getenv("TESTNET", "false").lower() == "true"
    jobs: bool = os.getenv("SHOW_JOBS", "false").lower() == "true"
    verbose: bool = os.getenv("VERBOSE", "false").lower() == "true"
    debug_shares: bool = os.getenv("DEBUG_SHARES", "false").lower() == "true"

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
