import json, base58
from aiorpcx import (
    RPCSession,
    JSONRPCConnection,
    JSONRPCv1,
    Request,
    handler_invocation,
    RPCError,
)
from ..state.template import TemplateState
from ..utils.enc import bech32_decode
from ..consensus.merkle import fold_branch_index0
from ..consensus.header import build_header80_le
from ..utils.hashers import dsha256, sha3d, flex_pow
from aiohttp import ClientSession
from ..consensus.targets import (
    target_to_diff1,
)

hashratedict = {}


class StratumSession(RPCSession):
    def __init__(
        self,
        state: TemplateState,
        testnet: bool,
        verbose: bool,
        node_url: str,
        aux_url: str | None,
        debug_shares: bool,
        transport,
    ):
        connection = JSONRPCConnection(JSONRPCv1)
        super().__init__(transport, connection=connection)
        import logging

        self._state = state
        self._testnet = testnet
        self._verbose = verbose
        self._debug_shares = debug_shares
        self._client_addr = transport._remote_address
        self._transport = transport
        self._node_url = node_url
        self._aux_url = aux_url
        self._extranonce1 = None
        self.logger = logging.getLogger("Stratum-Proxy")

        self.handlers = {
            "mining.subscribe": self.handle_subscribe,
            "mining.authorize": self.handle_authorize,
            "mining.submit": self.handle_submit,
            "mining.configure": self.handle_configure,
            "eth_submitHashrate": self.handle_eth_submitHashrate,
        }

    async def handle_request(self, request):
        if isinstance(request, Request):
            handler = self.handlers.get(request.method, None)
            if not handler:
                return
        else:
            return
        return await handler_invocation(handler, request)()

    async def connection_lost(self):
        # best-effort cleanup
        try:
            wid = getattr(self, "_worker_id", None)
            if wid:
                from .session import hashratedict  # or wherever it lives now

                hashratedict.pop(wid, None)
        except Exception:
            pass

        self._state.new_sessions.discard(self)
        self._state.all_sessions.discard(self)

        # call parent (zero-arg async in your aiorpcx)
        try:
            await super().connection_lost()
        except TypeError:
            # if parent is sync in other envs
            try:
                super().connection_lost()  # no args
            except Exception:
                pass

    async def handle_subscribe(self, *args):
        if self not in self._state.all_sessions:
            self._state.new_sessions.add(self)
        self._state.bits_counter += 1
        subscription_id = f"subscription_{self._state.bits_counter}"
        self._extranonce1 = self._state.bits_counter.to_bytes(4, "big").hex()
        extranonce2_size = 4
        return [
            [
                ["mining.set_difficulty", subscription_id],
                ["mining.notify", subscription_id],
            ],
            self._extranonce1,
            extranonce2_size,
        ]

    async def handle_authorize(self, username: str, password: str):
        self._worker_id = username
        address = username.split(".")[0]
        pub_h160 = None
        try:
            if address.startswith("kc1") or address.startswith("tkc1"):
                if address.startswith("tkc1") and not self._testnet:
                    raise RPCError(
                        20, f"Testnet address {address} not allowed on mainnet"
                    )
                if address.startswith("kc1") and self._testnet:
                    raise RPCError(
                        20, f"Mainnet address {address} not allowed on testnet"
                    )
                hrp, wit = bech32_decode(address)
                if hrp is None or wit is None:
                    raise RPCError(20, f"Invalid Bech32 address: {address}")
                expected = "tkc" if self._testnet else "kc"
                if hrp != expected:
                    raise RPCError(20, f"Wrong network for address {address}")
                if len(wit) == 20:
                    pub_h160 = wit
                else:
                    raise RPCError(20, "Unsupported witness program length")
            else:
                addr_decoded = base58.b58decode_check(address)
                expected_version = 109 if self._testnet else 50
                if addr_decoded[0] != expected_version:
                    raise RPCError(20, f"Invalid address version")
                pub_h160 = addr_decoded[1:]
        except RPCError:
            raise
        except Exception as e:
            raise RPCError(20, f"Address validation failed: {address} - {str(e)}")
        if not self._state.pub_h160:
            self._state.pub_h160 = pub_h160

        # Register this session now
        self._state.all_sessions.add(self)
        self._state.new_sessions.discard(self)

        # If a job exists, send it right away
        job = self._state.current_job_params()
        if job:
            difficulty = target_to_diff1(int(self._state.target, 16))
            self._share_difficulty = difficulty
            await self.send_notification("mining.set_difficulty", (difficulty,))
            await self.send_notification("mining.notify", job)
            return True

    async def handle_configure(self, extensions):
        return {}

    async def handle_submit(
        self,
        worker: str,
        job_id: str,
        extranonce2_hex: str,
        ntime_hex: str,
        nonce_hex: str,
    ):
        state = self._state
        if job_id != hex(state.job_counter)[2:]:
            self.logger.error("Miner submitted unknown/old job %s", job_id)
            return False

        if not (
            state.coinbase1
            and state.coinbase2
            and state.coinbase1_nowit
            and state.coinbase2_nowit
        ):
            self.logger.error("Coinbase parts not ready")
            return False

        en1 = bytes.fromhex(self._extranonce1 or "")
        en2 = bytes.fromhex(extranonce2_hex)
        self.logger.debug("Extranonce1: %s", en1.hex())
        self.logger.debug("Extranonce2: %s", en2.hex())

        coinbase_wit = state.coinbase1 + en1 + en2 + state.coinbase2
        coinbase_nowit = state.coinbase1_nowit + en1 + en2 + state.coinbase2_nowit
        coinbase_txid_le = sha3d(coinbase_nowit)

        merkle_root_le = fold_branch_index0(
            coinbase_txid_le, [bytes.fromhex(x) for x in state.merkle_branches]
        )
        self.logger.debug("Coinbase TXID LE: %s", coinbase_txid_le.hex())
        self.logger.debug("Merkle Branches: %s", state.merkle_branches)
        self.logger.debug("Merkle root LE: %s", merkle_root_le.hex())
        self.logger.debug("Merkle root BE: %s", merkle_root_le[::-1].hex())

        ntime_le = bytes.fromhex(ntime_hex)[::-1]
        nonce_le = bytes.fromhex(nonce_hex)[::-1]
        header80 = build_header80_le(
            state.version,
            state.prevHash_be,
            merkle_root_le,
            ntime_le,
            state.bits_le,
            nonce_le,
        )
        if self._debug_shares:
            self.logger.debug("Rebuilt header80: %s", header80.hex())

        flex_digest_le = flex_pow(header80)
        self.logger.debug("Flex digest: %s", flex_digest_le.hex())
        self.logger.debug("Flex digest BE: %s", flex_digest_le[::-1].hex())
        hnum = int.from_bytes(flex_digest_le, "little")
        self.logger.debug("Flex number: %d", hnum)
        target_int = int(state.target, 16)

        sent_diff = getattr(self, "_share_difficulty", 1.0) or 1.0
        DIFF1 = int(
            "00000000ffff0000000000000000000000000000000000000000000000000000", 16
        )
        share_diff = DIFF1 / max(1, hnum)
        is_block = hnum <= target_int
        if not is_block and (share_diff / sent_diff) < 0.99:
            if self._debug_shares:
                self.logger.error(
                    "Low difficulty share: shareDiff=%.18f minerDiff=%.18f",
                    share_diff,
                    sent_diff,
                )
            return False

        if self._verbose or is_block:
            self.logger.info(
                "Share accepted: %s by %s - shareDiff=%.18f%s",
                header80.hex(),
                worker,
                share_diff,
                " (BLOCK!)" if is_block else "",
            )

        if is_block:
            tx_count = len(state.externalTxs) + 1
            if tx_count < 0xFD:
                tx_count_hex = tx_count.to_bytes(1, "little").hex()
            elif tx_count <= 0xFFFF:
                tx_count_hex = "fd" + tx_count.to_bytes(2, "little").hex()
            elif tx_count <= 0xFFFFFFFF:
                tx_count_hex = "fe" + tx_count.to_bytes(4, "little").hex()
            else:
                tx_count_hex = "ff" + tx_count.to_bytes(8, "little").hex()
            block_hex = (
                header80.hex()
                + tx_count_hex
                + coinbase_wit.hex()
                + "".join(state.externalTxs)
            )

            async with ClientSession() as http:
                from ..rpc.kcn import submitblock

                js = await submitblock(http, self._node_url, block_hex)
                if js.get("error"):
                    self.logger.error("KCN submit error: %s", js["error"])
                else:
                    self.logger.info("KCN submit result: %s", js.get("result"))

            if self._aux_url and state.aux_job:
                try:
                    from ..consensus.auxpow import AuxJob

                    # Minimal auxpow blob (coinbase proof, no aux-branch for single leaf)
                    def ser_varint(n: int):
                        if n < 0xFD:
                            return n.to_bytes(1, "little")
                        if n <= 0xFFFF:
                            return b"\xfd" + n.to_bytes(2, "little")
                        if n <= 0xFFFFFFFF:
                            return b"\xfe" + n.to_bytes(4, "little")
                        return b"\xff" + n.to_bytes(8, "little")

                    auxpow_hex = (
                        coinbase_wit
                        + ser_varint(len(state.coinbase_branch))
                        + b"".join(state.coinbase_branch)
                        + (0).to_bytes(4, "little")
                        + header80
                        + ser_varint(0)
                        + (0).to_bytes(4, "little")
                    ).hex()
                    from ..rpc.lcn import submitauxblock

                    js = await submitauxblock(
                        http, self._aux_url, state.aux_job.aux_hash, auxpow_hex
                    )
                    if js.get("error"):
                        self.logger.error("LCN submitauxblock error: %s", js["error"])
                    else:
                        self.logger.info(
                            "LCN submitauxblock result: %s", js.get("result")
                        )
                except Exception as e:
                    self.logger.error("LCN submit failed: %s", e)
        return True

    async def handle_eth_submitHashrate(self, hashrate: str, clientid: str):
        try:
            rate = int(hashrate, 16)
            worker = str(self).strip(">").split()[3]
            from math import isfinite

            hashratedict[worker] = rate
            total = sum(hashratedict.values())
            self.logger.info(
                "Reported hashrate: %.2f Mh/s (total: %.2f Mh/s)",
                rate / 1_000_000,
                total / 1_000_000,
            )
        except Exception:
            pass
        return True
