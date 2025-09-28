import asyncio
import argparse
from copy import deepcopy
import json
import time
import os

import base58

import logging
import coloredlogs

from aiohttp import ClientSession
from aiorpcx import RPCSession, JSONRPCConnection, JSONRPCv1, Request, serve_rs, handler_invocation, RPCError, TaskGroup
from functools import partial
from hashlib import sha256
from typing import Set, List, Optional, Tuple
from dataclasses import dataclass
import hashlib
import flexhash

# ----------------------------
# Globals / constants
POW_LIMIT = int("00000000ffff0000000000000000000000000000000000000000000000000000", 16)  # diff1
# ----------------------------
hashratedict = {}
SHOW_JOBS = False

# ----------------------------
# Utility helpers
# ----------------------------

def test_flex_algorithm():
    """
    Test the Flex algorithm implementation against a known block header.
    Returns: (is_working: bool, test_details: str)
    """
    logger = logging.getLogger('KCN-logger')
    try:
        logger.info("✓ flexhash wheel imported successfully")
        # 80-byte test header (example)
        test_header = bytes.fromhex(
            '0080002076072c36f42b41ba89cd3d229d7dfe61cac5122680282cea5f1c5d29'
            '53d9e219b54e3c2632d047161fab4c3287d7c7e061a35e31096c8d8fcf5b670f'
            '91b80e05bbc2d7687dbf7a1d85fadda3'
        )
        flex_result = flexhash.hash(test_header)                  # returns LE bytes
        expected_be = '00000046b116e5637891a2da9baf5e48dcb72cf19d2d95c3f9397cba1eba6d6d'
        ok = (flex_result[::-1].hex() == expected_be)
        if ok:
            logger.info("✓ Flex algorithm matches expected test vector")
            return True, f"Flex OK — hash={flex_result[::-1].hex()}"
        else:
            logger.warning("⚠️ Flex algorithm MISMATCH (this is informational for bring-up)")
            logger.warning("  Got (BE):   %s", flex_result[::-1].hex())
            logger.warning("  Expect (BE):%s", expected_be)
            return False, "Flex hash mismatch on test vector"
    except Exception as e:
        logger.error(f"❌ Error testing Flex algorithm: {str(e)}")
        return False, f"Error: {str(e)}"


def hash256_3(b: bytes) -> bytes:  # SHA3-256d used for display hash
    return hashlib.sha3_256(hashlib.sha3_256(b).digest()).digest()


def bech32_decode(bech: str):
    """Simple Bech32 decoder for extracting witness program (basic; prefer a proper lib in prod)."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if not bech:
        return None, None
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None
    hrp = bech[:pos]
    data = bech[pos + 1:]
    decoded = []
    for char in data:
        if char not in CHARSET:
            return None, None
        decoded.append(CHARSET.find(char))
    if len(decoded) < 6:
        return None, None
    witver = decoded[0]
    if witver > 16:
        return None, None
    converted = []
    acc = 0
    bits = 0
    for value in decoded[1:-6]:  # skip checksum
        acc = (acc << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            converted.append((acc >> bits) & 255)
    if bits >= 5 or ((acc << (5 - bits)) & 31):
        return None, None
    return hrp, bytes(converted)


def var_int(i: int) -> bytes:
    assert i >= 0, i
    if i < 0xfd:
        return i.to_bytes(1, 'little')
    elif i <= 0xffff:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4, 'little')
    else:
        return b'\xff' + i.to_bytes(8, 'little')


def op_push(i: int) -> bytes:
    if i < 0x4C:
        return i.to_bytes(1, 'little')
    elif i <= 0xff:
        return b'\x4c' + i.to_bytes(1, 'little')
    elif i <= 0xffff:
        return b'\x4d' + i.to_bytes(2, 'little')
    else:
        return b'\x4e' + i.to_bytes(4, 'little')


def formatDiff(target: str) -> Optional[str]:
    clean_target = prune0x(target)
    target_int = int(clean_target, 16)
    if target_int == 0:
        return "INF"
    max_target = POW_LIMIT
    diff = max_target / target_int
    UNITS = [(10**12, 'T'), (10**9, 'G'), (10**6, 'M'), (10**3, 'K')]
    for l, u in UNITS:
        if diff > l:
            return '{:.5f}{}'.format(diff / l, u)
    return '{:.5f}'.format(diff)


def compare_targets(kcn_target: str, aux_target: Optional[str]) -> str:
    """Return easier (higher) target as hex string (big-endian)."""
    if not aux_target:
        return kcn_target
    kcn_int = int(prune0x(kcn_target), 16)
    aux_int = int(prune0x(aux_target), 16)
    return aux_target if aux_int > kcn_int else kcn_target


def get_target_difficulty(target: str) -> float:
    clean_target = prune0x(target)
    target_int = int(clean_target, 16)
    if target_int == 0:
        return float('inf')
    return POW_LIMIT / target_int


def prune0x(s: str) -> str:
    return s[2:] if isinstance(s, str) and s.startswith('0x') else s


def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b).digest()).digest()


def merkle_from_txids(txids: List[bytes]) -> bytes:
    # txids/leaves are LE bytes
    if not txids:
        return dsha256(b'')
    if len(txids) == 1:
        return txids[0]
    level = txids[:]
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [dsha256(level[i] + level[i+1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_branch_from_leaves(leaves: List[bytes], leaf_index: int) -> Tuple[List[bytes], int]:
    if not leaves:
        return ([], 0)
    branch = []
    idx = leaf_index
    level = leaves[:]
    if len(level) == 1:
        return ([], 0)
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        pair = idx ^ 1
        branch.append(level[pair])
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(dsha256(level[i] + level[i+1]))
        level = next_level
        idx //= 2
    return (branch, leaf_index)


# --- target helpers ---
def bits_to_target(bits_hex: str) -> str:
    """Expand compact 'bits' (hex string) to 256-bit target hex (big-endian, 64 chars)."""
    bits = int(bits_hex, 16)
    exp = bits >> 24
    mant = bits & 0xFFFFFF
    if exp <= 3:
        target_int = mant >> (8 * (3 - exp))
    else:
        target_int = mant << (8 * (exp - 3))
    return f"{target_int:064x}"


def normalize_target_be(target_hex: str) -> str:
    """Normalize any hex target to 64-char big-endian hex."""
    return prune0x(target_hex).rjust(64, '0').lower()


# ----------------------------
# AuxPoW structures
# ----------------------------
@dataclass
class AuxJob:
    symbol: str
    url: str
    aux_hash: str       # hex, big-endian string from createauxblock
    target: Optional[str] = None
    chain_id: Optional[int] = None


def ser_varint(n: int) -> bytes:
    return var_int(n)


def ser_hashes(branch: List[bytes]) -> bytes:
    return ser_varint(len(branch)) + b''.join(h for h in branch)


def build_auxpow_blob(*, coinbase_tx: bytes,
                      coinbase_branch: List[bytes], coinbase_index: int,
                      parent_header: bytes,
                      aux_branch: List[bytes], aux_index: int) -> str:
    """
    Standard AuxPoW serialization:
      coinbase_tx | coinbase_merkle_branch | coinbase_branch_index | parent_header | aux_merkle_branch | aux_branch_index
    """
    blob = b''
    blob += coinbase_tx
    blob += ser_hashes(coinbase_branch)
    blob += coinbase_index.to_bytes(4, 'little')
    blob += parent_header
    blob += ser_hashes(aux_branch)
    blob += aux_index.to_bytes(4, 'little')
    return blob.hex()


# ----------------------------
# Shared mining state
# ----------------------------
class TemplateState:
    # Parent (Kylacoin/Flex) block template fields
    height: int = -1
    timestamp: int = -1
    pub_h160: Optional[bytes] = None

    bits: Optional[str] = None
    target: Optional[str] = None
    target_source: str = "KCN"  # Track which chain's target we're using
    headerHash: Optional[str] = None

    version: int = -1
    prevHash: Optional[bytes] = None
    externalTxs: List[str] = []
    coinbase_tx: Optional[bytes] = None
    coinbase_txid: Optional[bytes] = None

    # Stratum coinbase split for mining.notify
    coinbase1: Optional[bytes] = None  # (with segwit marker/flag)
    coinbase2: Optional[bytes] = None
    merkle_branches: List[str] = []    # hex strings

    # AuxPoW (Lyncoin) related
    aux_job: Optional[AuxJob] = None
    aux_root: Optional[bytes] = None  # single-leaf => dsha256(LE(aux_hash))
    mm_nonce: int = 0
    mm_tree_size: int = 0
    aux_last_update: int = 0

    # coinbase -> merkle root path for AuxPoW proof
    coinbase_branch: List[bytes] = []
    coinbase_index: int = 0

    current_commitment: Optional[str] = None

    new_sessions: Set[RPCSession] = set()
    all_sessions: Set[RPCSession] = set()

    awaiting_update = False

    job_counter = 0
    bits_counter = 0

    # Added for correct header/txid handling
    header_prefix: Optional[bytes] = None   # version|prev|merkle (68 bytes, LE)
    bits_le: Optional[bytes] = None
    coinbase1_nowit: Optional[bytes] = None
    coinbase2_nowit: Optional[bytes] = None

    def __init__(self):
        self.logger = logging.getLogger('KCN-logger')

    @property
    def tag(self):
        return '\x1b[0;36mKylacoin\x1b[0m'

    def get_merkle_hashes(self, merkle_branches):
        """Convert merkle branch bytes to hex strings for stratum"""
        return [branch.hex() for branch in merkle_branches]

    def __repr__(self):
        return (
            f'Height:\t\t{self.height}\nAddress h160:\t\t{self.pub_h160}\nBits:\t\t{self.bits}\nTarget:\t\t{self.target}\n'
            f'Header Hash:\t\t{self.headerHash}\nVersion:\t\t{self.version}\nPrevious Header:\t\t{self.prevHash.hex() if self.prevHash else None}\n'
            f'Extra Txs:\t\t{self.externalTxs}\n'
            f'Coinbase:\t\t{self.coinbase_tx.hex() if self.coinbase_tx else None}\n'
            f'Coinbase txid:\t\t{self.coinbase_txid.hex() if self.coinbase_txid else None}\nAux job:\t\t{self.aux_job}\n'
            f'New sessions:\t\t{self.new_sessions}\nSessions:\t\t{self.all_sessions}'
        )


# ----------------------------
# State queue helpers (old jobs)
# ----------------------------

def add_old_state_to_queue(queue, state, drop_after: int):
    id = hex(state.job_counter)[2:]
    if id in queue[1]:
        return
    queue[0].append(id)
    queue[1][id] = state
    while len(queue[0]) > drop_after:
        del queue[1][queue[0].pop(0)]


def lookup_old_state(queue, id: str) -> Optional[TemplateState]:
    return queue[1].get(id, None)


# ----------------------------
# Stratum session
# ----------------------------
class StratumSession(RPCSession):

    def __init__(self, state: TemplateState, old_states, testnet: bool, verbose: bool, node_url: str, aux_url: Optional[str], debug_shares: bool, transport):
        connection = JSONRPCConnection(JSONRPCv1)
        super().__init__(transport, connection=connection)
        self._state = state
        self._testnet = testnet
        self._verbose = verbose
        self._debug_shares = debug_shares
        self._old_states = old_states
        self._client_addr = transport._remote_address
        self._transport = transport
        self._node_url = node_url
        self._aux_url = aux_url
        self._extranonce1 = None
        self.logger = logging.getLogger('KCN-logger')

        logging.info('Connection with client %s:%d established', self._client_addr.host.exploded, self._client_addr.port)

        self.handlers = {
            'mining.subscribe': self.handle_subscribe,
            'mining.authorize': self.handle_authorize,
            'mining.submit': self.handle_submit,
            'mining.configure': self.handle_configure,
            'eth_submitHashrate': self.handle_eth_submitHashrate,
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
        worker = str(self).strip('>').split()[3]
        if self._verbose:
            logging.info('Connection with client %s:%d closed.', self._client_addr.host.exploded, self._client_addr.port)
        hashratedict.pop(worker, None)
        self._state.new_sessions.discard(self)
        self._state.all_sessions.discard(self)
        return await super().connection_lost()

    async def handle_subscribe(self, *args):
        if self not in self._state.all_sessions:
            self._state.new_sessions.add(self)
        self._state.bits_counter += 1

        # Generate subscription ID
        subscription_id = f"subscription_{self._state.bits_counter}"

        # Stratum extranonce1 & extranonce2_size
        self._extranonce1 = self._state.bits_counter.to_bytes(4, 'big').hex()
        extranonce2_size = 4

        return [
            [
                ["mining.set_difficulty", subscription_id],
                ["mining.notify", subscription_id]
            ],
            self._extranonce1,
            extranonce2_size
        ]

    async def handle_authorize(self, username: str, password: str):
        # First address that connects becomes payout address
        address = username.split('.')[0]

        # Handle different address formats
        pub_h160 = None

        try:
            # Bech32 (kc1 / tkc1)
            if address.startswith('kc1') or address.startswith('tkc1'):
                if address.startswith('tkc1') and not self._testnet:
                    raise RPCError(20, f'Testnet address {address} not allowed on mainnet')
                if address.startswith('kc1') and self._testnet:
                    raise RPCError(20, f'Mainnet address {address} not allowed on testnet')
                hrp, witness_program = bech32_decode(address)
                if hrp is None or witness_program is None:
                    raise RPCError(20, f'Invalid Bech32 address: {address}')
                expected_hrp = 'tkc' if self._testnet else 'kc'
                if hrp != expected_hrp:
                    raise RPCError(20, f'Wrong network for address {address}')
                if len(witness_program) == 20:
                    pub_h160 = witness_program
                else:
                    raise RPCError(20, f'Unsupported witness program length: {len(witness_program)}')
            else:
                # Base58Check
                try:
                    addr_decoded = base58.b58decode_check(address)
                    expected_version = 109 if self._testnet else 50
                    if addr_decoded[0] != expected_version:
                        raise RPCError(20, f'Invalid address version for {"testnet" if self._testnet else "mainnet"}: {address}')
                    pub_h160 = addr_decoded[1:]
                except Exception as e:
                    raise RPCError(20, f'Invalid address format: {address} - {str(e)}')

        except RPCError:
            raise
        except Exception as e:
            raise RPCError(20, f'Address validation failed: {address} - {str(e)}')

        if not self._state.pub_h160:
            self._state.pub_h160 = pub_h160

        return True

    async def handle_configure(self, extensions):
        if self._verbose:
            self.logger.debug('Miner configure request: %s', extensions)
        return {}

    async def handle_submit(self, worker: str, job_id: str, extranonce2_hex: str, ntime_hex: str, nonce_hex: str):
        if self._verbose:
            self.logger.debug('Possible solution for %s job %s', worker, job_id)

        state = self._state
        if job_id != hex(state.job_counter)[2:]:
            old_state = lookup_old_state(self._old_states, job_id)
            if old_state is not None:
                state = old_state
            else:
                self.logger.error('Miner submitted unknown/old job %s', job_id)
                return False

        # --- rebuild coinbase (wit + no-wit) with extranonces ---
        en1 = bytes.fromhex(self._extranonce1 or "")
        en2 = bytes.fromhex(prune0x(extranonce2_hex))

        if state.coinbase1 is None or state.coinbase2 is None \
           or state.coinbase1_nowit is None or state.coinbase2_nowit is None:
            self.logger.error('Coinbase parts not ready for job %s', job_id)
            return False

        coinbase_wit = state.coinbase1 + en1 + en2 + state.coinbase2
        coinbase_nowit = state.coinbase1_nowit + en1 + en2 + state.coinbase2_nowit  # used for txid leaf

        # --- merkle root from coinbase txid -> root using stored branch (LE siblings) ---
        coinbase_txid_le = dsha256(coinbase_nowit)
        h = coinbase_txid_le
        for sib_hex in state.merkle_branches:
            h = dsha256(h + bytes.fromhex(sib_hex))
        merkle_root_le = h

        # --- assemble 80B header (LE fields) using miner-submitted nTime/nonce ---
        ntime_le = bytes.fromhex(prune0x(ntime_hex))[::-1]
        nonce_le = bytes.fromhex(prune0x(nonce_hex))[::-1]
        header80 = (
            state.version.to_bytes(4, 'little') +
            state.prevHash +
            merkle_root_le[::-1] +
            ntime_le +
            state.bits_le +
            nonce_le
        )
        self.logger.debug('Rebuilt header80: %s', header80.hex())
        self.logger.debug('prevHash (LE for header): %s', state.prevHash.hex())
        self.logger.debug('prevHash (BE display): %s', state.prevHash[::-1].hex())

        # --- work hash (Flex) ---
        flex_digest_le = flexhash.hash(header80)
        if not isinstance(flex_digest_le, (bytes, bytearray)) or len(flex_digest_le) != 32:
            self.logger.error('flexhash returned invalid digest')
            return False
        flex_digest_le = bytes(flex_digest_le[::-1])
        self.logger.debug('Flex hash (LE): %s', flex_digest_le.hex())
        self.logger.debug('Flex hash (BE): %s', flex_digest_le[::-1].hex()) 

        hnum = int.from_bytes(flex_digest_le, "little")
        block_target_int = int(state.target, 16)

        DIFF1 = POW_LIMIT
        share_diff = DIFF1 / max(1, hnum)
        miner_diff = getattr(self, "_share_difficulty", 0.0) or 0.0

        # Target-based acceptance (derive from difficulty we sent)
        eff_target = getattr(self, "_share_target_int", None)
        if eff_target is None:
            sent = getattr(self, "_share_difficulty", None)
            if sent is not None:
                eff_target = min(POW_LIMIT, int(POW_LIMIT / max(sent, 1e-12)))

        is_block = hnum <= block_target_int
        meets_share = True if eff_target is None else (hnum <= eff_target)

        self.logger.debug('Share details: h=%d shareTarget=%s blockTarget=%d shareDiff=%.18f minerDiff=%.18f',
                          hnum, str(eff_target), block_target_int, share_diff, miner_diff)

        if not is_block and not meets_share:
            if self._debug_shares:
                self.logger.error('Low-difficulty share vs target: h=%d > shareTarget=%s', hnum, str(eff_target))
            return False

        # display hash for logs = SHA3-256d(header80) big-endian print
        block_hash_display = hash256_3(header80)[::-1].hex()
        if is_block:
            self.logger.info('VALID BLOCK: hash=%s h=%d', block_hash_display, state.height)
        elif self._debug_shares:
            self.logger.info('Valid share: hash=%s', block_hash_display)

        # --- build+submit blocks if found ---
        if is_block:
            tx_count_hex = var_int(len(state.externalTxs) + 1).hex()
            block_hex = header80.hex() + tx_count_hex + coinbase_wit.hex() + ''.join(state.externalTxs)

            # Decide where to submit (KCN/LCN) based on selected target
            using_aux_target = (hasattr(state, 'aux_job') and state.aux_job and
                                state.aux_job.target and state.target == state.aux_job.target)

            submit_to_kcn = True
            submit_to_aux = bool(state.aux_job and self._aux_url)
            if using_aux_target:
                kcn_target_int = int(getattr(state, 'kcn_original_target', state.target), 16)
                if hnum > kcn_target_int:
                    submit_to_kcn = False  # only meets LCN (easier) target

            # --- submit to KCN ---
            if submit_to_kcn:
                data = {'jsonrpc': '2.0', 'id': '0', 'method': 'submitblock', 'params': [block_hex]}
                async with ClientSession() as session:
                    async with session.post(f'{self._node_url}', data=json.dumps(data)) as resp:
                        js = await resp.json()
                        if not os.path.exists('./submit_history'):
                            os.mkdir('./submit_history')
                        with open(f'./submit_history/{state.height}_{state.job_counter}.txt', 'w') as f:
                            f.write(f'Response:\n{json.dumps(js, indent=2)}\n\nState:\n{state.__repr__()}')
                        if js.get('error'):
                            self.logger.error('KCN RPC error (%s): %s', js['error'].get('code'), js['error'].get('message'))

            # --- submit to LCN (AuxPoW) ---
            if submit_to_aux and state.aux_job:
                try:
                    auxpow_hex = build_auxpow_blob(
                        coinbase_tx=coinbase_wit,
                        coinbase_branch=state.coinbase_branch,
                        coinbase_index=state.coinbase_index,
                        parent_header=header80,
                        aux_branch=[], aux_index=0,
                    )
                    data_aux = {'jsonrpc': '2.0', 'id': '0', 'method': 'submitauxblock',
                                'params': [state.aux_job.aux_hash, auxpow_hex]}
                    async with ClientSession() as session:
                        async with session.post(self._aux_url, data=json.dumps(data_aux)) as resp:
                            js = await resp.json()
                            if js.get('error'):
                                self.logger.error('LCN submitauxblock error: %s', js['error'])
                            else:
                                self.logger.info('LCN submitauxblock result: %s', js.get('result'))
                except Exception as e:
                    self.logger.error('LCN AuxPoW submit failed: %s', str(e))

            chains = []
            if submit_to_kcn: chains.append('KCN')
            if submit_to_aux: chains.append('LCN')
            msg = f'Found block at height {state.height} - submitted to: {", ".join(chains) if chains else "none"}'
            self.logger.info(msg)
            await self.send_notification('client.show_message', (msg,))

        # Always acknowledge to miner (share accepted)
        return True

    async def handle_eth_submitHashrate(self, hashrate: str, clientid: str):
        data = {'jsonrpc': '2.0', 'id': '0', 'method': 'getmininginfo', 'params': []}
        async with ClientSession() as session:
            async with session.post(f'{self._node_url}', data=json.dumps(data)) as resp:
                try:
                    json_obj = await resp.json()
                    if json_obj.get('error', None):
                        raise Exception(json_obj.get('error', None))
                    blocks_int: int = json_obj['result']['blocks']
                    difficulty_int: int = json_obj['result']['difficulty']
                    networkhashps_int: int = json_obj['result']['networkhashps']
                except Exception as e:
                    self.logger.error('RPC error for mininginfo: %s', str(e))
                    return

        hashrate = int(hashrate, 16)
        worker = str(self).strip('>').split()[3]
        hashratedict.update({worker: hashrate})
        totalHashrate = 0

        self.logger.info(f'----------------------------')
        for x, y in hashratedict.items():
            totalHashrate += y
            self.logger.info(f'Reported Hashrate: {round(y / 1_000_000, 2)}Mh/s for ID: {x}')
        self.logger.info(f'----------------------------')
        self.logger.info(f'Total Reported Hashrate: {round(totalHashrate / 1_000_000, 2)}Mh/s')

        if self._testnet:
            self.logger.info(f'Network Hashrate: {round(networkhashps_int / 1_000_000, 2)}Mh/s')
        else:
            self.logger.info(f'Network Hashrate: {round(networkhashps_int / 1_000_000_000_000, 2)}Th/s')

        if totalHashrate != 0:
            TTF = difficulty_int * 2**32 / totalHashrate
            if self._testnet:
                msg = f'Estimated time to find: {round(TTF)} seconds'
            else:
                msg = f'Estimated time to find: {round(TTF / 86400, 2)} days'
            self.logger.info(msg)
            await self.send_notification('client.show_message', (msg,))
        else:
            self.logger.info('Mining software has yet to send data')
        return True


# ----------------------------
# Aux job refresh
# ----------------------------
async def refresh_aux_job(state: TemplateState, session: ClientSession, aux_url: Optional[str], aux_address: str = '', force_update: bool = False):
    # Skip AuxPoW if no aux_url or no address
    if not aux_url or not aux_address or aux_address.strip() == '':
        state.aux_job = None
        state.aux_root = None
        state.mm_tree_size = 0
        state.aux_last_update = 0
        return

    current_time = int(time.time())
    if not force_update and state.aux_job and (current_time - state.aux_last_update) < 30:
        return

    data = {'jsonrpc': '2.0', 'id': '0', 'method': 'createauxblock', 'params': [aux_address]}
    async with session.post(aux_url, data=json.dumps(data)) as resp:
        js = await resp.json()
        if js.get('error'):
            state.logger.error('Aux createauxblock error: %s', js['error'])
            state.aux_job = None
            state.aux_root = None
            state.mm_tree_size = 0
            return
        r = js['result']

        # Prefer compact 'bits' -> full target (endian-safe). If only target strings provided, normalize and fix common LE cases.
        processed_target = None
        bits_val = r.get('bits')
        if bits_val is not None:
            # bits may be int or hex string
            if isinstance(bits_val, int):
                bits_hex = f"{bits_val:08x}"
            else:
                bits_hex = prune0x(str(bits_val))
            processed_target = bits_to_target(bits_hex)
        else:
            raw_target = r.get('_target') or r.get('target')
            if raw_target:
                t = prune0x(str(raw_target)).lower().zfill(64)
                # Lyncoin returns LE 256-bit target; reverse to BE unconditionally.
                try:
                    t = bytes.fromhex(t)[::-1].hex()
                except Exception:
                    pass
                processed_target = normalize_target_be(t)

        job = AuxJob(
            symbol='LCN',
            url=aux_url,
            aux_hash=r['hash'],
            target=processed_target,
            chain_id=r.get('chainid')
        )

        job_changed = (not state.aux_job or
                       state.aux_job.aux_hash != job.aux_hash or
                       state.aux_job.target != job.target)

        state.aux_job = job
        # Single-leaf aux tree root: SHA256d(LE(aux_hash))
        leaf = dsha256(bytes.fromhex(job.aux_hash)[::-1])
        state.aux_root = leaf
        state.mm_tree_size = 1
        state.mm_nonce = int(time.time()) & 0xffffffff
        state.aux_last_update = current_time

        if SHOW_JOBS and job_changed:
            state.logger.info('Aux job updated: %s hash=%s target=%s chainid=%s', job.symbol, job.aux_hash, job.target, job.chain_id)


# ----------------------------
# State updater loop
# ----------------------------

async def stateUpdater(state: TemplateState, old_states, drop_after, verbose, node_url: str, aux_url: Optional[str], aux_address: str = '', use_easier_target: bool = False, proxy_signature: Optional[str] = None):
    if not state.pub_h160:
        return
    data = {'jsonrpc': '2.0', 'id': '0', 'method': 'getblocktemplate', 'params': [{"rules": ["segwit"]}]}
    async with ClientSession() as http:
        async with http.post(f'{node_url}', data=json.dumps(data)) as resp:
            try:
                json_obj = await resp.json()
                if json_obj.get('error', None):
                    raise Exception(json_obj.get('error', None))

                version_int: int = json_obj['result']['version']
                height_int: int = json_obj['result']['height']
                bits_hex: str = json_obj['result']['bits']
                prev_hash_hex: str = json_obj['result']['previousblockhash']
                txs_list: List = json_obj['result']['transactions']
                coinbase_sats_int: int = json_obj['result']['coinbasevalue']
                witness_hex: str = json_obj['result']['default_witness_commitment']
                coinbase_flags_hex: str = json_obj['result']['coinbaseaux'].get('flags', '') if 'coinbaseaux' in json_obj['result'] else ''
                target_hex: str = json_obj['result']['target']

                # optional rewards in template
                coinbase_devreward = json_obj['result'].get('coinbasedevreward')
                dev_address = None
                dev_sats_int = 0
                if coinbase_devreward:
                    dev_sats_int = coinbase_devreward['value']
                    dev_address = coinbase_devreward['address']

                community_address = json_obj['result'].get('CommunityAutonomousAddress')
                community_sats_int = json_obj['result'].get('CommunityAutonomousValue', 0)

                ts = int(time.time())
                new_witness = witness_hex != state.current_commitment
                state.current_commitment = witness_hex

                state.bits = bits_hex
                state.version = version_int
                state.prevHash = bytes.fromhex(prev_hash_hex)[::-1]  # store LE for direct header use

                new_block = False
                original_state = None

                # New block?
                if state.height == -1 or state.height != height_int:
                    original_state = deepcopy(state)
                    if verbose:
                        state.logger.info('%s New block, updating state', state.tag)
                    new_block = True
                    state.height = height_int

                # Update Lyncoin aux job
                await refresh_aux_job(state, http, aux_url, aux_address, force_update=new_block)

                # Target selection logic
                final_target = target_hex  # default to Kylacoin target (BE hex)
                state.kcn_original_target = target_hex
                new_target_source = "KCN"

                if use_easier_target and state.aux_job and state.aux_job.target:
                    aux_target = state.aux_job.target
                    if new_block or not hasattr(state, '_last_debug_kcn') or state._last_debug_kcn != target_hex:
                        state.logger.debug(f'Target comparison: KCN={target_hex}, LCN={aux_target}')
                        state.logger.debug(f'KCN int: {int(target_hex, 16)}, LCN int: {int(aux_target, 16)}')
                        state._last_debug_kcn = target_hex
                    final_target = compare_targets(target_hex, aux_target)
                    if final_target != target_hex:
                        new_target_source = "LCN"

                target_changed = (state.target != final_target or
                                  state.target_source != new_target_source or
                                  new_block)

                if target_changed:
                    state.target_source = new_target_source
                    if use_easier_target and state.aux_job and state.aux_job.target:
                        kcn_formatted = formatDiff(target_hex)
                        aux_formatted = formatDiff(state.aux_job.target)
                        if final_target != target_hex:
                            state.logger.info(f'Using easier Lyncoin target: KCN diff={kcn_formatted}, LCN diff={aux_formatted}')
                        else:
                            state.logger.info(f'Using Kylacoin target (harder): KCN diff={kcn_formatted}, LCN diff={aux_formatted}')
                    else:
                        kcn_formatted = formatDiff(target_hex)
                        if state.aux_job and state.aux_job.target:
                            aux_formatted = formatDiff(state.aux_job.target)
                            state.logger.info(f'Using Kylacoin target: KCN diff={kcn_formatted}, LCN diff={aux_formatted}')
                        else:
                            state.logger.info(f'Using Kylacoin target: diff={kcn_formatted} (no aux job)')
                else:
                    state.target_source = new_target_source

                # Update state with selected target
                state.target = final_target
                final_target_hex = final_target

                # Roll job if new block, new witness, or stale timestamp
                job_params = None
                if new_block or new_witness or state.timestamp + 60 < ts:
                    if original_state is None:
                        original_state = deepcopy(state)

                    # Build coinbase
                    bytes_needed_sub_1 = 0
                    while True:
                        if state.height <= (2 ** (7 + (8 * bytes_needed_sub_1))) - 1:
                            break
                        bytes_needed_sub_1 += 1
                    bip34_height = state.height.to_bytes(bytes_needed_sub_1 + 1, 'little')

                    # AuxPoW tag in scriptSig
                    mm_tag = b''
                    if state.aux_root:
                        mm_magic = bytes([0xFA, 0xBE, 0x6D, 0x6D])
                        aux_root_le = state.aux_root[::-1]
                        mm_tag = (mm_magic + aux_root_le + state.mm_tree_size.to_bytes(4, 'little') + state.mm_nonce.to_bytes(4, 'little'))

                    sig_str = proxy_signature or os.getenv('PROXY_SIGNATURE', '/kcn-lcn-stratum-proxy/')
                    proxy_sig = sig_str.encode('utf-8')
                    arbitrary_data = mm_tag + proxy_sig

                    coinbase_script = (
                        op_push(len(bip34_height)) + bip34_height +
                        op_push(len(arbitrary_data)) + arbitrary_data
                    )

                    # Coinbase input pieces
                    coinbase_txin_start = bytes(32) + b'\xff' * 4 + var_int(len(coinbase_script)) + coinbase_script
                    coinbase_txin_end = b'\xff' * 4

                    # Miner output (P2PKH)
                    vout_to_miner = b'\x76\xa9\x14' + state.pub_h160 + b'\x88\xac'

                    outputs = []
                    outputs.append(coinbase_sats_int.to_bytes(8, 'little') + op_push(len(vout_to_miner)) + vout_to_miner)
                    if verbose:
                        state.logger.debug(f'Miner output: {coinbase_sats_int} satoshis')

                    # Developer reward (optional)
                    if coinbase_devreward and dev_sats_int > 0:
                        try:
                            if 'scriptpubkey' in coinbase_devreward:
                                dev_script = bytes.fromhex(coinbase_devreward['scriptpubkey'])
                                outputs.append(dev_sats_int.to_bytes(8, 'little') + op_push(len(dev_script)) + dev_script)
                                if verbose:
                                    state.logger.debug(f'Dev reward output: {dev_sats_int} satoshis to {dev_address}')
                            else:
                                state.logger.warning(f'No scriptpubkey provided for dev address {dev_address}')
                        except Exception as e:
                            state.logger.warning(f'Could not parse dev reward: {e}')

                    # Community output (optional)
                    if community_address and community_sats_int > 0:
                        try:
                            vout_to_community = b'\x76\xa9\x14' + base58.b58decode_check(community_address)[1:] + b'\x88\xac'
                            outputs.append(community_sats_int.to_bytes(8, 'little') + op_push(len(vout_to_community)) + vout_to_community)
                            if verbose:
                                state.logger.debug(f'Community output: {community_sats_int} satoshis to {community_address}')
                        except Exception as e:
                            state.logger.warning(f'Could not parse community address {community_address}: {e}')

                    # Witness commitment from node
                    witness_vout = bytes.fromhex(witness_hex)
                    outputs.append(bytes(8) + op_push(len(witness_vout)) + witness_vout)
                    if verbose:
                        state.logger.debug(f'Witness commitment added')

                    num_outputs = len(outputs)
                    if verbose:
                        state.logger.debug(f'Total outputs in coinbase: {num_outputs}')

                    # Full coinbase (witness serialization)
                    coinbase_txin = coinbase_txin_start + coinbase_txin_end
                    state.coinbase_tx = (
                        int(1).to_bytes(4, 'little') +
                        b'\x00\x01' +                     # segwit marker/flag
                        b'\x01' + coinbase_txin +
                        var_int(num_outputs) +
                        b''.join(outputs) +
                        b'\x01\x20' + bytes(32) + bytes(4)  # witness + locktime
                    )

                    # No-witness serialization for txid
                    coinbase_no_wit_full = (
                        int(8).to_bytes(4, 'little') +
                        b'\x01' + coinbase_txin +
                        var_int(num_outputs) +
                        b''.join(outputs) +
                        bytes(4)  # locktime
                    )
                    state.coinbase_txid = dsha256(coinbase_no_wit_full)

                    # Stratum coinbase split (with segwit)
                    state.coinbase1 = (
                        int(1).to_bytes(4, 'little') +
                        b'\x00\x01' +
                        b'\x01' + coinbase_txin_start
                    )
                    state.coinbase2 = (
                        coinbase_txin_end +
                        var_int(num_outputs) +
                        b''.join(outputs) +
                        b'\x01\x20' + bytes(32) + bytes(4)
                    )

                    # No-witness split for txid rebuild in submit
                    state.coinbase1_nowit = (
                        int(8).to_bytes(4, 'little') +
                        b'\x01' + coinbase_txin_start
                    )
                    state.coinbase2_nowit = (
                        coinbase_txin_end +
                        var_int(num_outputs) +
                        b''.join(outputs) +
                        bytes(4)
                    )

                    # Collect txs + merkle (JS-style): leaf = txid = dsha256(coinbase_no_wit)
                    incoming_txs = []
                    txids = [state.coinbase_txid]
                    for tx_data in txs_list:
                        incoming_txs.append(tx_data['data'])
                        txids.append(bytes.fromhex(tx_data['txid'])[::-1])
                    state.externalTxs = incoming_txs

                    merkle = merkle_from_txids(txids)
                    state.coinbase_branch, state.coinbase_index = merkle_branch_from_leaves(txids, 0)
                    state.merkle_branches = state.get_merkle_hashes(state.coinbase_branch)

                    # Prepare header prefix & bits
                    state.bits_le = bytes.fromhex(bits_hex)[::-1]
                    state.header_prefix = (
                        version_int.to_bytes(4, 'little') +
                        state.prevHash +
                        merkle
                    )

                    state.headerHash = None  # not meaningful until nonce/time present
                    state.timestamp = ts

                    state.job_counter += 1
                    add_old_state_to_queue(old_states, original_state, drop_after)

                    if SHOW_JOBS:
                        diff_display = formatDiff(final_target_hex)
                        state.logger.info('New %s job diff %s height %d (using %s target)', state.tag, diff_display, state.height, state.target_source)

                    # Update existing sessions with difficulty & notify
                    for session in state.all_sessions:
                        difficulty = get_target_difficulty(final_target_hex)
                        sent_diff = difficulty / 3000.0  # TEST: easier diff by factor 1e4
                        eff_target = min(POW_LIMIT, int(POW_LIMIT / max(sent_diff, 1e-12)))
                        if verbose:
                            state.logger.debug(f'Updating miner diff {sent_diff} (target: {final_target_hex}) -> shareTarget={eff_target}')
                        setattr(session, "_share_difficulty", float(sent_diff))
                        setattr(session, "_share_target_int", int(eff_target))
                        await session.send_notification('mining.set_difficulty', (float(sent_diff),))

                # Prepare job params for notify
                if state.coinbase1 and state.coinbase2:
                    job_params = [
                        hex(state.job_counter)[2:],                  # jobId
                        state.prevHash[::-1].hex(),                  # previousblockhash (BE)
                        state.coinbase1.hex(),
                        state.coinbase2.hex(),
                        state.merkle_branches,
                        version_int.to_bytes(4, 'big').hex(),       # version (BE)
                        bits_hex,                                    # bits (BE hex)
                        ts.to_bytes(4, 'big').hex(),                # time (BE)
                        True
                    ]

                # Send job notifications to existing sessions
                for session in state.all_sessions:
                    if (new_block or new_witness or state.timestamp + 60 < ts) and job_params:
                        await session.send_notification('mining.notify', job_params)

                # Send notifications to new sessions
                for session in state.new_sessions:
                    state.all_sessions.add(session)
                    difficulty = get_target_difficulty(final_target_hex)
                    sent_diff = difficulty / 3000.0  # TEST ease
                    eff_target = min(POW_LIMIT, int(POW_LIMIT / max(sent_diff, 1e-12)))
                    if verbose:
                        state.logger.debug(f'Sending miner diff {sent_diff} -> shareTarget={eff_target}')
                    setattr(session, "_share_difficulty", float(sent_diff))
                    setattr(session, "_share_target_int", int(eff_target))
                    await session.send_notification('mining.set_difficulty', (float(sent_diff),))
                    if job_params:
                        await session.send_notification('mining.notify', job_params)
                state.new_sessions.clear()

            except Exception as e:
                state.logger.critical('RPC error for getblocktemplate: %s', str(e))
                state.logger.critical('Sleeping for 5 minutes. Solutions may be stale; consider restarting the proxy.')
                await asyncio.sleep(300)


# ----------------------------
# Main
# ----------------------------

def main():
    parser = argparse.ArgumentParser(prog='kcn-lcn-stratum-proxy', description='Stratum proxy to solo mine KCN (parent) with LCN AuxPoW (child).')
    parser.add_argument('--ip', default=os.getenv('PROXY_IP', '127.0.0.1'), help='IP address to bind proxy server on (127.0.0.1=localhost only, 0.0.0.0=all interfaces)')
    parser.add_argument('--port', type=int, default=int(os.getenv('STRATUM_PORT', '54321')), help='listen port (default 54321)')
    parser.add_argument('--rpcip', default=os.getenv('KCN_RPC_IP', '127.0.0.1'), help='KCN node RPC IP')
    parser.add_argument('--rpcport', type=int, help='KCN node RPC port')
    parser.add_argument('--rpcuser', default=os.getenv('KCN_RPC_USER'), help='KCN RPC username')
    parser.add_argument('--rpcpass', default=os.getenv('KCN_RPC_PASS'), help='KCN RPC password')
    parser.add_argument('--aux-rpcip', default=os.getenv('LCN_RPC_IP'), help='LCN node RPC IP')
    parser.add_argument('--aux-rpcport', type=int, help='LCN node RPC port')
    parser.add_argument('--aux-rpcuser', default=os.getenv('LCN_RPC_USER'), help='LCN RPC username')
    parser.add_argument('--aux-rpcpass', default=os.getenv('LCN_RPC_PASS'), help='LCN RPC password')
    parser.add_argument('--aux-address', default=os.getenv('LCN_WALLET_ADDRESS', ''), help='LCN address for createauxblock (leave blank to disable AuxPoW mining)')
    parser.add_argument('--proxy-signature', help='custom proxy signature in coinbase (overrides PROXY_SIGNATURE env var)')
    parser.add_argument('--use-easier-target', action='store_true', default=os.getenv('USE_EASIER_TARGET', 'true').lower() == 'true', help='use easier target between KCN and LCN (may increase block finding rate)')
    parser.add_argument('-t', '--testnet', action='store_true', default=os.getenv('TESTNET', 'false').lower() == 'true', help='use testnet address version for miner address check')
    parser.add_argument('-j', '--jobs', action='store_true', default=os.getenv('SHOW_JOBS', 'false').lower() == 'true', help='show jobs in log')
    parser.add_argument('-v', '--verbose', '--debug', action='store_true', default=os.getenv('VERBOSE', 'false').lower() == 'true', help='debug logging')
    parser.add_argument('--debug-shares', action='store_true', default=os.getenv('DEBUG_SHARES', 'false').lower() == 'true', help='detailed debugging for share submissions and rejections')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')

    args = parser.parse_args()
    global SHOW_JOBS
    SHOW_JOBS = args.jobs or args.verbose

    logger = logging.getLogger('KCN-logger')

    # Set RPC ports from environment if not provided via command line
    if args.rpcport is None:
        env_port = os.getenv('KCN_RPC_PORT')
        if env_port:
            args.rpcport = int(env_port)
        else:
            args.rpcport = 9766 if not args.testnet else 19766

    if args.aux_rpcport is None:
        env_aux_port = os.getenv('LCN_RPC_PORT')
        if env_aux_port:
            args.aux_rpcport = int(env_aux_port)

    # Validate required credentials are provided
    if not args.rpcuser:
        parser.error('KCN RPC username is required (--rpcuser or KCN_RPC_USER environment variable)')
    if not args.rpcpass:
        parser.error('KCN RPC password is required (--rpcpass or KCN_RPC_PASS environment variable)')

    proxy_port = args.port
    proxy_ip = args.ip
    node_url = f'http://{args.rpcuser}:{args.rpcpass}@{args.rpcip}:{args.rpcport}'

    aux_url = None
    if args.aux_rpcip and args.aux_rpcport and args.aux_rpcuser and args.aux_rpcpass:
        aux_url = f'http://{args.aux_rpcuser}:{args.aux_rpcpass}@{args.aux_rpcip}:{args.aux_rpcport}'

    level = 'DEBUG' if args.verbose else 'INFO'
    coloredlogs.install(level=level, milliseconds=True)
    coloredlogs.install(logger=logger, level=level, milliseconds=True)

    # Test Flex algorithm implementation
    logger.info('=== FLEX ALGORITHM TEST ===')
    flex_working, flex_details = test_flex_algorithm()
    if flex_working:
        logger.info(f'✓ {flex_details}')
    else:
        logger.warning(f'⚠️  {flex_details}')
    logger.info('===========================')

    # Log testing/debugging configuration
    skip_flex = os.getenv('SKIP_FLEX_VALIDATION', 'false').lower() == 'true'
    share_multiplier = float(os.getenv('SHARE_DIFFICULTY_MULTIPLIER', '1.0'))
    debug_shares = os.getenv('DEBUG_SHARES', 'false').lower() == 'true'

    logger.info('Testing Configuration:')
    logger.info(f'  Skip Flex Validation: {skip_flex}')
    logger.info(f'  Share Difficulty Multiplier: {share_multiplier}x {"(EASIER TESTING)" if share_multiplier > 1.0 else "(NORMAL)"}')
    logger.info(f'  Debug Share Logging: {debug_shares}')
    logger.info('===========================')

    # Log mining mode
    if aux_url and args.aux_address and args.aux_address.strip():
        logger.info('AuxPoW mode: Mining Kylacoin (primary) + Lyncoin (auxiliary)')
        logger.info(f'Lyncoin address: {args.aux_address}')
    else:
        logger.info('Primary mode: Mining Kylacoin only (AuxPoW disabled)')
        if not aux_url:
            logger.info('Reason: Lyncoin RPC not configured')
        elif not args.aux_address or not args.aux_address.strip():
            logger.info('Reason: Lyncoin address not provided')

    if not os.path.exists('./submit_history'):
        os.mkdir('./submit_history')

    # Shared state
    state = TemplateState()

    # Stores old state info
    historical_states = [list(), dict()]  # (queue, map)
    store = 20

    session_generator = partial(StratumSession, state, historical_states, args.testnet, args.verbose, node_url, aux_url, args.debug_shares)

    async def updateState():
        while True:
            await stateUpdater(state, historical_states, store, args.verbose, node_url, aux_url, args.aux_address, args.use_easier_target, args.proxy_signature)
            await asyncio.sleep(0.1)

    async def beginServing():
        try:
            server = await serve_rs(session_generator, proxy_ip, proxy_port, reuse_address=True)
            logging.info('Serving on {}:{}'.format(*server.sockets[0].getsockname()))
            if args.testnet:
                logging.info('Using testnet')
            await server.serve_forever()
        except Exception as e:
            logger.error('Error starting server: %s', str(e))
            return

    async def execute():
        async with TaskGroup(wait=any) as group:
            await group.spawn(updateState())
            await group.spawn(beginServing())
        for task in group.tasks:
            if not task.cancelled():
                exc = task.exception()
                if exc:
                    raise exc

    asyncio.run(execute())


if __name__ == '__main__':
    main()
