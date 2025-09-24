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

# ----------------------------
# Globals / constants
# ----------------------------
hashratedict = {}
SHOW_JOBS = False

# ----------------------------
# Utility helpers
# ----------------------------

def bech32_decode(bech: str):
    """Simple Bech32 decoder for extracting witness program"""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    
    if not bech:
        return None, None
    
    # Split HRP and data
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None
    
    hrp = bech[:pos]
    data = bech[pos + 1:]
    
    # Decode data part
    decoded = []
    for char in data:
        if char not in CHARSET:
            return None, None
        decoded.append(CHARSET.find(char))
    
    # Convert from 5-bit to 8-bit (simplified)
    if len(decoded) < 6:
        return None, None
        
    # Extract witness version (first byte) and program (remaining bytes converted to 8-bit)
    witver = decoded[0]
    if witver > 16:
        return None, None
    
    # Convert 5-bit groups to bytes (simplified implementation)
    # For production, use proper bech32 library
    converted = []
    acc = 0
    bits = 0
    for value in decoded[1:-6]:  # Exclude checksum
        acc = (acc << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            converted.append((acc >> bits) & 255)
    
    if bits >= 5 or ((acc << (5 - bits)) & 31):
        return None, None
    
    return hrp, bytes(converted)

def var_int(i: int) -> bytes:
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
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
    # Remove 0x prefix if present and convert full target
    clean_target = prune0x(target)
    target_int = int(clean_target, 16)
    
    if target_int == 0:
        return "INF"  # Infinite difficulty for zero target
    
    # Use standard Bitcoin difficulty calculation
    max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    diff = max_target / target_int
    
    UNITS = [(1000000000000, 'T'), (1000000000, 'G'), (1000000, 'M'), (1000, 'K')]
    for l, u in UNITS:
        if diff > l:
            return '{:.5f}{}'.format(diff / l, u)
    
    # If diff is less than 1000, show as plain number
    return '{:.5f}'.format(diff)


def compare_targets(kcn_target: str, aux_target: Optional[str]) -> str:
    """
    Compare Kylacoin and Lyncoin targets and return the easier one.
    Lower target value = higher difficulty, so we want the higher target value (easier).
    """
    if not aux_target:
        return kcn_target
    
    # Convert targets to integers for comparison
    kcn_int = int(kcn_target, 16)
    aux_int = int(aux_target, 16)
    
    # Higher target value = easier difficulty
    if aux_int > kcn_int:
        return aux_target
    else:
        return kcn_target


def get_target_difficulty(target: str) -> float:
    """Calculate difficulty from target"""
    # Remove 0x prefix if present
    clean_target = prune0x(target)
    
    # Convert full target to integer to avoid division by zero
    target_int = int(clean_target, 16)
    if target_int == 0:
        return float('inf')  # Maximum difficulty for zero target
    
    # Use standard Bitcoin difficulty calculation: max_target / current_target
    # Max target is 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    return max_target / target_int


def prune0x(s: str) -> str:
    return s[2:] if s.startswith('0x') else s


def process_aux_target(target_hash: str) -> str:
    """
    Process auxiliary target hash similar to JavaScript utils.uint256BufferFromHash
    Equivalent to:
    let fromHex = Buffer.from(hex, 'hex');
    if (fromHex.length != 32) {
      const empty = Buffer.alloc(32);
      empty.fill(0);
      fromHex.copy(empty);
      fromHex = empty;
    }
    return exports.reverseBuffer(fromHex);
    """
    if not target_hash:
        return target_hash
    
    # Remove 0x prefix if present
    clean_hash = prune0x(target_hash)
    
    # Convert hex string to bytes
    from_hex = bytes.fromhex(clean_hash)
    
    # If length != 32 bytes, create 32-byte buffer filled with zeros and copy data
    if len(from_hex) != 32:
        empty = bytearray(32)  # 32 bytes filled with zeros
        # Copy the original data to the beginning of the empty buffer
        copy_len = min(len(from_hex), 32)
        empty[:copy_len] = from_hex[:copy_len]
        from_hex = bytes(empty)
    
    # Reverse the buffer (equivalent to reverseBuffer)
    reversed_bytes = from_hex[::-1]
    
    # Convert back to hex string
    return reversed_bytes.hex()


def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b).digest()).digest()


def merkle_from_txids(txids: List[bytes]) -> bytes:
    # Returns merkle root from little-endian txids
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
    # Build branch (list of sibling hashes) from leaf to root; leaves are LE txids
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


# ----------------------------
# AuxPoW structures
# ----------------------------
@dataclass
class AuxJob:
    symbol: str
    url: str
    aux_hash: str       # hex, big-endian string from getauxblock
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
    Standard Namecoin-style AuxPoW serialization used by many AuxPoW forks:
      coinbase_tx | coinbase_merkle_branch | coinbase_branch_index | parent_header | aux_merkle_branch | aux_branch_index
    For single-leaf aux tree: aux_branch is empty, aux_index = 0.
    Fields mm_nonce and mm_tree_size live in the coinbase scriptSig tag, not here.
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
    header: Optional[bytes] = None
    coinbase_tx: Optional[bytes] = None
    coinbase_txid: Optional[bytes] = None
    
    # Stratum coinbase split for mining.notify
    coinbase1: Optional[bytes] = None  # Coinbase part 1 (before extranonce)
    coinbase2: Optional[bytes] = None  # Coinbase part 2 (after extranonce)
    merkle_branches: List[str] = []    # Merkle branch hashes for stratum

    # AuxPoW (Lyncoin) related
    aux_job: Optional[AuxJob] = None
    aux_root: Optional[bytes] = None  # single-leaf => dsha256(LE(aux_hash))
    mm_nonce: int = 0
    mm_tree_size: int = 0
    aux_last_update: int = 0  # Timestamp of last aux job update

    # coinbase -> merkle root path for AuxPoW proof
    coinbase_branch: List[bytes] = []
    coinbase_index: int = 0

    current_commitment: Optional[str] = None

    new_sessions: Set[RPCSession] = set()
    all_sessions: Set[RPCSession] = set()

    awaiting_update = False

    job_counter = 0
    bits_counter = 0

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
            f'Header:\t\t{self.header.hex() if self.header else None}\nCoinbase:\t\t{self.coinbase_tx.hex() if self.coinbase_tx else None}\n'
            f'Coinbase txid:\t\t{self.coinbase_txid.hex() if self.coinbase_txid else None}\nAux job:\t\t{self.aux_job}\n'
            f'New sessions:\t\t{self.new_sessions}\nSessions:\t\t{self.all_sessions}'
        )

    def build_block(self, nonce: str) -> str:
        # Flex algorithm block: header (76 bytes) + nonce (4 bytes) + transactions
        # Full header for Flex is header + nonce = 80 bytes total
        return (
            self.header.hex()
            + nonce
            + var_int(len(self.externalTxs) + 1).hex()
            + self.coinbase_tx.hex()
            + ''.join(self.externalTxs)
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

    def __init__(self, state: TemplateState, old_states, testnet: bool, verbose: bool, node_url: str, aux_url: Optional[str], transport):
        connection = JSONRPCConnection(JSONRPCv1)
        super().__init__(transport, connection=connection)
        self._state = state
        self._testnet = testnet
        self._verbose = verbose
        self._old_states = old_states
        self._client_addr = transport._remote_address
        self._transport = transport
        self._node_url = node_url
        self._aux_url = aux_url

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
        
        # Return proper stratum subscription format with subscription IDs
        extranonce1 = self._state.bits_counter.to_bytes(2, 'big').hex()
        extranonce2_size = 2
        
        return [
            [
                ["mining.set_difficulty", subscription_id],
                ["mining.notify", subscription_id]
            ],
            extranonce1,
            extranonce2_size
        ]

    async def handle_authorize(self, username: str, password: str):
        # First address that connects becomes payout address
        address = username.split('.')[0]
        
        # Handle different address formats
        pub_h160 = None
        
        try:
            # Try Bech32 format first (kc1q... for mainnet, tkc1q... for testnet)
            if address.startswith('kc1') or address.startswith('tkc1'):
                # Bech32 address - extract pubkey hash
                if address.startswith('tkc1') and not self._testnet:
                    raise RPCError(20, f'Testnet address {address} not allowed on mainnet')
                if address.startswith('kc1') and self._testnet:
                    raise RPCError(20, f'Mainnet address {address} not allowed on testnet')
                
                # Decode Bech32 address
                hrp, witness_program = bech32_decode(address)
                if hrp is None or witness_program is None:
                    raise RPCError(20, f'Invalid Bech32 address: {address}')
                
                # Verify HRP matches network
                expected_hrp = 'tkc' if self._testnet else 'kc'
                if hrp != expected_hrp:
                    raise RPCError(20, f'Wrong network for address {address}')
                
                # For P2WPKH (witness version 0, 20-byte program)
                if len(witness_program) == 20:
                    pub_h160 = witness_program
                else:
                    raise RPCError(20, f'Unsupported witness program length: {len(witness_program)}')
                    
            else:
                # Try legacy Base58Check format
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
        
        # Store the pubkey hash for coinbase construction
        if not self._state.pub_h160:
            self._state.pub_h160 = pub_h160
            
        return True

    async def handle_configure(self, extensions):
        """Handle mining.configure - miner capability negotiation"""
        if self._verbose:
            self.logger.debug('Miner configure request: %s', extensions)
        
        # Return empty result - we don't support any special extensions yet
        # But this prevents miners from erroring on unsupported method
        return {}

    async def handle_submit(self, worker: str, job_id: str, extranonce2_hex: str, ntime_hex: str, nonce_hex: str):
        if self._verbose:
            self.logger.debug('Possible solution for worker %s submitting block for job %s nonce %s', worker, job_id, nonce_hex)

        state = self._state
        if job_id != hex(state.job_counter)[2:]:
            if self._verbose:
                self.logger.error('An old job was submitted, trying old states')
            old_state = lookup_old_state(self._old_states, job_id)
            if old_state is not None:
                state = old_state
            else:
                self.logger.error('Miner submitted an old job that we did not have')

        nonce_hex = bytes.fromhex(prune0x(nonce_hex))[::-1].hex()

        block_hex = state.build_block(nonce_hex)
        
        # Validate solution against the target that was used for mining
        # Flex algorithm uses 80-byte header (76 + 4 nonce)
        block_header = bytes.fromhex(block_hex[:160])  # First 80 bytes of block (160 hex chars)
        block_hash = dsha256(block_header)
        block_hash_int = int.from_bytes(block_hash, 'little')
        mining_target_int = int(state.target, 16)
        
        if block_hash_int > mining_target_int:
            self.logger.error('Solution does not meet mining target difficulty')
            return False
        
        # Determine submission strategy based on which target was used
        using_aux_target = (hasattr(state, 'aux_job') and state.aux_job and 
                           state.aux_job.target and state.target == state.aux_job.target)
        
        submit_to_kcn = True
        submit_to_aux = True
        
        if using_aux_target:
            # Using easier Lyncoin target - check if it also meets Kylacoin target
            kcn_target_int = int(getattr(state, 'kcn_original_target', state.target), 16)
            meets_kcn_difficulty = block_hash_int <= kcn_target_int
            
            if meets_kcn_difficulty:
                self.logger.info('Solution meets both Lyncoin (easier) and Kylacoin (harder) targets - submitting to both')
                submit_to_kcn = True
                submit_to_aux = True
            else:
                self.logger.info('Solution meets Lyncoin target only - submitting to Lyncoin only')
                submit_to_kcn = False
                submit_to_aux = True
        else:
            # Using Kylacoin target - always submit to both chains
            self.logger.info('Using Kylacoin target - submitting to both chains')

        # Submit to Kylacoin if appropriate
        if submit_to_kcn:
            data = {'jsonrpc': '2.0', 'id': '0', 'method': 'submitblock', 'params': [block_hex]}
            async with ClientSession() as session:
                async with session.post(f'{self._node_url}', data=json.dumps(data)) as resp:
                    json_resp = await resp.json()
                    if not os.path.exists('./submit_history'):
                        os.mkdir('./submit_history')
                    with open(f'./submit_history/{state.height}_{state.job_counter}.txt', 'w') as f:
                        dump = f'Response:\n{json.dumps(json_resp, indent=2)}\n\nState:\n{state.__repr__()}'
                        f.write(dump)

                    if json_resp.get('error', None):
                        self.logger.error('KCN RPC error (%d): %s', json_resp['error']['code'], json_resp['error']['message'])

                    result = json_resp.get('result', None)
                    if self._verbose:
                        if result == 'inconclusive':
                            self.logger.error('KCN block submission failed: inconclusive')
                        elif result == 'duplicate':
                            self.logger.error('KCN block submission failed: duplicate')
                        elif result == 'duplicate-inconclusive':
                            self.logger.error('KCN block submission failed: duplicate-inconclusive')
                        elif result == 'inconclusive-not-best-prevblk':
                            self.logger.error('KCN block submission failed: inconclusive-not-best-prevblk')
                    if result not in (None, 'inconclusive', 'duplicate', 'duplicate-inconclusive', 'inconclusive-not-best-prevblk'):
                        self.logger.error('KCN block submission failed: %s', json.dumps(json_resp))

        # Get height from block hex (Flex header layout: version|prev|merkle|time|bits|height)
        # Height is at offset 72-76 in the header (before nonce)
        block_height = int.from_bytes(bytes.fromhex(block_hex[(4+32+32+4+4)*2:(4+32+32+4+4+4)*2]), 'little', signed=False)
        
        chains_submitted = []
        if submit_to_kcn:
            chains_submitted.append('KCN')
        if submit_to_aux:
            chains_submitted.append('LCN')
        
        msg = f'Found block {block_height} - submitted to: {", ".join(chains_submitted)}'
        self.logger.info(msg)
        await self.send_notification('client.show_message', (msg,))

        # Submit to Lyncoin AuxPoW if appropriate
        if submit_to_aux and state.aux_job and self._aux_url:
            try:
                auxpow_hex = build_auxpow_blob(
                    coinbase_tx=state.coinbase_tx,
                    coinbase_branch=state.coinbase_branch,
                    coinbase_index=state.coinbase_index,
                    parent_header=state.header,
                    aux_branch=[],
                    aux_index=0,
                )
                data_aux = {'jsonrpc': '2.0', 'id': '0', 'method': 'submitauxblock', 'params': [state.aux_job.aux_hash, auxpow_hex]}
                async with ClientSession() as session:
                    async with session.post(self._aux_url, data=json.dumps(data_aux)) as resp:
                        js = await resp.json()
                        if js.get('error'):
                            self.logger.error('LCN submitauxblock error: %s', js['error'])
                        else:
                            self.logger.info('LCN submitauxblock result: %s', js.get('result'))
            except Exception as e:
                self.logger.error('LCN AuxPoW submit failed: %s', str(e))

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
async def refresh_aux_job(state: TemplateState, session: ClientSession, aux_url: Optional[str], aux_address: str = 'lc1q44hvy3fg7rka5k9c0waqdu8yw3q4cca6fnxlff', force_update: bool = False):
    # Pull Lyncoin createauxblock and compute single-leaf root
    if not aux_url:
        state.aux_job = None
        state.aux_root = None
        state.mm_tree_size = 0
        state.aux_last_update = 0
        return
    
    # Only update aux job every 30 seconds unless forced (e.g., new block)
    current_time = int(time.time())
    if not force_update and state.aux_job and (current_time - state.aux_last_update) < 30:
        return
    
    # Use createauxblock with the specified address
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
        
        # Get raw target from response
        raw_target = r.get('_target') or r.get('target') or r.get('bits')
        
        # Process target similar to JavaScript utils.uint256BufferFromHash
        processed_target = process_aux_target(raw_target) if raw_target else raw_target
        
        # Debug: Log what we're getting from createauxblock
        state.logger.debug(f"Lyncoin createauxblock response: _target={r.get('_target')}, target={r.get('target')}, bits={r.get('bits')}")
        state.logger.debug(f"Raw target: {raw_target}, Processed target: {processed_target}")
        
        job = AuxJob(
            symbol='LCN', 
            url=aux_url, 
            aux_hash=r['hash'], 
            target=processed_target, 
            chain_id=r.get('chainid')
        )
        # Check if aux job actually changed
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

async def stateUpdater(state: TemplateState, old_states, drop_after, verbose, node_url: str, aux_url: Optional[str], aux_address: str = 'lc1q44hvy3fg7rka5k9c0waqdu8yw3q4cca6fnxlff', use_easier_target: bool = False, proxy_signature: Optional[str] = None):
    if not state.pub_h160:
        return
    data = {'jsonrpc': '2.0', 'id': '0', 'method': 'getblocktemplate', 'params': [{"rules": ["segwit"]}]}
    async with ClientSession() as session:
        async with session.post(f'{node_url}', data=json.dumps(data)) as resp:
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
                
                # Handle coinbasedevreward if present
                coinbase_devreward = json_obj['result'].get('coinbasedevreward')
                dev_address = None
                dev_sats_int = 0
                if coinbase_devreward:
                    dev_sats_int = coinbase_devreward['value']
                    dev_address = coinbase_devreward['address']
                
                # Handle community autonomous if present (fallback for older format)
                community_address = json_obj['result'].get('CommunityAutonomousAddress')
                community_sats_int = json_obj['result'].get('CommunityAutonomousValue', 0)

                ts = int(time.time())
                new_witness = witness_hex != state.current_commitment
                state.current_commitment = witness_hex
                # Note: target will be set after aux job update for proper comparison
                state.bits = bits_hex
                state.version = version_int
                state.prevHash = bytes.fromhex(prev_hash_hex)[::-1]

                new_block = False
                original_state = None

                # New block?
                if state.height == -1 or state.height != height_int:
                    original_state = deepcopy(state)
                    if verbose:
                        state.logger.info('%s New block, updating state', state.tag)
                    new_block = True

                    state.height = height_int

                # Update Lyncoin aux job when rolling parent jobs or periodically
                # Force update on new blocks, otherwise use rate limiting
                await refresh_aux_job(state, session, aux_url, aux_address, force_update=new_block)

                # Target selection logic
                final_target = target_hex  # Default to Kylacoin target
                state.kcn_original_target = target_hex  # Always store original Kylacoin target
                new_target_source = "KCN"  # Track which chain's target we're using
                
                if use_easier_target and state.aux_job and state.aux_job.target:
                    aux_target = state.aux_job.target
                    
                    # Debug logging to see target values
                    if new_block or not hasattr(state, '_last_debug_kcn') or state._last_debug_kcn != target_hex:
                        state.logger.debug(f'Target comparison: KCN={target_hex}, LCN={aux_target}')
                        state.logger.debug(f'KCN int: {int(target_hex, 16)}, LCN int: {int(aux_target, 16)}')
                        state._last_debug_kcn = target_hex
                    
                    final_target = compare_targets(target_hex, aux_target)
                    
                    if final_target != target_hex:
                        new_target_source = "LCN"
                
                # Only log target selection if it changed or on new blocks
                target_changed = (state.target != final_target or 
                                state.target_source != new_target_source or 
                                new_block)
                
                if target_changed:
                    state.target_source = new_target_source
                    kcn_diff = get_target_difficulty(target_hex)
                    
                    if use_easier_target and state.aux_job and state.aux_job.target:
                        aux_diff = get_target_difficulty(state.aux_job.target)
                        kcn_formatted = formatDiff(target_hex)
                        aux_formatted = formatDiff(state.aux_job.target)
                        
                        if final_target != target_hex:
                            state.logger.info(f'Using easier Lyncoin target: KCN diff={kcn_formatted}, LCN diff={aux_formatted}')
                        else:
                            state.logger.info(f'Using Kylacoin target (harder): KCN diff={kcn_formatted}, LCN diff={aux_formatted}')
                    else:
                        # Not using easier target mode or no aux job
                        kcn_formatted = formatDiff(target_hex)
                        if state.aux_job and state.aux_job.target:
                            aux_formatted = formatDiff(state.aux_job.target)
                            state.logger.info(f'Using Kylacoin target: KCN diff={kcn_formatted}, LCN diff={aux_formatted}')
                        else:
                            state.logger.info(f'Using Kylacoin target: diff={kcn_formatted} (no aux job)')
                else:
                    # Target didn't change, just update the target_source variable
                    state.target_source = new_target_source
                    
                # Update state with selected target
                state.target = final_target
                final_target_hex = final_target

                # Prepare job parameters (will be updated if job rolls)
                job_params = None
                
                # Roll job if new block, new witness, or stale timestamp
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

                    # AuxPoW tag in scriptSig (no extra fees in vouts)
                    mm_tag = b''
                    if state.aux_root:
                        mm_magic = bytes([0xFA, 0xBE, 0x6D, 0x6D])
                        aux_root_le = state.aux_root[::-1]
                        mm_tag = (mm_magic + aux_root_le + state.mm_tree_size.to_bytes(4, 'little') + state.mm_nonce.to_bytes(4, 'little'))

                    # Get proxy signature from parameter, environment, or use default
                    sig_str = proxy_signature or os.getenv('PROXY_SIGNATURE', '/kcn-lcn-stratum-proxy/')
                    proxy_sig = sig_str.encode('utf-8')
                    arbitrary_data = mm_tag + proxy_sig

                    coinbase_script = (
                        op_push(len(bip34_height)) + bip34_height +
                        op_push(len(arbitrary_data)) + arbitrary_data
                    )

                    # For stratum, we need to split coinbase around extranonce space
                    # Coinbase1: version + witness flag + input count + prevout + sequence + script_len + bip34_height + extranonce1_len
                    # Extranonce space (will be filled by miner)  
                    # Coinbase2: extranonce2_len + remaining script + sequence + outputs + witness + locktime
                    
                    coinbase_txin_start = bytes(32) + b'\xff' * 4 + var_int(len(coinbase_script)) + coinbase_script
                    coinbase_txin_end = b'\xff' * 4

                    vout_to_miner = b'\x76\xa9\x14' + state.pub_h160 + b'\x88\xac'
                    
                    # Build outputs list
                    outputs = []
                    
                    # Miner output
                    outputs.append(coinbase_sats_int.to_bytes(8, 'little') + op_push(len(vout_to_miner)) + vout_to_miner)
                    if verbose:
                        state.logger.debug(f'Miner output: {coinbase_sats_int} satoshis')
                    
                    # Developer reward output (if present)
                    if dev_address and dev_sats_int > 0:
                        try:
                            # Use scriptpubkey from the response (most reliable)
                            if 'scriptpubkey' in coinbase_devreward:
                                dev_script = bytes.fromhex(coinbase_devreward['scriptpubkey'])
                                outputs.append(dev_sats_int.to_bytes(8, 'little') + op_push(len(dev_script)) + dev_script)
                                if verbose:
                                    state.logger.debug(f'Dev reward output: {dev_sats_int} satoshis to {dev_address}')
                            else:
                                state.logger.warning(f'No scriptpubkey provided for dev address {dev_address}')
                        except Exception as e:
                            state.logger.warning(f'Could not parse dev reward: {e}')
                    
                    # Community output (if present and different from dev)
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

                    # Build full coinbase transaction for internal use
                    coinbase_txin = coinbase_txin_start + coinbase_txin_end
                    
                    state.coinbase_tx = (
                        int(1).to_bytes(4, 'little') +
                        b'\x00\x01' +
                        b'\x01' + coinbase_txin +
                        var_int(num_outputs) +
                        b''.join(outputs) +
                        b'\x01\x20' + bytes(32) + bytes(4)
                    )

                    coinbase_no_wit = (
                        int(1).to_bytes(4, 'little') +
                        b'\x01' + coinbase_txin +
                        var_int(num_outputs) +
                        b''.join(outputs) +
                        bytes(4)
                    )
                    
                    # Build stratum coinbase split (coinbase1 + extranonce + coinbase2)
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
                    state.coinbase_txid = dsha256(coinbase_no_wit)

                    # Collect txs + merkle
                    incoming_txs = []
                    txids = [state.coinbase_txid]
                    for tx_data in txs_list:
                        incoming_txs.append(tx_data['data'])
                        txids.append(bytes.fromhex(tx_data['txid'])[::-1])
                    state.externalTxs = incoming_txs

                    merkle = merkle_from_txids(txids)
                    # AuxPoW needs coinbase branch/index
                    state.coinbase_branch, state.coinbase_index = merkle_branch_from_leaves(txids, 0)
                    # Convert merkle branches to stratum format
                    state.merkle_branches = state.get_merkle_hashes(state.coinbase_branch)

                    # Parent header layout: version|prev|merkle|time|bits|height (Flex algorithm - 76 bytes without nonce/mixhash)
                    state.header = (
                        version_int.to_bytes(4, 'little') +
                        state.prevHash +
                        merkle +
                        ts.to_bytes(4, 'little') +
                        bytes.fromhex(bits_hex)[::-1] +
                        state.height.to_bytes(4, 'little')
                    )

                    state.headerHash = dsha256(state.header)[::-1].hex()
                    state.timestamp = ts

                    state.job_counter += 1
                    add_old_state_to_queue(old_states, original_state, drop_after)

                    if SHOW_JOBS:
                        diff_display = formatDiff(final_target_hex)
                        state.logger.info('New %s job diff %s height %d (using %s target)', state.tag, diff_display, state.height, state.target_source)

                    for session in state.all_sessions:
                        # Calculate difficulty for miners that expect it
                        difficulty = get_target_difficulty(final_target_hex)
                        if verbose:
                            state.logger.debug(f'Updating difficulty {difficulty} (target: {final_target_hex}) for existing session')
                        await session.send_notification('mining.set_difficulty', (difficulty,))

                # Prepare job parameters in correct stratum format (if coinbase is ready)
                job_params = None
                if state.coinbase1 and state.coinbase2:
                    job_params = [
                        hex(state.job_counter)[2:],  # jobId
                        state.prevHash[::-1].hex(),  # previousblockhash (big-endian)
                        state.coinbase1.hex(),       # coinbase1
                        state.coinbase2.hex(),       # coinbase2
                        state.merkle_branches,       # merkle branches
                        version_int.to_bytes(4, 'big').hex(),  # version (big-endian)
                        bits_hex,                    # bits
                        ts.to_bytes(4, 'big').hex(), # time (big-endian)
                        True                         # clean_jobs
                    ]

                # Send job notifications to existing sessions
                for session in state.all_sessions:
                    if (new_block or new_witness or state.timestamp + 60 < ts) and job_params:
                        await session.send_notification('mining.notify', job_params)

                # Send notifications to new sessions
                for session in state.new_sessions:
                    state.all_sessions.add(session)
                    # Calculate difficulty for miners that expect it
                    difficulty = get_target_difficulty(final_target_hex)
                    if verbose:
                        state.logger.debug(f'Sending difficulty {difficulty} (target: {final_target_hex}) to new session')
                    await session.send_notification('mining.set_difficulty', (difficulty,))
                    if job_params:  # Only send if coinbase is ready
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
    parser.add_argument('--aux-address', default=os.getenv('LCN_WALLET_ADDRESS', 'lc1q44hvy3fg7rka5k9c0waqdu8yw3q4cca6fnxlff'), help='LCN address for createauxblock')
    parser.add_argument('--proxy-signature', help='custom proxy signature in coinbase (overrides PROXY_SIGNATURE env var)')
    parser.add_argument('--use-easier-target', action='store_true', default=os.getenv('USE_EASIER_TARGET', 'true').lower() == 'true', help='use easier target between KCN and LCN (may increase block finding rate)')
    parser.add_argument('-t', '--testnet', action='store_true', default=os.getenv('TESTNET', 'false').lower() == 'true', help='use testnet address version for miner address check')
    parser.add_argument('-j', '--jobs', action='store_true', default=os.getenv('SHOW_JOBS', 'false').lower() == 'true', help='show jobs in log')
    parser.add_argument('-v', '--verbose', '--debug', action='store_true', default=os.getenv('VERBOSE', 'false').lower() == 'true', help='debug logging')
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
            # Use defaults based on testnet setting
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

    if not os.path.exists('./submit_history'):
        os.mkdir('./submit_history')

    # Shared state
    state = TemplateState()

    # Stores old state info
    historical_states = [list(), dict()]  # (queue, map)
    store = 20

    session_generator = partial(StratumSession, state, historical_states, args.testnet, args.verbose, node_url, aux_url)

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
