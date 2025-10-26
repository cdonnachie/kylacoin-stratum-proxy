import json


async def submitauxblock(session, aux_url: str, aux_hash: str, auxpow_hex: str):
    data = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": "submitauxblock",
        "params": [aux_hash, auxpow_hex],
    }
    async with session.post(aux_url, data=json.dumps(data)) as resp:
        return await resp.json()


async def getauxblock(session, aux_url: str, aux_hash: str):
    """Query an auxblock for confirmation status"""
    data = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": "getauxblock",
        "params": [aux_hash],
    }
    async with session.post(aux_url, data=json.dumps(data)) as resp:
        return await resp.json()


async def getblock(session, node_url: str, block_hash: str):
    """Query a block for confirmation status"""
    data = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": "getblock",
        "params": [block_hash],
    }
    async with session.post(node_url, data=json.dumps(data)) as resp:
        return await resp.json()


async def getblocktemplate(session, aux_url: str):
    """Get block template for LCN (for block reward extraction)"""
    data = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": "getblocktemplate",
        "params": [{"rules": ["segwit"]}],
    }
    async with session.post(aux_url, data=json.dumps(data)) as resp:
        return await resp.json()
