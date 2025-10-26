import json


async def getblocktemplate(session, node_url: str):
    data = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": "getblocktemplate",
        "params": [{"rules": ["segwit"]}],
    }
    async with session.post(node_url, data=json.dumps(data)) as resp:
        return await resp.json()


async def submitblock(session, node_url: str, block_hex: str):
    data = {"jsonrpc": "2.0", "id": "0", "method": "submitblock", "params": [block_hex]}
    async with session.post(node_url, data=json.dumps(data)) as resp:
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
