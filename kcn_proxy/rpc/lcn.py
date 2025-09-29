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
