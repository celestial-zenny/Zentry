"""Solana JSON-RPC client. Only needs `requests`; no web3/solana-py.

getAccountInfo is the single call this tool depends on, and it needs no API key
on the public mainnet endpoint.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass

import requests

DEFAULT_ENDPOINT = "https://api.mainnet-beta.solana.com"

# Chosen because none of these require an API key.
CLUSTERS = {
    "mainnet": "https://api.mainnet-beta.solana.com",
    "devnet": "https://api.devnet.solana.com",
    "testnet": "https://api.testnet.solana.com",
}


class RpcError(RuntimeError):
    pass


@dataclass
class Account:
    pubkey: str
    owner: str
    lamports: int
    executable: bool
    data: bytes


class Rpc:
    def __init__(self, endpoint: str = DEFAULT_ENDPOINT, timeout: int = 20, retries: int = 3):
        self.endpoint = CLUSTERS.get(endpoint, endpoint)
        self.timeout = timeout
        self.retries = retries
        self._session = requests.Session()
        self._session.headers["Content-Type"] = "application/json"
        self.calls = 0

    def _post(self, method: str, params: list) -> dict:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        last: Exception | None = None
        for attempt in range(self.retries):
            try:
                self.calls += 1
                r = self._session.post(self.endpoint, json=payload, timeout=self.timeout)
                if r.status_code == 429:  # public endpoint rate limit
                    time.sleep(1.5 * (attempt + 1))
                    last = RpcError("429 rate limited")
                    continue
                r.raise_for_status()
                body = r.json()
                if "error" in body:
                    raise RpcError(f"{method}: {body['error'].get('message', body['error'])}")
                return body["result"]
            except (requests.RequestException, ValueError) as exc:
                last = exc
                time.sleep(0.6 * (attempt + 1))
        raise RpcError(f"{method} failed after {self.retries} attempts: {last}")

    def get_account(self, pubkey: str) -> Account | None:
        """None means the account does not exist on chain."""
        res = self._post("getAccountInfo", [pubkey, {"encoding": "base64"}])
        val = res.get("value") if isinstance(res, dict) else None
        if not val:
            return None
        return Account(
            pubkey=pubkey,
            owner=val["owner"],
            lamports=val.get("lamports", 0),
            executable=val.get("executable", False),
            data=base64.b64decode(val["data"][0]) if val.get("data") else b"",
        )

    def health(self) -> str:
        try:
            return str(self._post("getHealth", []))
        except RpcError as exc:
            return f"unhealthy: {exc}"
