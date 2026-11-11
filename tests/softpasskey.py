"""A software passkey for tests: produces real WebAuthn registration and assertion
responses (ES256, attestation "none") so the executor's verification runs for real."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftPasskey:
    def __init__(self, rp_id: str, origin: str, user_verified: bool = True):
        self.rp_id, self.origin, self.uv = rp_id, origin, user_verified
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.counter = 0

    def _client_data(self, kind: str, challenge_b64u: str, origin: str | None = None) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge_b64u,
                           "origin": origin or self.origin, "crossOrigin": False}).encode()

    def _flags(self, attested: bool) -> bytes:
        return bytes([0x01 | (0x04 if self.uv else 0) | (0x40 if attested else 0)])

    def register(self, options: dict) -> dict:
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"),
                            -3: nums.y.to_bytes(32, "big")})
        auth = (hashlib.sha256(self.rp_id.encode()).digest() + self._flags(True)
                + struct.pack(">I", 0) + bytes(16) + struct.pack(">H", len(self.cred_id))
                + self.cred_id + cose)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        client = self._client_data("webauthn.create", options["challenge"])
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "attestationObject": b64u(att)}}

    def sign(self, options: dict, origin: str | None = None,
             challenge: str | None = None) -> dict:
        auth = (hashlib.sha256(self.rp_id.encode()).digest() + self._flags(False)
                + struct.pack(">I", self.counter))
        client = self._client_data("webauthn.get", challenge or options["challenge"], origin)
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "authenticatorData": b64u(auth),
                             "signature": b64u(sig)}}
