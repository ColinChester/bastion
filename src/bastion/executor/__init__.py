"""The executor (Phase 3): the only part of Bastion that changes the system.

It runs inside bastiond and accepts a fixed set of typed actions. Every request is
checked here, on the Mac, regardless of what the orchestrator or gateway decided:

- commands must carry a valid Ed25519 signature from the gateway, a fresh nonce and a
  short expiry
- each action validates its own target (protected processes, allowed folders, identity)
- automatic actions are reversible (tier 1), rate-limited, and only logged while in
  shadow mode
- destructive actions (tier 2), and anything not marked automatic, wait for a passkey
  approval that is cryptographically bound to the exact stored request
- everything is written to an append-only, hash-chained audit log, with an undo record
"""
