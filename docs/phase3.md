# Phase 3: actions, approvals and undo

Phase 3 is the first time Bastion can change the Mac. It can do three reversible things
on its own, and two permanent things only after you approve them with a passkey.

It starts in **shadow mode**: every action is decided and logged exactly as it would be
live, and nothing is changed. After 14 clean days you switch it on yourself.

```
containers (OrbStack)                                  bastiond (root, on the Mac)
┌────────────────────────────────────────────┐        ┌────────────────────────────────┐
│ core: agents propose an action name        │        │ executor                       │
│   │  (never a target)                      │        │  1. verify the signature       │
│   ▼                                        │ signed │  2. re-check the target        │
│ gateway: look up the detection, derive the │command │  3. shadow? log only           │
│   target, ask the Cedar policy, sign       │───────▶│  4. automatic and tier 1? run  │
│   (only container with the signing key)    │        │     otherwise wait for passkey │
│ web: Approvals page, passkey prompts       │───────▶│  5. write the audit log        │
└────────────────────────────────────────────┘ passkey└────────────────────────────────┘
```

## What it can do

| Action | Tier | What happens | Undo |
| --- | --- | --- | --- |
| Pause a program (`suspend_process`) | 1 | `SIGSTOP`: frozen, not killed | resume it |
| Quarantine a file (`quarantine_file`) | 1 | moved to a root-only vault, hash recorded | moved back with its permissions |
| Disable a launch item (`disable_launch_item`) | 1 | unloaded and renamed `.plist.disabled` | renamed back and reloaded |
| Delete a quarantined file (`delete_quarantined`) | 2 | removed from the vault | none |
| Delete a disabled launch item (`delete_disabled_item`) | 2 | the `.disabled` file is removed | none |

Tier 2 only ever applies to something tier 1 already contained. There is no "kill" and
no "delete this path".

## How a decision is made

1. An agent's finding lists action names it proposes. Its free-text "target" is ignored.
2. The gateway fetches the detection from bastiond itself and takes the target from it
   (`core/playbook.py`): the detection's own process, its binary, or its launch item.
3. The gateway asks the Cedar policy in [`policy/bastion.cedar`](../policy/bastion.cedar):
   - **automatic** when the owning agent says *malicious* at 80 % confidence or more and
     the rule isn't low severity;
   - **needs approval** when the verdict is *suspicious* or *malicious* but that bar isn't
     met, and always for tier 2;
   - **denied** otherwise (benign or inconclusive verdicts, the wrong agent, system
     files, Bastion's own tools).
4. Allowed commands are signed (Ed25519) with a 2-minute lifetime and a one-time id.
5. The executor verifies the signature and re-checks the target without trusting the
   gateway: path rules, protected programs and labels, size limits, and that the process
   is still the same program at the same pid.
6. After an automatic quarantine or disable, the gateway files a tier 2 request so you
   can delete the item for good, or undo it, from the Approvals page.

## Approvals

Approvals are WebAuthn passkeys, verified by bastiond on the Mac, not by the console.
The challenge you sign includes a hash of the exact action and target, so an approval
can't be replayed or moved to a different request. Requests expire after 7 days.

- Register a device: `sudo bastion passkey enroll` prints a one-time 8-digit code
  (10 minutes, 5 tries); enter it at `/enroll` in the console on that device.
- Approve, deny or undo on the console's **Approvals and actions** page. Undo needs the
  passkey too. Deny doesn't.
- No phone to hand: `sudo bastion approve|deny|undo ID` on the Mac. Root is already able
  to do anything, so the terminal needs no passkey.

## Shadow mode and going live

```bash
sudo bastion autonomy            # mode, shadow day, passkeys, pending approvals
sudo bastion actions             # what it did, or would have done
sudo bastion autonomy on         # go live (refuses before day 15 unless --force)
sudo bastion autonomy off        # back to shadow at any time
```

Only this root command changes the mode. No model, container or web request can.
In shadow mode, approval requests are still real: approving one runs it, because you
decided it. The Phase 3 gate is **zero unwanted shadow actions over the 14 days**.

Other limits enforced by the executor: at most 5 automatic actions per hour (more than
that becomes "not acting"), and the same action on the same target is done once even when
several detections fire for one event.

## The audit log

Every command, refusal, approval, denial, action and undo is appended to a hash-chained
log in `executor.db`. `sudo bastion audit --verify` recomputes the chain and reports the
first altered or missing entry; `sudo bastion doctor` runs the same check.

## Setup

```bash
./scripts/setup-phase3.sh
sudo bastion passkey enroll      # then open https://<mac>.<tailnet>.ts.net/enroll
```

The script creates the signing key (it stays in `deploy/.env.gateway`, never printed),
gives bastiond the public half, starts the gateway container and leaves everything in
shadow mode.

## Limits worth knowing

- **bastiond is still one root process.** The plan's split into an unprivileged detector
  and a small root executor is deferred to Phase 4. The executor code is isolated in
  `src/bastion/executor` and reachable only through signed commands and passkeys.
- **The gateway trusts the core's verdict.** A compromised core could claim "malicious,
  99 %". It still can't choose a target outside a real detection, touch protected
  programs or system files, exceed the hourly limit, or do anything permanent.
- **A file can change between the check and the move.** The executor opens without
  following symlinks and records the hash of what it actually moved, but a racing writer
  could swap contents. Quarantine is reversible, which bounds the harm.
- **Tide has no actions yet.** Network blocking needs LuLu integration (Phase 4).
- **Passkeys are bound to the console's address.** If the Mac's Tailscale name changes,
  re-run the setup script and enroll again.
