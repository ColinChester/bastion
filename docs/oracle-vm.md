# Creating the Oracle Cloud VM (Phase 0)

The VM hosts the orchestrator, event bus, ntfy and the web console from Phase 4 on.
It's requested now because Ampere (Arm) capacity is often unavailable for days.
Nothing runs on it until Phase 4. It only needs to exist and be reachable over Tailscale.

## Before you start

1. **Tailscale account.** Install Tailscale on your Mac and iPhone and sign in with the same account. The free Personal plan is enough.
2. **One-off auth key.** In the Tailscale admin console, go to Settings → Keys → Generate auth key. Choose *not reusable*, *pre-approved*, expiring in 1 hour. Copy `deploy/vm/cloud-init.yaml` to `deploy/vm/cloud-init.local.yaml` (git ignores it) and paste the key there in place of `__TAILSCALE_AUTHKEY__`.
3. **Dedicated SSH key** for emergency console access:
   `ssh-keygen -t ed25519 -f ~/.ssh/bastion_vm -C bastion-vm` (set a passphrase).

## Create the instance

OCI Console → Compute → Instances → **Create instance**:

| Setting | Value |
| --- | --- |
| Name | `bastion-vm` |
| Image | Canonical Ubuntu 24.04 (the **aarch64** build) |
| Shape | Ampere → `VM.Standard.A1.Flex`, **2 OCPU, 12 GB RAM** |
| Networking | Default VCN and public subnet; assign a public IPv4 for now |
| SSH key | Paste `~/.ssh/bastion_vm.pub` |
| Boot volume | 100 GB (the Always Free total is 200 GB) |
| Advanced → Management → cloud-init | Paste `cloud-init.local.yaml` |

2 OCPU / 12 GB is the Always Free limit for free-tier tenancies since June 15, 2026. Pay-as-you-go accounts were reportedly told the old 4/24 still applies, but stay at 2/12 so it's free either way.

**"Out of host capacity"?** Try each availability domain in the dropdown. If all fail, try again at a different time of day. Upgrading the account to Pay As You Go is widely reported to make A1 capacity easier to get, and Always Free resources stay free. If you do that, set a $1 budget alert under Billing → Budgets.

## After it boots (5–10 minutes)

1. Check that `bastion-vm` appears in your Tailscale admin console, then run `tailscale ssh ubuntu@bastion-vm` from your Mac.
2. Close public SSH. In OCI → Networking → your VCN → Security Lists, delete the ingress rule for TCP 22. You can also remove the instance's public IP, since Tailscale doesn't need one. The VM then has no public ports at all.
3. Confirm `docker ps` works and `systemctl status unattended-upgrades` is active.

## Idle reclamation

Oracle may reclaim an Always Free instance that stays idle for 7 days: 95th-percentile CPU, network and (on A1) memory all under 20% ([Oracle docs](https://docs.oracle.com/en-us/iaas/Content/FreeTier/resourceref.htm)). An empty VM will look idle until the Phase 4 stack runs on it. Your options:

- Accept the risk. If it's reclaimed, recreate it when Phase 4 starts. This guide takes 15 minutes.
- Upgrade the account to Pay As You Go, which people widely report exempts instances from idle reclamation. Oracle's documentation doesn't say so explicitly, so treat that as unconfirmed.

Don't run a busy-loop just to dodge reclamation; that's against the spirit of the free tier.
