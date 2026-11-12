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

## Keep retrying automatically (GitHub Actions)

If the console keeps saying "Out of host capacity", let GitHub retry for you. The
`oracle-provision` workflow applies your Resource Manager stack every 10 minutes, even
while your Mac is asleep (each run keeps trying for up to 5 hours and an hourly
schedule starts the next, because GitHub drops many scheduled triggers), and **disables itself once the VM exists**. It then opens a
GitHub issue (and, optionally, sends an ntfy push) so you know.

| Outcome of a run | What the workflow does |
| --- | --- |
| Out of host capacity, or Oracle rate-limited the request | Tries again in 10 minutes, within the same run |
| VM created, or it already exists | Disables itself, opens an issue "Oracle VM is up" |
| A setup problem (bad key, missing permission, service limit, wrong instance name) | Disables itself, opens an issue with the error, red run |
| Anything else | Red run (GitHub emails you), keeps trying |

The logic is in `scripts/oracle-provision.sh`, tested in `tests/test_oracle_provision.py`.

### 1. A stack that creates the VM

In OCI → Developer Services → Resource Manager → Stacks, the stack should create the
instance exactly as in the table above, with the instance named `bastion-vm` (or set the
repository variable `OCI_INSTANCE_NAME` to the name you used). Use a Tailscale auth key
that survives the wait: **reusable, pre-approved, expiring in 30 days** instead of the
1-hour key, and delete it in Tailscale once the VM has joined.

### 2. A user that can only do this

So the key stored in GitHub can't touch anything else in the account:

1. Identity & Security → Domains → Default → Groups → create `BastionProvisioner`.
2. Users → create `bastion-provisioner` (no console password needed) and add it to the group.
3. Identity & Security → Policies → create a policy in the compartment that holds the
   stack (for a free account that's usually the root compartment):

   ```
   Allow group 'Default'/'BastionProvisioner' to manage orm-family in tenancy
   Allow group 'Default'/'BastionProvisioner' to manage instance-family in tenancy
   Allow group 'Default'/'BastionProvisioner' to manage volume-family in tenancy
   Allow group 'Default'/'BastionProvisioner' to manage virtual-network-family in tenancy
   ```

   If the stack lives in its own compartment, write `in compartment <name>` instead of
   `in tenancy`. Resource Manager runs the apply with this user's permissions, so it
   needs the instance, volume and network rights, not just `orm-family`.
4. Open the user → API keys → Add API key → Generate API key pair. Download the
   private key and keep the "Configuration file preview" it shows.

### 3. GitHub secrets

In GitHub → bastion → Settings → Secrets and variables → Actions → New repository secret:

| Secret | Value |
| --- | --- |
| `OCI_USER_OCID` | `user=` from the configuration preview |
| `OCI_TENANCY_OCID` | `tenancy=` |
| `OCI_FINGERPRINT` | `fingerprint=` |
| `OCI_REGION` | `region=` (e.g. `us-ashburn-1`) |
| `OCI_PRIVATE_KEY` | the whole downloaded `.pem` file, including the BEGIN/END lines |
| `OCI_STACK_ID` | the stack's OCID (`ocid1.ormstack…`) |
| `OCI_COMPARTMENT_ID` | the compartment the VM is created in (the tenancy OCID for root) |
| `NTFY_URL` (optional) | e.g. `https://ntfy.sh/<a random topic>`; the Mac's own ntfy is tailnet-only, so GitHub can't reach it |

Then delete the downloaded `.pem` from your Mac.

### 4. Start it

Actions tab → **oracle-provision** → Run workflow, to try once right away. Open the run:
a green run whose log says `result: capacity` means everything is set up and it's just
waiting for Oracle. After that it runs on its own; a new run starts hourly at :17 if none is in progress.

To stop it early: Actions → oracle-provision → ⋯ → Disable workflow. After you fix a
setup problem it reported, enable it again from the same menu.

## After it boots (5–10 minutes)

1. Check that `bastion-vm` appears in your Tailscale admin console, then run `tailscale ssh ubuntu@bastion-vm` from your Mac.
2. Close public SSH. In OCI → Networking → your VCN → Security Lists, delete the ingress rule for TCP 22. You can also remove the instance's public IP, since Tailscale doesn't need one. The VM then has no public ports at all.
3. Confirm `docker ps` works and `systemctl status unattended-upgrades` is active.

## Idle reclamation

Oracle may reclaim an Always Free instance that stays idle for 7 days: 95th-percentile CPU, network and (on A1) memory all under 20% ([Oracle docs](https://docs.oracle.com/en-us/iaas/Content/FreeTier/resourceref.htm)). An empty VM will look idle until the Phase 4 stack runs on it. Your options:

- Accept the risk. If it's reclaimed, recreate it when Phase 4 starts. This guide takes 15 minutes.
- Upgrade the account to Pay As You Go, which people widely report exempts instances from idle reclamation. Oracle's documentation doesn't say so explicitly, so treat that as unconfirmed.

Don't run a busy-loop just to dodge reclamation; that's against the spirit of the free tier.
