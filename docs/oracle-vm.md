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

**Don't trust "Save as stack" from the Create instance page.** The first stack made that way
kept the console's defaults: an Oracle Linux image, 1 OCPU / 6 GB, no public IP and no
cloud-init, and its SSH key was later overwritten on the Mac (issue #41). Download the stack's
Terraform (Stack details → Terraform configuration → Download) and check that the
`oci_core_instance` has:

| Field | Value |
| --- | --- |
| `source_details.source_id` | a Canonical Ubuntu 24.04 **aarch64** image (a `data "oci_core_images"` lookup filtered by OS, version and shape keeps it current) |
| `shape_config` | `ocpus = 2`, `memory_in_gbs = 12` |
| `create_vnic_details.assign_public_ip` | `true`. With only an internet gateway, a VM without one has no route out, so cloud-init can't install Tailscale |
| `metadata.ssh_authorized_keys` | the contents of `~/.ssh/bastion_vm.pub` (`ssh-keygen -lf` both to compare fingerprints) |
| `metadata.user_data` | `base64encode(file("cloud-init.local.yaml"))`, with the 30-day key in that file |
| `lifecycle.ignore_changes` | `[source_details[0].source_id, metadata]`, so a later apply doesn't replace the VM |

Keep the edited files in `deploy/vm/stack.local/` (gitignored: they hold the Tailscale key),
zip `main.tf`, `bastion_vm.pub` and `cloud-init.local.yaml`, and upload the zip in Edit stack.
Then press **Plan** and read its log: it should say `Plan: 1 to add` with the values above.
The workflow skips the apply while any `bastion-vm` is running, so terminate a wrong one first.

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

1. Run **oracle-inspect** with `check` (below). It should say `check OK`; anything marked `←`
   is wrong before you even try to log in.
2. Check that `bastion-vm` appears in your Tailscale admin console (⋯ → Disable key expiry), then run `tailscale ssh ubuntu@bastion-vm` from your Mac. Revoke the Tailscale auth key: it's readable in the instance metadata.
3. Close public SSH. In OCI → Networking → your VCN → Security Lists, delete the ingress rule for TCP 22. You can also remove the instance's public IP, since Tailscale doesn't need one. The VM then has no public ports at all. Set the repository variable `EXPECT_PUBLIC_IP` to `no` so the daily check notices if one comes back.
4. Confirm `docker ps` works and `systemctl status unattended-upgrades` is active.
5. Delete the provisioner's secrets (`OCI_USER_OCID`, `OCI_FINGERPRINT`, `OCI_PRIVATE_KEY`, `OCI_COMPARTMENT_ID`, `NTFY_URL`) and its API key in OCI. Keep `OCI_TENANCY_OCID`, `OCI_REGION` and `OCI_STACK_ID`: the inspector uses them.

## Inspecting the VM (read-only)

The **oracle-inspect** workflow (`scripts/oracle-inspect.py`) answers questions about the VM
and the tenancy without anyone holding write access. It runs as a second OCI user that can
only `inspect`/`read`, runs a fixed list of queries, and redacts its output, because the
repository is public and so are its Actions logs: keys, `user_data` and Tailscale keys are
removed, OCIDs are shortened, and public IPs and email addresses are masked. Claude can start
it and read the result through the GitHub API, so it never needs Oracle credentials.

| Query | Shows |
| --- | --- |
| `check` | state, shape, image, public IP, SSH key fingerprint, cloud-init, each marked `←` if it differs from what this guide expects; red run on a mismatch |
| `instance`, `image`, `network` | details, the boot image's OS, private/public IP and the subnet's ingress rules |
| `ssh-key` | fingerprints only (compare with `ssh-keygen -lf ~/.ssh/bastion_vm.pub`) |
| `cloud-init` | whether `user_data` is set, its size and SHA-256 (compare with `shasum -a 256` of your local file), and whether the Tailscale placeholder was left in |
| `agent` | Oracle Cloud Agent plugins and their status |
| `metrics` | 7-day p95 CPU and memory against the 20% idle-reclaim line, and network per day |
| `limits` | A1 OCPUs and memory used vs. the tenancy limit |
| `stack`, `job-log` | recent Resource Manager jobs, and one job's log with a summary line (job: `latest`, `latest-apply`, `latest-plan` or an OCID) |
| `audit` | write operations in the tenancy (who, what, when) over the last N hours |
| `cloud-guard` | open Cloud Guard problems (Cloud Guard must be enabled: Identity & Security → Cloud Guard; it's free) |
| `budget`, `backups` | budgets and spend; boot volume backups |
| `watch` | `check` + `metrics` + `audit` + `cloud-guard`. Runs daily at 08:41 New York time; a red run means a mismatch, an idle VM or a high-risk Cloud Guard problem |
| `all` | everything except `job-log` |

Run it: Actions → **oracle-inspect** → Run workflow → pick a query. The result is in the run's
log and its summary page.

### Setup (about 5 minutes)

1. Identity & Security → Domains → Default → Groups → create `BastionInspector`; Users →
   create `bastion-inspector` (no console password) and add it to the group.
2. Policies → create `bastion-inspector-read` in the root compartment:

   ```
   Allow group 'Default'/'BastionInspector' to read instance-family in tenancy
   Allow group 'Default'/'BastionInspector' to read instance-agent-plugins in tenancy
   Allow group 'Default'/'BastionInspector' to read virtual-network-family in tenancy
   Allow group 'Default'/'BastionInspector' to read volume-family in tenancy
   Allow group 'Default'/'BastionInspector' to read orm-family in tenancy
   Allow group 'Default'/'BastionInspector' to read metrics in tenancy
   Allow group 'Default'/'BastionInspector' to read resource-availability in tenancy
   Allow group 'Default'/'BastionInspector' to read audit-events in tenancy
   Allow group 'Default'/'BastionInspector' to read cloud-guard-family in tenancy
   Allow group 'Default'/'BastionInspector' to read usage-budgets in tenancy
   ```

   `read instance-family` includes instance metadata, so this user can read `user_data`.
   That's why the Tailscale key must be revoked once the VM joins, and why the script never
   prints it.
3. Open the user → API keys → Add API key → Generate API key pair; download the private key.
4. GitHub → Settings → Secrets and variables → Actions:

   | Secret | Value |
   | --- | --- |
   | `OCI_INSPECT_USER_OCID` | `user=` from the configuration preview |
   | `OCI_INSPECT_FINGERPRINT` | `fingerprint=` |
   | `OCI_INSPECT_PRIVATE_KEY` | the whole `.pem` file |
   | `OCI_TENANCY_OCID`, `OCI_REGION`, `OCI_STACK_ID` | already set for provisioning |

   Optional **variables** (Variables tab) for `check`: `EXPECT_SSH_FP` (the `SHA256:…` from
   `ssh-keygen -lf ~/.ssh/bastion_vm.pub`), `EXPECT_PUBLIC_IP` (`yes` while provisioning, `no`
   after the lockdown) and `EXPECT_CLOUD_INIT` (`yes`).
5. Delete the downloaded `.pem`, then run the workflow once with `check`.

If a query says the policy needs a line, it names the line to add. Until these secrets
exist, the daily run just leaves a notice.

## Idle reclamation

Oracle may reclaim an Always Free instance that stays idle for 7 days: 95th-percentile CPU, network and (on A1) memory all under 20% ([Oracle docs](https://docs.oracle.com/en-us/iaas/Content/FreeTier/resourceref.htm)). An empty VM will look idle until the Phase 4 stack runs on it. Your options:

- Accept the risk. If it's reclaimed, recreate it when Phase 4 starts. This guide takes 15 minutes.
- Upgrade the account to Pay As You Go, which people widely report exempts instances from idle reclamation. Oracle's documentation doesn't say so explicitly, so treat that as unconfirmed.

Don't run a busy-loop just to dodge reclamation; that's against the spirit of the free tier.
