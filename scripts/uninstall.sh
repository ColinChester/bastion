#!/usr/bin/env bash
# Remove Bastion's daemon, package and (optionally) its data.
# osquery, Santa and the Objective-See apps are left installed unless you pass --all.
#   ./scripts/uninstall.sh            remove bastiond + /opt/bastion, keep data
#   ./scripts/uninstall.sh --purge    also delete /Library/Application Support/Bastion
#   ./scripts/uninstall.sh --all      also stop osquery and remove its LaunchDaemon
set -euo pipefail
PURGE=0; ALL=0
for a in "$@"; do
  case "$a" in --purge) PURGE=1 ;; --all) ALL=1; PURGE=1 ;; *) echo "unknown: $a"; exit 2 ;; esac
done
sudo launchctl bootout system/com.bastion.bastiond 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.bastion.bastiond.plist /usr/local/bin/bastion
sudo rm -rf /opt/bastion
if [[ $PURGE -eq 1 ]]; then
  sudo rm -rf "/Library/Application Support/Bastion" /Library/Logs/Bastion
fi
if [[ $ALL -eq 1 ]]; then
  sudo launchctl bootout system/io.osquery.agent 2>/dev/null || true
  sudo rm -f /Library/LaunchDaemons/io.osquery.agent.plist
  echo "osquery stopped. Remove Santa, LuLu, BlockBlock and KnockKnock with their own"
  echo "uninstallers; remove the Santa profile in System Settings > Device Management."
fi
echo "Bastion removed."
