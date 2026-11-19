#!/bin/sh

# Remove Safe Mode agent
sudo launchctl bootout system/com.ammonia.safemode 2>/dev/null || true
for uid in $(ps -axo uid,comm | awk '$2 ~ /WindowServer/ {print $1}' | sort -u); do
  sudo launchctl bootout "gui/$uid/com.ammonia.safemode" 2>/dev/null || true
done
sudo rm -f /Library/LaunchAgents/com.ammonia.safemode.plist

# Remove directories
sudo rm -rf /var/ammonia
sudo rm -rf /usr/local/bin/ammonia

# Remove system launch daemon
sudo launchctl bootout system/com.bedtime.ammonia 2>/dev/null || true
sudo launchctl unload /Library/LaunchDaemons/com.bedtime.ammonia.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.bedtime.ammonia.plist

# Reboot
sudo shutdown -r now
