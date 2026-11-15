#!/bin/sh
set -e

# Check if the variable $ammoniabuildfolder is set and not empty
if [ -z "$ammoniabuildfolder" ]; then
    # Check if ammonia exists in the Build directory
    if [ -f "./Build/ammonia" ]; then
        # Set $ammoniabuildfolder to the current directory
        ammoniabuildfolder=$(pwd)
    else
        # Ask the user to enter the build directory's path
        echo "Please enter the build directory's path:"
        read ammoniabuildfolder
    fi
fi

# Create a directory for the scripts
mkdir -p "$ammoniabuildfolder/scripts"

# Create a postinstall script to set up the LaunchDaemon + Safe Mode agent
cat <<'EOL' > "$ammoniabuildfolder/scripts/postinstall"
#!/bin/sh

echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.bedtime.ammonia</string>
    <key>ProgramArguments</key>
    <array>
        <string>/private/var/ammonia/core/ammonia</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>" > /Library/LaunchDaemons/com.bedtime.ammonia.plist

echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.ammonia.safemode</string>
    <key>ProgramArguments</key>
    <array>
        <string>/private/var/ammonia/core/gui/Ammonia Injector.app/Contents/MacOS/Ammonia Injector</string>
        <string>--watch</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
</dict>
</plist>" > /Library/LaunchAgents/com.ammonia.safemode.plist

launchctl bootout system/com.bedtime.ammonia 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.bedtime.ammonia.plist 2>/dev/null \
  || launchctl load /Library/LaunchDaemons/com.bedtime.ammonia.plist 2>/dev/null || true

# Load Safe Mode agent for current GUI users best-effort
for uid in $(ps -axo uid,comm | awk '$2 ~ /WindowServer/ {print $1}' | sort -u); do
  launchctl bootout "gui/$uid/com.ammonia.safemode" 2>/dev/null || true
  launchctl bootstrap "gui/$uid" /Library/LaunchAgents/com.ammonia.safemode.plist 2>/dev/null || true
done

nvram boot-args="-arm64e_preview_abi $(nvram boot-args 2>/dev/null | cut -f 2-)"
defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation -bool true

exit 0
EOL

# Make the postinstall script executable
chmod +x "$ammoniabuildfolder/scripts/postinstall"

# Create a temporary directory and setup the installation files in it.
mkdir -p "$ammoniabuildfolder/temp/ammonia/core/tweaks"
mkdir -p "$ammoniabuildfolder/temp/ammonia/core/gui"

cp "$ammoniabuildfolder/./fridagum.dylib" "$ammoniabuildfolder/temp/ammonia/core/"
cp "$ammoniabuildfolder/./Build/ammonia" "$ammoniabuildfolder/temp/ammonia/core/"
chmod +x "$ammoniabuildfolder/temp/ammonia/core/ammonia"
cp "$ammoniabuildfolder/./Build/liblibinfect.dylib" "$ammoniabuildfolder/temp/ammonia/core/"
cp "$ammoniabuildfolder/./Build/libopener.dylib" "$ammoniabuildfolder/temp/ammonia/core/"

if [ -d "$ammoniabuildfolder/./Build/Ammonia Injector.app" ]; then
  rm -rf "$ammoniabuildfolder/temp/ammonia/core/gui/Ammonia Injector.app"
  cp -R "$ammoniabuildfolder/./Build/Ammonia Injector.app" "$ammoniabuildfolder/temp/ammonia/core/gui/"
elif [ -f "$ammoniabuildfolder/./Build/AmmoniaSafeMode" ]; then
  cp "$ammoniabuildfolder/./Build/AmmoniaSafeMode" "$ammoniabuildfolder/temp/ammonia/core/gui/"
  chmod +x "$ammoniabuildfolder/temp/ammonia/core/gui/AmmoniaSafeMode"
fi

# core must be user-writable so Ammonia Injector can clear .safemode markers
# written by root-owned hosts (WindowServer / loginwindow).
chmod 777 "$ammoniabuildfolder/temp/ammonia/core"
chmod 777 "$ammoniabuildfolder/temp/ammonia/core/tweaks"
chmod 777 "$ammoniabuildfolder/temp/ammonia/core/gui"

# Build the package
sudo pkgbuild --install-location /private/var/ --root "$ammoniabuildfolder/temp" --scripts "$ammoniabuildfolder/scripts" --identifier net.bedtime.ammonia "$ammoniabuildfolder/ammonia.pkg"
rm -rf "$ammoniabuildfolder/scripts/"

# Remove the temporary directory
rm -rf "$ammoniabuildfolder/temp"

echo "Built $ammoniabuildfolder/ammonia.pkg"
