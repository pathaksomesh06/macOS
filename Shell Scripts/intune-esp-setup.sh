# Copyright (c) 2024 [Somesh Pathak]. All rights reserved.
# This script automates Ubuntu installation and Intune enrollment to provide a seamless enterprise device setup experience.
# Disclaimer: This script is provided "as-is" without any warranties of any kind, either express or implied.

#!/bin/bash

# Configuration
LOG_FILE="/var/log/intune-esp.log"
TEMP_DIR="/var/tmp/esp-setup"
STATUS_FILE="$TEMP_DIR/esp-progress"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check root
if [ "$EUID" -ne 0 ]; then 
   echo "Please run as root"
   exit 1
fi

# Create temp directory with proper permissions
mkdir -p "$TEMP_DIR"
chmod 1777 "$TEMP_DIR"
touch "$STATUS_FILE"
chmod 666 "$STATUS_FILE"

# Functions
update_status() {
   local progress=$1
   local message=$2
   echo "{\"progress\": $progress, \"message\": \"$message\", \"complete\": false}" > "$STATUS_FILE"
   sleep 1  # Add small delay to ensure UI updates
}

mark_complete() {
   echo "{\"progress\": 100, \"message\": \"Setup complete\", \"complete\": true}" > "$STATUS_FILE"
   sleep 1
}

log_message() {
   echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

install_dependencies() {
   log_message "Installing dependencies"
   update_status 5 "Installing required packages..."
   
   apt-get update
   DEBIAN_FRONTEND=noninteractive apt-get install -y \
       python3 \
       python3-gi \
       python3-gi-cairo \
       gir1.2-gtk-3.0 \
       curl \
       gpg \
       wget \
       ufw
}

perform_installation() {
   touch "$LOG_FILE"
   chmod 644 "$LOG_FILE"
   
   # Start Python UI
   python3 "$SCRIPT_DIR/esp_dialog.py" &
   UI_PID=$!
   sleep 2  # Give UI time to initialize
   
   # Step 1: System Requirements
   update_status 10 "Checking system requirements..."
   sleep 2
   
   # Step 2: Required Packages
   update_status 20 "Installing required packages..."
   install_dependencies
   
   # Step 3: Microsoft Repository
   update_status 40 "Setting up Microsoft repository..."
   rm -f /usr/share/keyrings/microsoft*
   rm -f /etc/apt/sources.list.d/microsoft*
   apt clean
   rm -rf /var/lib/apt/lists/*
   
   curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > "$TEMP_DIR/microsoft.gpg"
   install -o root -g root -m 644 "$TEMP_DIR/microsoft.gpg" /usr/share/keyrings/microsoft.gpg
   echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/24.04/prod noble main" > /etc/apt/sources.list.d/microsoft-ubuntu-noble-prod.list
   rm -f "$TEMP_DIR/microsoft.gpg"
   
   apt-get update
   
   # Step 4: Intune Portal
   update_status 60 "Installing Intune Company Portal..."
   if ! DEBIAN_FRONTEND=noninteractive apt-get install -y intune-portal; then
       log_message "Failed to install Intune Portal"
       update_status 65 "Intune Portal installation failed"
       return 1
   fi
   
   # Step 5: Microsoft Defender
   update_status 80 "Installing Microsoft Defender..."
   MDE_INSTALLER="$TEMP_DIR/mde_installer.sh"
   wget -O "$MDE_INSTALLER" https://raw.githubusercontent.com/microsoft/mdatp-xplat/master/linux/installation/mde_installer.sh
   chmod +x "$MDE_INSTALLER"
   if ! "$MDE_INSTALLER" --install --channel prod --quiet; then
       log_message "Failed to install Microsoft Defender"
       update_status 85 "Microsoft Defender installation failed, continuing..."
   fi
   
   # Step 6: Security Settings
   update_status 90 "Configuring security settings..."
   ufw --force enable
   ufw default deny incoming
   ufw default allow outgoing
   ufw allow 80/tcp
   ufw allow 443/tcp
   
   # Step 7: Verification
   update_status 95 "Verifying installation..."
   if ! dpkg -l intune-portal >/dev/null 2>&1; then
       log_message "Installation verification failed"
       return 1
   fi
   
   # Mark completion
   mark_complete
   wait $UI_PID
}

main() {
   export DISPLAY=:0
   
   if ! perform_installation; then
       log_message "Installation failed"
       rm -rf "$TEMP_DIR"
       exit 1
   fi
   
   rm -rf "$TEMP_DIR"
}

if ! main; then
   log_message "Setup failed. Check logs for details."
   exit 1
fi