#!/bin/bash

# Function to update the Swift Dialog
updateSplashScreen() {
    # Check if Swift Dialog is present
    if [[ -a "/Library/Application Support/Dialog/Dialog.app/Contents/MacOS/Dialog" ]]; then
        # Send a command to Swift Dialog to update the screen
        echo "$s(date) | Updating Swift Dialog monitor for FileVault status: $1" >> /var/tmp/dialog.log
        /Library/Application Support/Dialog/Dialog.app/Contents/MacOS/Dialog command updateSplashScreen title="FileVault Status" message="$1" status="$2"
    else
        echo "Swift Dialog is not present"
    fi
}

# Check FileVault status
fileVaultStatus=$(fdesetup status)

# Interpret the FileVault status and call the updateSplashScreen function with appropriate parameters
if [[ $fileVaultStatus == *"FileVault is On."* ]]; then
    updateSplashScreen "FileVault is enabled" "success"
elif [[ $fileVaultStatus == *"FileVault is Off."* ]]; then
    updateSplashScreen "FileVault is disabled" "error"
else
    updateSplashScreen "FileVault status is unknown" "error"
fi
