pwpolicy_file=""
shiftKeyDown=$(osascript -l JavaScript -e "ObjC.import('Cocoa'); ($.NSEvent.modifierFlags & $.NSEventModifierFlagShift) > 1")
if [[ $shiftKeyDown == "true" ]]; then
    echo "-----DEBUG-----"
    set -o xtrace -o verbose
fi
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi
ssh_key_check=0
if /usr/sbin/sshd -T &> /dev/null || /usr/sbin/sshd -G &>/dev/null; then
    ssh_key_check=0
else
    /usr/bin/ssh-keygen -q -N "" -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key
    ssh_key_check=1
fi
plb="/usr/libexec/PlistBuddy"
CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }')
CURR_USER_UID=$(/usr/bin/id -u $CURRENT_USER)
arch=$(/usr/bin/arch)
RED='\e[31m'
STD='\e[39m'
GREEN='\e[32m'
YELLOW='\e[33m'
audit_plist="/Library/Preferences/org.cmmc_lvl1.audit.plist"
audit_log="/Library/Logs/cmmc_lvl1_baseline.log"