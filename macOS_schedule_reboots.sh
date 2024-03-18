#!/bin/bash

# Function to play an alert sound multiple times
play_alert_sound() {
    local sound_path="/System/Library/Sounds/Sosumi.aiff"
    for _ in {1..3}; do
        afplay "$sound_path" & sleep 0.2
    done
}

# Function to calculate system uptime in days accurately
calculate_uptime() {
    local current_unix_time="$(date '+%s')"  # Get the current Unix time
    local boot_unix_time="$(sysctl -n kern.boottime | awk -F 'sec = |, usec' '{ print $2; exit }')"  # Get the boot Unix time
    local uptime_seconds="$((current_unix_time - boot_unix_time))"  # Calculate the uptime in seconds
    local uptime_days="$((uptime_seconds / 86400))"  # Convert uptime to days
    echo $uptime_days  # Return the uptime in days
}

# Function to determine the currently logged-in user
get_current_user() {
    echo $(stat -f%Su /dev/console)  # Get the username of the currently logged-in user
}

# Function to prompt for reboot based on uptime
prompt_reboot() {
    local system_user=$(get_current_user)  # Get the currently logged-in user
    local uptime_days=$1  # Get the system's uptime in days

    if [ "$uptime_days" -le 5 ]; then
        echo "Uptime is less than or equal to 5 days. Exiting."
    elif [ "$uptime_days" -ge 7 ] && [ "$uptime_days" -le 10 ]; then
        echo "Uptime is between 7 and 10 days. Displaying daily notification."
        launchctl asuser "$(id -u "$system_user")" sudo -u "$system_user" /usr/local/bin/dialog \
        --notification \
        --title "\"$uptime_days days without a reboot!\"" \
        --message "\"Your Mac has been running for $uptime_days days. It is recommended to restart soon for optimal performance.\"" \
        --icon caution \
        afplay "/System/Library/Sounds/Pop.aiff"
    elif [ "$uptime_days" -ge 11 ] && [ "$uptime_days" -le 13 ]; then
        echo "Uptime is between 11 and 13 days. Displaying dialog with Defer button."
        afplay "/System/Library/Sounds/Sosumi.aiff" &
        launchctl asuser "$(id -u "$system_user")" sudo -u "$system_user" /usr/local/bin/dialog \
        --title "\"Restart Now\"" \
        --message "\"Your Mac requires a restart to apply critical updates and improvements. It will automatically restart in 10 minutes. Please save your work.\"" \
        --icon warning \
        --button1text "\"Restart now\"" \
        --button2text "\"Defer\"" \
        --timer 600 \
        --width 650 --height 280 \
        --messagefont "size=13" \
        --position bottomright \
        --moveable \
        --ontop
    elif [ "$uptime_days" -gt 15 ]; then
        echo "Uptime is more than 15 days. Displaying acknowledgment window with countdown."
        osascript -e "set volume output volume 80 --100%" &
        afplay "/System/Library/Sounds/Sosumi.aiff" & sleep 0.2 && afplay "/System/Library/Sounds/Sosumi.aiff" & sleep 0.4 && afplay "/System/Library/Sounds/Sosumi.aiff" &
        launchctl asuser "$(id -u "$system_user")" sudo -u "$system_user" /usr/local/bin/dialog \
        --title "\"Restart required\"" \
        --message "\"Your Mac has been running for $uptime_days days and it is recommended to restart now to apply important updates and improvements.\"" \
        --button1text "OK" \
        --width 650 --height 230 \
        --messagefont size=13 \
        --hidetimerbar \
        --icon warning \
        # --blurscreen \
        --ontop

        launchctl asuser "$(id -u "$system_user")" sudo -u "$system_user" /usr/local/bin/dialog \
        --title "none" \
        --message "\"Your computer will restart when the timer reaches zero. Please save your work now.\"" \
        --button1text "\"Restart now\"" \
        --timer 600 \
        --width 320 --height 110 \
        --messagefont "size=13" \
        --position bottomright \
        --icon "none" \
        --ontop
    fi
}

# Main execution block
uptime_days=$(calculate_uptime)  # Calculate the system's uptime in days
prompt_reboot "$uptime_days"  # Trigger reboot prompts based on system uptime
