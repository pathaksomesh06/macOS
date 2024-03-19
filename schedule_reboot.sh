#!/bin/bash

# Sounds an alert for user attention
alert_sound_sequence() {
    local alert_tune="/System/Library/Sounds/Sosumi.aiff"
    for i in {1..3}; do
        afplay "$alert_tune" & sleep 0.25
    done
}

# Calculates the active duration of the system in minutes
fetch_system_uptime() {
    local epoch_now="$(date '+%s')"
    local boot_epoch=$(sysctl -n kern.boottime | awk -F 'sec = |, usec' '{ print $2; exit }')
    local seconds_active=$((epoch_now - boot_epoch))
    local minutes_active=$((seconds_active / 60))
    echo $minutes_active
}

# Identifies the user currently logged into the system
current_user_session() {
    echo $(stat -f%Su /dev/console)
}

# Decides when to prompt the user based on system uptime
generate_reboot_prompt() {
    local logged_user=$(current_user_session)
    local active_minutes=$(fetch_system_uptime)

    if [ "$active_minutes" -le 10 ]; then
        echo "System's been active for just 0 to 10 minutes. Standing by."
        exit 0
    elif [ "$active_minutes" -gt 10 ] && [ "$active_minutes" -le 20 ]; then
        echo "Active for 11 to 20 minutes. Time for a friendly reboot reminder."
        launchctl asuser "$(id -u "$logged_user")" sudo -u "$logged_user" /usr/local/bin/dialog \
            --notification \
            --title "A Nudge for System Refresh" \
            --message "Spruce up your Mac's performance with a quick restart. Your Mac's been on for $active_minutes minutes already."
    elif [ "$active_minutes" -gt 20 ] && [ "$active_minutes" -le 50 ]; then
        echo "21 to 50 minutes uptime. Advising a reboot with an option to pause."
        alert_sound_sequence &
        launchctl asuser "$(id -u "$logged_user")" sudo -u "$logged_user" /usr/local/bin/dialog \
        --title "Gentle Reboot Suggestion" \
        --message "Your diligent Mac could use a reboot for a smooth experience. Would you like to reboot now or hold off?" \
        --icon caution \
        --button1text "Refresh Now" \
        --button2text "Hold" \
        --timer 600 \
        --width 400 --height 160 \
        --messagefont "size=12" \
        --position bottomright \
        --moveable \
        --ontop
    elif [ "$active_minutes" -gt 60 ]; then
        echo "Over 60 minutes of uptime. Initiating a crucial reboot countdown."
        osascript -e "set volume output volume 15" &
        alert_sound_sequence &
        launchctl asuser "$(id -u "$logged_user")" sudo -u "$logged_user" /usr/local/bin/dialog \
        --title "Urgent Reboot Needed" \
        --message "We're gearing up for a reboot to enhance your Mac's performance. You have 10 minutes to safeguard your work." \
        --button1text "Comply" \
        --width 600 --height 200 \
        --messagefont size=12 \
        --hidetimerbar \
        --icon warning \
        --ontop

        launchctl asuser "$(id -u "$logged_user")" sudo -u "$logged_user" /usr/local/bin/dialog \
        --title "Heads Up!" \
        --message "Reminder: System reboot in 10 minutes. Please wrap up your tasks." \
        --button1text "Initiate Reboot" \
        --timer 600 \
        --width 300 --height 100 \
        --messagefont "size=12" \
        --position bottomright \
        --icon "none" \
        --ontop
    fi
}

# Kickstarts the execution
active_minutes=$(fetch_system_uptime)
generate_reboot_prompt "$active_minutes"
