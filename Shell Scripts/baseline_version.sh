#!/bin/bash

######
# INSTRUCTIONS
#
#
# Upload this as a shell script for custom attribute.
#
# Used to gather the baseline version being used.
######

result=$(/bin/ls -l /Library/Preferences | /usr/bin/grep "org.*.audit.plist" | /usr/bin/awk '{print $NF}')

if [[ ! -z "$result" ]]; then
    count=$(echo "$result" | /usr/bin/wc -l | /usr/bin/xargs)
    if [[ "$count" != 1 ]]; then
        result="Multiple Baselines Set"
    else
        # Mapping filename to baseline name
        case "$result" in
        "org.cis_lvl1.audit.plist")
            baselineName="CIS Level 1"
            ;;
        "org.cis_lvl2.audit.plist")
            baselineName="CIS Level 2"
            ;;
        # Add more mappings as needed
        *)
            baselineName="Unknown Baseline"
            ;;
        esac
        result=$baselineName
    fi
else
    result="No Baseline Set"
fi
echo "$result"
