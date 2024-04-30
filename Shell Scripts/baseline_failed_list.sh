#!/bin/bash

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
######
# INSTRUCTIONS
#
# https://github.com/usnistgov/macos_security
#
# Upload the following text into Extension Attribute section.
#
# Used to gather the list of failed controls from the compliance audit.
######

audit=$(/bin/ls -l /Library/Preferences | /usr/bin/grep 'org.*.audit.plist' | /usr/bin/awk '{print $NF}')
FAILED_RULES=()
if [[ ! -z "$audit" ]]; then

    count=$(echo "$audit" | /usr/bin/wc -l | /usr/bin/xargs)
    if [[ "$count" == 1 ]]; then
        auditfile="/Library/Preferences/${audit}"

        rules=($(/usr/libexec/PlistBuddy -c "print :" "${auditfile}" | /usr/bin/awk '/Dict/ { print $1 }'))
        
        for rule in ${rules[*]}; do
            if [[ $rule == "Dict" ]]; then
                continue
            fi
            FINDING=$(/usr/libexec/PlistBuddy -c "print :$rule:finding" "${auditfile}")
            if [[ "$FINDING" == "true" ]]; then
                FAILED_RULES+=($rule)
            fi
        done
              

    else
        FAILED_RULES="Multiple Baselines Found"
    fi
else
    FAILED_RULES="No Baseline Set"
fi

# sort the results
IFS=$'
' sorted=($(/usr/bin/sort <<<"${FAILED_RULES[*]}")); unset IFS

printf "<result>"
printf "%s
" "${sorted[@]}"
printf "</result>"