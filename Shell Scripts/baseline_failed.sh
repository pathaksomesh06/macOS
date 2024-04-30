#!/bin/bash

######
# INSTRUCTIONS
# 
# https://github.com/usnistgov/macos_security
#
# Upload the following text into Extension Attribute section.
#
# Used to gather the total number of failed results from the compliance audit.
######

audit=$(ls -l /Library/Preferences | /usr/bin/grep 'org.*.audit.plist' | /usr/bin/awk '{print $NF}')
EXEMPT_RULES=()
FAILED_RULES=()

if [[ ! -z "$audit" ]]; then

    count=$(echo "$audit" | /usr/bin/wc -l | /usr/bin/xargs)
    if [[ "$count" == 1 ]]; then
    
        # Get the Exemptions
        exemptfile="/Library/Managed Preferences/${audit}"
        if [[ ! -e "$exemptfile" ]];then
            exemptfile="/Library/Preferences/${audit}"
        fi

        rules=($(/usr/libexec/PlistBuddy -c "print :" "${exemptfile}" | /usr/bin/awk '/Dict/ { print $1 }'))
        
        for rule in ${rules[*]}; do
            if [[ $rule == "Dict" ]]; then
                continue
            fi
            EXEMPTIONS=$(/usr/libexec/PlistBuddy -c "print :$rule:exempt" "${exemptfile}" 2>/dev/null)
            if [[ "$EXEMPTIONS" == "true" ]]; then
                EXEMPT_RULES+=($rule)
            fi
        done
        
        unset $rules

        # Get the Findings
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
        # count items only in Findings
        count=0
        for finding in ${FAILED_RULES[@]}; do
            if [[ ! " ${EXEMPT_RULES[*]} " =~ " ${finding} " ]] ;then
                ((count=count+1))
            fi
        done
    else
        count="-2"
    fi
else
    count="-1"
fi

/bin/echo "<result>${count}</result>"