#!/bin/bash

# Replace these with your actual Workspace ID and Primary Key
CustomerId="b1319add-2b65-4e43-b44f-bc0224307dc8"
SharedKey="dj6PfoU9vEc44BRfBLl89XqtNJ0teptExMWzE/+uGAkOhY+MWOdh0VHf3zrwnnyfM99Q9oRwb0Vcq6rs7XOqrA==y"

# Function to create the authorization signature
function generate_signature() {
    local customerId="$1"
    local sharedKey="$2"
    local date="$3"
    local contentLength="$4"
    local method="$5"
    local contentType="$6"
    local resource="$7"
    
    local stringToHash="$method\n$contentLength\n$contentType\nx-ms-date:$date\n$resource"
    local decodedKey=$(echo "$sharedKey" | base64 -d | xxd -p -u -c 256)
    local hash=$(echo -ne "$stringToHash" | xxd -p -u -c 256 | xxd -r -p | openssl dgst -sha256 -mac HMAC -macopt hexkey:$decodedKey -binary | base64)
    
    echo "SharedKey $customerId:$hash"
}
# Function to send data to Log Analytics
function send_data() {
    local customerId="$1"
    local sharedKey="$2"
    local data="$3"
    local logType="$4"
    
    local method="POST"
    local contentType="application/json"
    local resource="/api/logs"
    local date=$(date -u +%a,\ %d\ %b\ %Y\ %H:%M:%S\ GMT)
    local contentLength=$(echo -n "$data" | wc -c | tr -d ' ')
    local signature=$(generate_signature "$customerId" "$sharedKey" "$date" "$contentLength" "$method" "$contentType" "$resource")
    local uri="https://$customerId.ods.opinsights.azure.com$resource?api-version=2016-04-01"
    
    curl --silent --location "$uri" \
         --header "Authorization: $signature" \
         --header "Log-Type: $logType" \
         --header "x-ms-date: $date" \
         --header "Content-Type: $contentType" \
         --data "$data"
}

# Retrieve Intune DeviceID
ManagedDeviceID=$(security find-certificate -a | awk -F= '/issu/ && /MICROSOFT INTUNE MDM DEVICE CA/ { getline; gsub(/"/, "", $2); print $2}' | head -n 1)

# Main data collection and processing
ComputerName=$(scutil --get ComputerName)
DeviceSerialNumber=$(system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')

# Collecting dynamic application data
Applications="["

appCount=0  # Initialize application count
IFS=$'\n'
for line in $(system_profiler SPApplicationsDataType); do
    if [[ "$line" =~ "Location:" ]]; then
        appPath=$(echo "$line" | awk -F": " '{print $2}')
        appName=$(basename "$appPath" .app)  # Extracts only the app name, removing path and .app extension
    elif [[ "$line" =~ "Version:" ]]; then
        # Parse Info.plist to check for CFBundleIdentifier containing "apple"
        bundleId=$(defaults read "$appPath/Contents/Info" CFBundleIdentifier 2>/dev/null)
        if [[ "$bundleId" != *"apple"* ]]; then
            appVersion=$(echo "$line" | awk -F": " '{print $2}')
            Applications+="{\"AppName\": \"$appName\", \"AppVersion\": \"$appVersion\", \"ComputerName\": \"$ComputerName\", \"DeviceSerialNumber\": \"$DeviceSerialNumber\", \"ManagedDeviceID\": \"$ManagedDeviceID\"},"
            ((appCount++))  # Increment application count
        fi
    fi
done
IFS=$' \t\n'

# Remove the last comma for JSON format correctness
Applications=$(echo $Applications | sed 's/,\]/\]/')

# Send data
send_data "$CustomerId" "$SharedKey" "$Applications" "Mac_app_inventory_CL"

# Final output with total count of apps
echo "Application inventory collected and uploaded to Azure Log Analytics workspace. The total count of apps discovered and uploaded are $appCount."
