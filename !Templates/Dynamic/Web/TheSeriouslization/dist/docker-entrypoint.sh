#!/bin/bash
# Minified version of the exact same script with hardcoded vars and making using of only /dev/tcp and no checks.
function get_flag() {
    FLAG_FMT="CSL" # Only user controlled variable.
    if [[ -z $CHALLENGE_ID || -z $TEAM_ID ]]; then
        echo "CHALLENGE_ID or TEAM_ID is empty. Make sure that the variables are set properly."
        exit 1
    fi
# API Key for Flag Checker Plugin.
    API_KEY="nz8AUWqi5neBpFbIr2pKNVrXtjSb4KRH"
    exec 3<>/dev/tcp/172.17.0.1/9512
    # Corrected HTTP request format with CRLF (`\r\n`)
    echo -en "GET /flag?chal_id=$CHALLENGE_ID&team_id=$TEAM_ID HTTP/1.1\nHost: $FLAG_ENDPOINT_HOST\napi-key:$API_KEY\n\n\n" >&3
    while IFS= read -r -u 3 line; do
        tmp=$(echo "$line" | grep -ioE "$FLAG_FMT{.*}")
        if [[ $? == 0 ]]; then
            flag=$(echo $tmp)
        fi
    done
    exec 3<&-
    if [[ "$flag" == "" ]]; then
        return 1
    else
        echo $flag
    fi
}
rm -f /flag /app/flag.txt
get_flag > /app/flag.txt

# Start the PHP built-in web server
php -S 0.0.0.0:80 -t /app