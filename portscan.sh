
#!/usr/bin/env bash

# Bash Port Scanner - Enhanced Edition
# Author: Humraz
# Purpose: TCP port scanning for authorized security testing

set -u

VERSION="1.0.0"
TARGET=""
PORT_INPUT="22,80,443,3306,5432,8080,8443"
TIMEOUT=1
OUTPUT=""
OPEN_COUNT=0
CLOSED_COUNT=0
FILTERED_COUNT=0
ERROR_COUNT=0
TOTAL_COUNT=0

# Terminal colors
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' RESET=''
fi

declare -a PORTS=()

usage() {
    cat <<EOF
Bash Port Scanner v${VERSION}

Usage:
  ./portscan.sh -t TARGET [OPTIONS]

Options:
  -t TARGET    Target IP address or hostname (required)
  -p PORTS     Ports, comma-separated or ranges
               Example: 22,80,443,8000-8100
  -T SECONDS   Connection timeout (1-10, default: 1)
  -o FILE      Save scan results to a text file
  -h           Display this help message

Examples:
  ./portscan.sh -t 127.0.0.1
  ./portscan.sh -t localhost -p 22,80,443
  ./portscan.sh -t 127.0.0.1 -p 1-100 -T 2
  ./portscan.sh -t localhost -p 22,80 -o report.txt

Only scan systems you own or have permission to test.
EOF
}

# Display output and optionally save it
log() {
    printf '%b\n' "$1"
    if [[ -n "$OUTPUT" ]]; then
        printf '%b\n' "$1" >> "$OUTPUT"
    fi
}

# Identify common services
get_service() {
    case "$1" in
        20) echo "FTP-DATA" ;;
        21) echo "FTP" ;;
        22) echo "SSH" ;;
        23) echo "TELNET" ;;
        25) echo "SMTP" ;;
        53) echo "DNS" ;;
        80) echo "HTTP" ;;
        110) echo "POP3" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        445) echo "SMB" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        5900) echo "VNC" ;;
        6379) echo "Redis" ;;
        8080) echo "HTTP-ALT" ;;
        8443) echo "HTTPS-ALT" ;;
        27017) echo "MongoDB" ;;
        *) echo "Unknown" ;;
    esac
}

# Parse and validate ports
parse_ports() {
    local item start end port count=0

    IFS=',' read -r -a entries <<< "$PORT_INPUT"

    for item in "${entries[@]}"; do
        if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start=$((10#${BASH_REMATCH[1]}))
            end=$((10#${BASH_REMATCH[2]}))

            if (( start < 1 || end > 65535 || start > end )); then
                echo "Error: Invalid port range: $item" >&2
                return 1
            fi

            for ((port=start; port<=end; port++)); do
                PORTS+=("$port")
                ((count+=1))
            done

        elif [[ "$item" =~ ^[0-9]+$ ]]; then
            port=$((10#$item))

            if (( port < 1 || port > 65535 )); then
                echo "Error: Invalid port: $item" >&2
                return 1
            fi

            PORTS+=("$port")
            ((count+=1))
        else
            echo "Error: Invalid port format: $item" >&2
            return 1
        fi

        if (( count > 4096 )); then
            echo "Error: Maximum 4096 ports allowed per scan." >&2
            return 1
        fi
    done

    if (( count == 0 )); then
        echo "Error: No ports specified." >&2
        return 1
    fi

    # Remove duplicate ports
    local -A seen=()
    local -a unique_ports=()

    for port in "${PORTS[@]}"; do
        if [[ -z "${seen[$port]+x}" ]]; then
            seen[$port]=1
            unique_ports+=("$port")
        fi
    done

    PORTS=("${unique_ports[@]}")
    TOTAL_COUNT=${#PORTS[@]}
}

# Scan one TCP port
scan_port() {
    local port="$1"
    local service result
    local exit_code

    service=$(get_service "$port")

    timeout "${TIMEOUT}s" bash -c \
        'exec 3<>"/dev/tcp/$1/$2"' _ "$TARGET" "$port" \
        2>/dev/null

    exit_code=$?

    case "$exit_code" in
        0)
            ((OPEN_COUNT+=1))
            result="${GREEN}[OPEN]${RESET} Port $port - $service"
            ;;
        124)
            ((FILTERED_COUNT+=1))
            result="${YELLOW}[FILTERED]${RESET} Port $port - $service"
            ;;
        1)
            ((CLOSED_COUNT+=1))
            result="${RED}[CLOSED]${RESET} Port $port - $service"
            ;;
        *)
            ((ERROR_COUNT+=1))
            result="${YELLOW}[ERROR]${RESET} Port $port - $service (exit code: $exit_code)"
            ;;
    esac

    log "$result"
}


# Parse command-line arguments
while getopts ":t:p:T:o:h" opt; do
    case "$opt" in
        t) TARGET="$OPTARG" ;;
        p) PORT_INPUT="$OPTARG" ;;
        T) TIMEOUT="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        h) usage; exit 0 ;;
        :)
            echo "Error: Option -$OPTARG requires an argument." >&2
            usage
            exit 1
            ;;
        \?)
            echo "Error: Invalid option -$OPTARG" >&2
            usage
            exit 1
            ;;
    esac
done

# Validate target
if [[ -z "$TARGET" || "$TARGET" == -* || "$TARGET" =~ [[:space:]] ]]; then
    echo "Error: A valid target is required using -t." >&2
    usage
    exit 1
fi

# Validate hostname/IP resolution
if ! command -v getent >/dev/null 2>&1; then
    echo "Error: Required command 'getent' is not installed." >&2
    exit 1
fi

if ! getent ahosts "$TARGET" >/dev/null 2>&1; then
    echo "Error: Cannot resolve target '$TARGET'." >&2
    exit 1
fi

# Validate timeout
if [[ ! "$TIMEOUT" =~ ^[0-9]+$ ]] || (( TIMEOUT < 1 || TIMEOUT > 10 )); then
    echo "Error: Timeout must be between 1 and 10 seconds." >&2
    exit 1
fi

# Check dependencies
for command in bash timeout; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Error: Required command '$command' is not installed." >&2
        exit 1
    fi
done

# Parse ports
if ! parse_ports; then
    exit 1
fi

# Prepare output report
if [[ -n "$OUTPUT" ]]; then
    if [[ -d "$OUTPUT" || ! -w "$(dirname "$OUTPUT")" ]]; then
        echo "Error: Output path is not writable." >&2
        exit 1
    fi
    if ! : > "$OUTPUT"; then
        echo "Error: Cannot create output file." >&2
        exit 1
    fi
fi

# Start scanning
log "${CYAN}========================================${RESET}"
log "${CYAN}       BASH PORT SCANNER v${VERSION}${RESET}"
log "${CYAN}========================================${RESET}"
log "Target       : $TARGET"
log "Port Count   : $TOTAL_COUNT"
log "Timeout      : ${TIMEOUT}s"
log "Started      : $(date '+%Y-%m-%d %H:%M:%S')"
log "----------------------------------------"
log "Scanning started..."
log ""

for port in "${PORTS[@]}"; do
    scan_port "$port"
done

# Final summary
log "========================================"
log "              SCAN SUMMARY"
log "========================================"
log "Total Ports  : $TOTAL_COUNT"
log "Open Ports   : $OPEN_COUNT"
log "Closed Ports : $CLOSED_COUNT"
log "Filtered     : $FILTERED_COUNT"
log "Errors       : $ERROR_COUNT"
log "Completed    : $(date '+%Y-%m-%d %H:%M:%S')"
log "========================================"

if [[ -n "$OUTPUT" ]]; then
    echo "Report saved to: $OUTPUT"
fi
