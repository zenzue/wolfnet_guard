#!/usr/bin/env bash
# WolfNet Guard - Defensive LAN monitoring utility
# Author: Aung Myat Thu
# Purpose: Authorized monitoring of networks and systems you own or administer.

set -Eeuo pipefail
shopt -s extglob

VERSION="1.0.0"
INTERFACE="eno2"
INTERVAL=15
ARP_CAPTURE_SECONDS=3
ARP_FLOOD_THRESHOLD=100
ALERT_COOLDOWN=120
EXPECTED_GATEWAY_MAC="${EXPECTED_GATEWAY_MAC:-}"
ENABLE_DNS=1
ENABLE_PASSIVE_ARP=1
ENABLE_PROCESS_WATCH=1
ENABLE_DESKTOP_ALERTS=1
STATE_DIR="/var/lib/wolfnet-guard"
LOG_DIR="/var/log/wolfnet-guard"
ALERT_HOOK="${ALERT_HOOK:-}"

DNS_CANARIES=(
  "one.one.one.one|1.1.1.1,1.0.0.1"
  "dns.google|8.8.8.8,8.8.4.4"
  "resolver1.opendns.com|208.67.222.222"
)
TRUSTED_DNS=("1.1.1.1" "9.9.9.9")

C_RESET='\033[0m'
C_GREEN='\033[1;32m'
C_DIM='\033[2;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[1;31m'
C_CYAN='\033[1;36m'
C_WHITE='\033[1;37m'

CURRENT_ARP=""
PREVIOUS_ARP=""
RAW_ARP=""
PREVIOUS_LISTENERS=""
DNS_HASH_FILE=""
GATEWAY_MAC_FILE=""
EVENT_LOG=""
RUN_LOG=""
LOCAL_MAC=""
LOCAL_IP=""
GATEWAY_IP=""
LAST_SCAN_DEVICES=0
LAST_ARP_RATE=0
LAST_DNS_STATUS="not checked"
LAST_PROCESS_STATUS="not checked"
LAST_EVENT="No alerts"
START_TIME="$(date +%s)"

# Alert cooldown cache: key -> epoch
# shellcheck disable=SC2034
declare -A LAST_ALERT_AT=()

usage() {
  cat <<USAGE
WolfNet Guard v${VERSION}

Usage: sudo $0 [options]

Options:
  -i, --interface NAME        Network interface (default: eno2)
  -t, --interval SECONDS      Delay between monitoring cycles (default: 15)
      --arp-window SECONDS    Passive ARP capture window (default: 3)
      --arp-threshold COUNT   ARP frames in window before flood alert (default: 100)
      --cooldown SECONDS      Repeated-alert cooldown (default: 120)
      --gateway-mac MAC       Pin the expected gateway MAC address
      --no-dns                Disable DNS spoof checks
      --no-passive-arp        Disable passive ARP-rate checks
      --no-process-watch      Disable Netcat/Socat process checks
      --no-desktop-alerts     Disable notify-send desktop alerts
      --state-dir PATH        State directory
      --log-dir PATH          Log directory
  -h, --help                  Show help

Environment:
  EXPECTED_GATEWAY_MAC        Same as --gateway-mac
  ALERT_HOOK                  Optional executable called as:
                              ALERT_HOOK severity title message

Examples:
  sudo $0 -i eno2 -t 10
  sudo EXPECTED_GATEWAY_MAC=aa:bb:cc:dd:ee:ff $0 -i eno2
USAGE
}

while (($#)); do
  case "$1" in
    -i|--interface) INTERFACE="${2:?Missing interface}"; shift 2 ;;
    -t|--interval) INTERVAL="${2:?Missing interval}"; shift 2 ;;
    --arp-window) ARP_CAPTURE_SECONDS="${2:?Missing seconds}"; shift 2 ;;
    --arp-threshold) ARP_FLOOD_THRESHOLD="${2:?Missing count}"; shift 2 ;;
    --cooldown) ALERT_COOLDOWN="${2:?Missing seconds}"; shift 2 ;;
    --gateway-mac) EXPECTED_GATEWAY_MAC="${2:?Missing MAC}"; shift 2 ;;
    --no-dns) ENABLE_DNS=0; shift ;;
    --no-passive-arp) ENABLE_PASSIVE_ARP=0; shift ;;
    --no-process-watch) ENABLE_PROCESS_WATCH=0; shift ;;
    --no-desktop-alerts) ENABLE_DESKTOP_ALERTS=0; shift ;;
    --state-dir) STATE_DIR="${2:?Missing path}"; shift 2 ;;
    --log-dir) LOG_DIR="${2:?Missing path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }
valid_mac() { [[ "$1" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]; }

for n in "$INTERVAL" "$ARP_CAPTURE_SECONDS" "$ARP_FLOOD_THRESHOLD" "$ALERT_COOLDOWN"; do
  is_uint "$n" || { echo "Numeric option expected, got: $n" >&2; exit 2; }
done
(( INTERVAL >= 2 )) || { echo "Interval must be at least 2 seconds." >&2; exit 2; }

if [[ -n "$EXPECTED_GATEWAY_MAC" ]]; then
  EXPECTED_GATEWAY_MAC="${EXPECTED_GATEWAY_MAC,,}"
  valid_mac "$EXPECTED_GATEWAY_MAC" || { echo "Invalid gateway MAC: $EXPECTED_GATEWAY_MAC" >&2; exit 2; }
fi

if (( EUID != 0 )); then
  echo "Run as root: sudo $0 ..." >&2
  exit 1
fi

required=(arp-scan ip awk sort comm grep sed cut date sha256sum ss ps flock timeout logger paste tput)
(( ENABLE_DNS )) && required+=(dig)
(( ENABLE_PASSIVE_ARP )) && required+=(tcpdump)
missing=()
for cmd in "${required[@]}"; do command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd"); done
if ((${#missing[@]})); then
  printf 'Missing commands: %s\n' "${missing[*]}" >&2
  echo "Debian/Ubuntu example: sudo apt install arp-scan tcpdump dnsutils iproute2 procps util-linux libnotify-bin" >&2
  exit 1
fi

ip link show dev "$INTERFACE" >/dev/null 2>&1 || {
  echo "Interface not found: $INTERFACE" >&2
  exit 1
}

mkdir -p "$STATE_DIR" "$LOG_DIR"
chmod 700 "$STATE_DIR"
chmod 750 "$LOG_DIR"

CURRENT_ARP="$STATE_DIR/current_arp.tsv"
PREVIOUS_ARP="$STATE_DIR/previous_arp.tsv"
RAW_ARP="$STATE_DIR/raw_arp.txt"
PREVIOUS_LISTENERS="$STATE_DIR/previous_listeners.txt"
DNS_HASH_FILE="$STATE_DIR/resolv.hash"
GATEWAY_MAC_FILE="$STATE_DIR/gateway.mac"
EVENT_LOG="$LOG_DIR/events.tsv"
RUN_LOG="$LOG_DIR/monitor.log"
touch "$PREVIOUS_ARP" "$PREVIOUS_LISTENERS" "$EVENT_LOG" "$RUN_LOG"

exec 9>"$STATE_DIR/monitor.lock"
flock -n 9 || { echo "Another WolfNet Guard instance is already running." >&2; exit 1; }

cleanup() {
  tput cnorm 2>/dev/null || true
  printf '%b\n' "${C_RESET}Monitor stopped. Logs: $LOG_DIR"
}
trap cleanup EXIT INT TERM

tput civis 2>/dev/null || true

sanitize() {
  local value="${1//$'\n'/ }"
  value="${value//$'\r'/ }"
  printf '%s' "$value"
}

cooldown_ok() {
  local key="$1" now last
  now="$(date +%s)"
  last="${LAST_ALERT_AT[$key]:-0}"
  if (( now - last >= ALERT_COOLDOWN )); then
    LAST_ALERT_AT[$key]="$now"
    return 0
  fi
  return 1
}

send_desktop_alert() {
  local urgency="$1" title="$2" message="$3"
  (( ENABLE_DESKTOP_ALERTS )) || return 0
  command -v notify-send >/dev/null 2>&1 || return 0

  local target_user="${SUDO_USER:-}"
  if [[ -n "$target_user" && "$target_user" != "root" ]]; then
    local uid
    uid="$(id -u "$target_user" 2>/dev/null || true)"
    [[ -n "$uid" ]] || return 0
    sudo -u "$target_user" \
      DISPLAY="${DISPLAY:-:0}" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
      notify-send -u "$urgency" "$title" "$message" >/dev/null 2>&1 || true
  else
    notify-send -u "$urgency" "$title" "$message" >/dev/null 2>&1 || true
  fi
}

alert() {
  local severity="$1" key="$2" title="$3" message="$4"
  cooldown_ok "$key" || return 0

  local now color urgency
  now="$(date '+%Y-%m-%d %H:%M:%S')"
  case "$severity" in
    CRITICAL) color="$C_RED"; urgency="critical" ;;
    WARNING)  color="$C_YELLOW"; urgency="normal" ;;
    *)        color="$C_CYAN"; urgency="low" ;;
  esac

  LAST_EVENT="$severity: $title - $message"
  printf '%b[%s] [%s] %s: %s%b\a\n' "$color" "$now" "$severity" "$title" "$message" "$C_RESET" | tee -a "$RUN_LOG" >&2
  printf '%s\t%s\t%s\t%s\n' "$now" "$severity" "$(sanitize "$title")" "$(sanitize "$message")" >> "$EVENT_LOG"
  logger -t wolfnet-guard "[$severity] $title: $message" || true
  send_desktop_alert "$urgency" "WolfNet Guard: $title" "$message"

  if [[ -n "$ALERT_HOOK" && -x "$ALERT_HOOK" ]]; then
    "$ALERT_HOOK" "$severity" "$title" "$message" >/dev/null 2>&1 || true
  fi
}

refresh_network_identity() {
  LOCAL_MAC="$(cat "/sys/class/net/$INTERFACE/address" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"
  LOCAL_IP="$(ip -o -4 addr show dev "$INTERFACE" scope global 2>/dev/null | awk '{print $4}' | paste -sd ',' -)"
  GATEWAY_IP="$(ip -4 route show default dev "$INTERFACE" 2>/dev/null | awk 'NR==1 {print $3}')"

  [[ -n "$LOCAL_IP" ]] || alert WARNING "no-ip-$INTERFACE" "Interface has no IPv4 address" "$INTERFACE is up but has no global IPv4 address."
  [[ -n "$GATEWAY_IP" ]] || alert WARNING "no-gateway-$INTERFACE" "Default gateway missing" "No IPv4 default gateway was found on $INTERFACE."
}

passive_arp_check() {
  (( ENABLE_PASSIVE_ARP )) || { LAST_ARP_RATE=0; return 0; }
  [[ -n "$LOCAL_MAC" ]] || return 0

  local count
  count="$({ timeout "$ARP_CAPTURE_SECONDS" tcpdump -l -nn -e -i "$INTERFACE" "arp and not ether src $LOCAL_MAC" 2>/dev/null || true; } | grep -c 'ARP,' || true)"
  LAST_ARP_RATE="${count:-0}"
  if (( LAST_ARP_RATE >= ARP_FLOOD_THRESHOLD )); then
    alert WARNING "arp-flood-$INTERFACE" "Possible ARP flood" \
      "$LAST_ARP_RATE ARP frames observed in ${ARP_CAPTURE_SECONDS}s on $INTERFACE (threshold: $ARP_FLOOD_THRESHOLD)."
  fi
}

run_arp_scan() {
  local tmp="$STATE_DIR/current_arp.tmp"
  if ! arp-scan --interface="$INTERFACE" --localnet --retry=1 --timeout=500 >"$RAW_ARP" 2>>"$RUN_LOG"; then
    alert WARNING "arp-scan-failed-$INTERFACE" "ARP scan failed" "arp-scan returned an error on $INTERFACE."
    return 1
  fi

  awk -F '\t' '
    /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]/ {
      ip=$1; mac=tolower($2); vendor=$3;
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", ip);
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", mac);
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", vendor);
      if (ip != "" && mac != "") print ip "\t" mac "\t" vendor;
    }
  ' "$RAW_ARP" | sort -t $'\t' -k1,1V -k2,2 -u > "$tmp"
  mv "$tmp" "$CURRENT_ARP"
  LAST_SCAN_DEVICES="$(wc -l < "$CURRENT_ARP")"
}

check_duplicate_ip_claims() {
  local findings
  findings="$({ awk -F '\t' '
    /^[0-9]+\./ {
      ip=$1; mac=tolower($2);
      key=ip SUBSEP mac;
      if (!seen[key]++) { macs[ip]=(macs[ip] ? macs[ip] "," mac : mac); count[ip]++ }
    }
    END { for (ip in count) if (count[ip] > 1) print ip " => " macs[ip] }
  ' "$RAW_ARP"; } || true)"

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local ip="${line%% =>*}"
    alert CRITICAL "duplicate-ip-$ip" "Duplicate IP claim" "$line"
  done <<< "$findings"
}

check_duplicate_mac_claims() {
  local findings
  findings="$({ awk -F '\t' '
    { ip=$1; mac=$2; key=mac SUBSEP ip; if (!seen[key]++) { ips[mac]=(ips[mac] ? ips[mac] "," ip : ip); count[mac]++ } }
    END { for (mac in count) if (count[mac] > 1) print mac " => " ips[mac] }
  ' "$CURRENT_ARP"; } || true)"

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local mac="${line%% =>*}"
    alert WARNING "duplicate-mac-$mac" "MAC appears on multiple IPs" "$line"
  done <<< "$findings"
}

check_ip_mac_changes() {
  [[ -s "$PREVIOUS_ARP" ]] || return 0

  while IFS=$'\t' read -r ip mac vendor; do
    [[ -n "$ip" && -n "$mac" ]] || continue
    local old_mac
    old_mac="$(awk -F '\t' -v target="$ip" '$1==target {print $2; exit}' "$PREVIOUS_ARP")"
    if [[ -n "$old_mac" && "$old_mac" != "$mac" ]]; then
      alert CRITICAL "ip-mac-change-$ip" "IP-to-MAC mapping changed" \
        "$ip changed from $old_mac to $mac${vendor:+ ($vendor)}. This may be DHCP churn, failover, or ARP spoofing."
    fi
  done < "$CURRENT_ARP"
}

check_device_changes() {
  [[ -s "$PREVIOUS_ARP" ]] || return 0

  local previous_pairs="$STATE_DIR/previous_pairs.tmp"
  local current_pairs="$STATE_DIR/current_pairs.tmp"
  cut -f1,2 "$PREVIOUS_ARP" | sort -u > "$previous_pairs"
  cut -f1,2 "$CURRENT_ARP" | sort -u > "$current_pairs"

  while IFS=$'\t' read -r ip mac; do
    [[ -n "$ip" && -n "$mac" ]] || continue
    local vendor
    vendor="$(awk -F '\t' -v target="$mac" '$2==target {print $3; exit}' "$CURRENT_ARP")"
    alert INFO "new-device-$mac" "New LAN device" "$ip [$mac]${vendor:+ - $vendor}"
  done < <(comm -13 "$previous_pairs" "$current_pairs")

  while IFS=$'\t' read -r ip mac; do
    [[ -n "$ip" && -n "$mac" ]] || continue
    alert INFO "device-left-$mac" "Device no longer responding" "$ip [$mac]"
  done < <(comm -23 "$previous_pairs" "$current_pairs")

  rm -f "$previous_pairs" "$current_pairs"
}

get_gateway_mac() {
  local mac=""
  [[ -n "$GATEWAY_IP" ]] || return 0
  mac="$(awk -F '\t' -v target="$GATEWAY_IP" '$1==target {print $2; exit}' "$CURRENT_ARP")"
  if [[ -z "$mac" ]]; then
    ping -c1 -W1 "$GATEWAY_IP" >/dev/null 2>&1 || true
    mac="$(ip neigh show "$GATEWAY_IP" dev "$INTERFACE" 2>/dev/null | awk '{print tolower($5); exit}')"
  fi
  printf '%s' "$mac"
}

check_gateway_mac() {
  [[ -n "$GATEWAY_IP" ]] || return 0
  local observed baseline
  observed="$(get_gateway_mac)"
  [[ -n "$observed" ]] || {
    alert WARNING "gateway-unresolved-$GATEWAY_IP" "Gateway MAC unresolved" "Could not resolve the MAC address for gateway $GATEWAY_IP."
    return 0
  }

  if [[ -n "$EXPECTED_GATEWAY_MAC" ]]; then
    baseline="$EXPECTED_GATEWAY_MAC"
  elif [[ -s "$GATEWAY_MAC_FILE" ]]; then
    baseline="$(tr -d '[:space:]' < "$GATEWAY_MAC_FILE" | tr '[:upper:]' '[:lower:]')"
  else
    printf '%s\n' "$observed" > "$GATEWAY_MAC_FILE"
    baseline="$observed"
    alert INFO "gateway-baseline-$GATEWAY_IP" "Gateway baseline created" "$GATEWAY_IP is currently mapped to $observed. Verify this value manually."
  fi

  if [[ "$observed" != "$baseline" ]]; then
    alert CRITICAL "gateway-mac-change-$GATEWAY_IP" "Gateway MAC changed" \
      "$GATEWAY_IP expected $baseline but observed $observed. Possible ARP spoofing or legitimate router failover."
  fi
}

check_resolver_configuration() {
  local current_hash old_hash
  current_hash="$(sha256sum /etc/resolv.conf 2>/dev/null | awk '{print $1}')"
  [[ -n "$current_hash" ]] || return 0

  if [[ ! -s "$DNS_HASH_FILE" ]]; then
    printf '%s\n' "$current_hash" > "$DNS_HASH_FILE"
    return 0
  fi

  old_hash="$(cat "$DNS_HASH_FILE")"
  if [[ "$current_hash" != "$old_hash" ]]; then
    alert WARNING "resolv-conf-changed" "DNS resolver configuration changed" \
      "/etc/resolv.conf changed. Current nameservers: $(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf)"
    printf '%s\n' "$current_hash" > "$DNS_HASH_FILE"
  fi
}

csv_contains_ip() {
  local csv="$1" needle="$2" item
  IFS=',' read -r -a _items <<< "$csv"
  for item in "${_items[@]}"; do [[ "$item" == "$needle" ]] && return 0; done
  return 1
}

answers_overlap_expected() {
  local answers="$1" expected="$2" ip
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    csv_contains_ip "$expected" "$ip" && return 0
  done <<< "$answers"
  return 1
}

check_dns_canaries() {
  (( ENABLE_DNS )) || { LAST_DNS_STATUS="disabled"; return 0; }
  LAST_DNS_STATUS="OK"
  check_resolver_configuration

  local entry domain expected local_answers trusted_answers resolver reachable=0
  for entry in "${DNS_CANARIES[@]}"; do
    domain="${entry%%|*}"
    expected="${entry#*|}"
    local_answers="$(dig +time=2 +tries=1 +short A "$domain" 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u || true)"

    if [[ -z "$local_answers" ]]; then
      LAST_DNS_STATUS="local lookup failed"
      alert WARNING "dns-local-failed-$domain" "Local DNS lookup failed" "No IPv4 response for $domain using the configured resolver."
      continue
    fi

    if ! answers_overlap_expected "$local_answers" "$expected"; then
      LAST_DNS_STATUS="canary mismatch"
      alert CRITICAL "dns-canary-$domain" "DNS canary mismatch" \
        "$domain returned [$(paste -sd ',' <<< "$local_answers")] but expected one of [$expected]. Possible DNS interception or poisoning."
    fi

    reachable=0
    for resolver in "${TRUSTED_DNS[@]}"; do
      trusted_answers="$(dig "@$resolver" +time=2 +tries=1 +short A "$domain" 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u || true)"
      [[ -n "$trusted_answers" ]] || continue
      reachable=1
      if ! answers_overlap_expected "$trusted_answers" "$expected"; then
        alert WARNING "trusted-dns-unexpected-$resolver-$domain" "Trusted DNS returned unexpected data" \
          "$resolver returned [$(paste -sd ',' <<< "$trusted_answers")] for $domain. Verify upstream connectivity and records."
      fi
    done

    if (( ! reachable )); then
      LAST_DNS_STATUS="direct DNS blocked"
      alert INFO "direct-dns-blocked" "Direct DNS checks unavailable" "Queries to trusted resolvers were blocked or timed out; local canary validation remains active."
    fi
  done
}

normalize_listeners() {
  ss -H -lntup 2>/dev/null | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' | sort -u
}

check_netcat_and_listeners() {
  (( ENABLE_PROCESS_WATCH )) || { LAST_PROCESS_STATUS="disabled"; return 0; }
  LAST_PROCESS_STATUS="OK"

  local matches
  matches="$(ps -eo pid=,user=,comm=,args= | awk '
    BEGIN { IGNORECASE=1 }
    $3 ~ /^(nc|ncat|netcat|socat)$/ || $4 ~ /(^|\/)(nc|ncat|netcat|socat)([[:space:]]|$)/ { print }
  ' || true)"

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    local pid comm key
    pid="$(awk '{print $1}' <<< "$line")"
    comm="$(awk '{print $3}' <<< "$line")"
    key="netcat-process-${pid}-${comm}"
    LAST_PROCESS_STATUS="suspicious process"
    alert WARNING "$key" "Netcat-style process detected" "$(sanitize "$line")"
  done <<< "$matches"

  local current_listeners="$STATE_DIR/current_listeners.tmp"
  normalize_listeners > "$current_listeners"

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if grep -Eiq 'users:.*"(nc|ncat|netcat|socat)"' <<< "$line"; then
      LAST_PROCESS_STATUS="suspicious listener"
      alert CRITICAL "netcat-listener-$(printf '%s' "$line" | sha256sum | cut -c1-12)" \
        "Netcat-style listener detected" "$line"
    fi
  done < "$current_listeners"

  if [[ -s "$PREVIOUS_LISTENERS" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      if ! grep -Eq '(127\.0\.0\.1|\[::1\])' <<< "$line"; then
        alert INFO "new-listener-$(printf '%s' "$line" | sha256sum | cut -c1-12)" \
          "New listening socket" "$line"
      fi
    done < <(comm -13 "$PREVIOUS_LISTENERS" "$current_listeners")
  fi

  cp "$current_listeners" "$PREVIOUS_LISTENERS"
  rm -f "$current_listeners"
}

render_dashboard() {
  local now uptime_seconds gateway_mac dns_servers
  now="$(date '+%Y-%m-%d %H:%M:%S')"
  uptime_seconds=$(( $(date +%s) - START_TIME ))
  gateway_mac="$(get_gateway_mac)"
  dns_servers="$(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"

  clear
  printf '%b' "$C_GREEN"
  cat <<'BANNER'
 __          __  _  __ _   _      _     _____                     _
 \ \        / / | |/ _| \ | |    | |   / ____|                   | |
  \ \  /\  / /__| | |_|  \| | ___| |_ | |  __ _   _  __ _ _ __ __| |
   \ \/  \/ / _ \ |  _| . ` |/ _ \ __|| | |_ | | | |/ _` | '__/ _` |
    \  /\  /  __/ | | | |\  |  __/ |_ | |__| | |_| | (_| | | | (_| |
     \/  \/ \___|_|_| |_| \_|\___|\__| \_____|\__,_|\__,_|_|  \__,_|
BANNER
  printf '%b\n' "$C_RESET"
  printf '%bDefensive LAN Monitor%b  v%s  |  Author: Aung Myat Thu\n' "$C_WHITE" "$C_RESET" "$VERSION"
  printf '%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n' "$C_DIM" "$C_RESET"
  printf '%bTime%b           %s\n' "$C_CYAN" "$C_RESET" "$now"
  printf '%bInterface%b      %s  MAC: %s  IPv4: %s\n' "$C_CYAN" "$C_RESET" "$INTERFACE" "${LOCAL_MAC:-unknown}" "${LOCAL_IP:-none}"
  printf '%bGateway%b        %s  MAC: %s\n' "$C_CYAN" "$C_RESET" "${GATEWAY_IP:-none}" "${gateway_mac:-unresolved}"
  printf '%bDNS servers%b    %s\n' "$C_CYAN" "$C_RESET" "${dns_servers:-none}"
  printf '%bDevices%b        %s discovered\n' "$C_CYAN" "$C_RESET" "$LAST_SCAN_DEVICES"
  printf '%bARP activity%b   %s frames / %ss  (threshold %s)\n' "$C_CYAN" "$C_RESET" "$LAST_ARP_RATE" "$ARP_CAPTURE_SECONDS" "$ARP_FLOOD_THRESHOLD"
  printf '%bDNS status%b     %s\n' "$C_CYAN" "$C_RESET" "$LAST_DNS_STATUS"
  printf '%bProcess watch%b  %s\n' "$C_CYAN" "$C_RESET" "$LAST_PROCESS_STATUS"
  printf '%bUptime%b         %ss\n' "$C_CYAN" "$C_RESET" "$uptime_seconds"
  printf '%bLast event%b     %s\n' "$C_YELLOW" "$C_RESET" "$LAST_EVENT"
  printf '%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n' "$C_DIM" "$C_RESET"
  printf '%b%-16s %-18s %s%b\n' "$C_WHITE" "IP ADDRESS" "MAC ADDRESS" "VENDOR" "$C_RESET"
  printf '%b%-16s %-18s %s%b\n' "$C_DIM" "----------" "-----------" "------" "$C_RESET"

  if [[ -s "$CURRENT_ARP" ]]; then
    while IFS=$'\t' read -r ip mac vendor; do
      printf '%-16s %-18s %s\n' "$ip" "$mac" "${vendor:-Unknown}"
    done < "$CURRENT_ARP"
  else
    printf '%bNo devices discovered.%b\n' "$C_YELLOW" "$C_RESET"
  fi

  printf '%b━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%b\n' "$C_DIM" "$C_RESET"
  printf 'Next cycle in %ss | Ctrl+C to stop | Events: %s\n' "$INTERVAL" "$EVENT_LOG"
}

main_loop() {
  refresh_network_identity
  normalize_listeners > "$PREVIOUS_LISTENERS" || true

  while true; do
    refresh_network_identity
    passive_arp_check

    if run_arp_scan; then
      check_duplicate_ip_claims
      check_duplicate_mac_claims
      check_ip_mac_changes
      check_device_changes
      check_gateway_mac
      check_dns_canaries
      check_netcat_and_listeners
      render_dashboard
      cp "$CURRENT_ARP" "$PREVIOUS_ARP"
    else
      render_dashboard
    fi

    sleep "$INTERVAL"
  done
}

main_loop
