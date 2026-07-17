# WolfNet Guard

```text
 __          __  _  __ _   _      _     _____                     _
 \ \        / / | |/ _| \ | |    | |   / ____|                   | |
  \ \  /\  / /__| | |_|  \| | ___| |_ | |  __ _   _  __ _ _ __ __| |
   \ \/  \/ / _ \ |  _| . ` |/ _ \ __|| | |_ | | | |/ _` | '__/ _` |
    \  /\  /  __/ | | | |\  |  __/ |_ | |__| | |_| | (_| | | | (_| |
     \/  \/ \___|_|_| |_| \_|\___|\__| \_____|\__,_|\__,_|_|  \__,_|
```

**WolfNet Guard** is a defensive Linux LAN-monitoring utility that combines active ARP discovery, passive ARP-rate monitoring, gateway identity checks, DNS consistency checks, local Netcat-style process detection, socket monitoring, terminal alerts, desktop notifications, system logging, and persistent state tracking.

**Author:** Aung Myat Thu  
**Version:** 1.1.0  
**Platform:** Linux  
**Purpose:** Authorized monitoring of networks and systems you own or administer.

> WolfNet Guard is an early-warning and visibility tool. It does not replace a managed switch, IDS/IPS, endpoint detection platform, packet-analysis system, or a properly designed network-monitoring architecture.

---

## Features

### LAN device monitoring

- Repeatedly scans the local Layer 2 network with `arp-scan`.
- Displays discovered IPv4 addresses, MAC addresses, and vendor names.
- Reports newly observed devices.
- Reports devices that no longer respond to the latest scan.
- Detects an IPv4 address appearing with more than one MAC address.
- Detects a MAC address appearing on more than one IPv4 address.
- Detects IP-to-MAC mapping changes between monitoring cycles.

### ARP-spoofing indicators

- Learns or accepts a pinned default-gateway MAC address.
- Raises a critical alert when the observed gateway MAC differs from the expected value.
- Captures ARP traffic for a configurable window with `tcpdump`.
- Raises an alert when ARP activity exceeds a configurable threshold.
- Detects duplicate IPv4 claims found in raw ARP-scan results.

### DNS monitoring

- Detects changes to `/etc/resolv.conf`.
- Queries known DNS canary names using the system-configured resolver.
- Compares returned IPv4 addresses with expected values.
- Attempts direct comparison queries through trusted public resolvers.
- Reports local lookup failures, canary mismatches, unexpected upstream answers, and blocked direct-DNS checks.

### Netcat and listener monitoring

- Searches the local process table for:
  - `nc`
  - `ncat`
  - `netcat`
  - `socat`
- Detects listening sockets associated with those processes.
- Reports newly opened non-loopback listening sockets.
- Tracks socket state between monitoring cycles.

### Alerting and evidence

- Color-coded terminal alerts.
- Terminal bell on alerts.
- Desktop notifications through `notify-send` when available.
- Syslog/journald events through `logger`.
- Human-readable runtime log.
- Tab-separated event log for later filtering or import.
- Configurable repeated-alert cooldown.
- Optional executable alert hook for custom integrations.

### Operator dashboard

The live terminal dashboard shows:

- Current date and time
- Interface name
- Local MAC address
- Local IPv4 address
- Default gateway and observed gateway MAC
- Configured DNS servers
- Number of discovered LAN devices
- Passive ARP activity
- DNS-check status
- process-watch status
- Monitor uptime
- Latest alert
- Current ARP-discovered device table

---

## Detection overview

| Detection | Severity | What it may indicate |
|---|---:|---|
| Duplicate IP claim | Critical | ARP spoofing, static-IP conflict, duplicate configuration, or failover behavior |
| IP-to-MAC mapping change | Critical | ARP spoofing, DHCP reassignment, NIC replacement, VM movement, or failover |
| Gateway MAC mismatch | Critical | Gateway impersonation, ARP spoofing, router replacement, or HA failover |
| DNS canary mismatch | Critical | DNS poisoning, interception, captive portal, filtering, or unexpected record changes |
| Netcat-style listener | Critical | Deliberate administrative listener, troubleshooting tool, reverse-shell handler, or unauthorized service |
| Possible ARP flood | Warning | ARP scan, broadcast storm, spoofing activity, discovery tool, or busy Layer 2 segment |
| MAC on multiple IPs | Warning | Proxy ARP, multi-IP host, container/virtual networking, or suspicious reuse |
| Resolver configuration changed | Warning | DHCP update, VPN connection, administrator change, or resolver manipulation |
| Netcat-style process | Warning | Legitimate troubleshooting or an unauthorized network utility |
| New LAN device | Info | Newly connected endpoint or a device that became responsive |
| Device no longer responding | Info | Device departure, sleep, firewall behavior, packet loss, or scan failure |
| New listening socket | Info | Newly started local network service |

Alerts are indicators, not automatic proof of compromise. Investigate the surrounding network and system context before taking action.

---

## Requirements

WolfNet Guard must run as `root` because ARP scanning, packet capture, and complete socket/process visibility require elevated privileges.

Required commands:

```text
arp-scan
ip
awk
sort
comm
grep
sed
cut
date
sha256sum
ss
ps
flock
timeout
logger
paste
tput
ping
dig          # when DNS checks are enabled
tcpdump      # when passive ARP checks are enabled
notify-send  # optional desktop notifications
```

### Debian and Ubuntu

```bash
sudo apt update
sudo apt install -y \
  arp-scan \
  tcpdump \
  dnsutils \
  iproute2 \
  iputils-ping \
  procps \
  util-linux \
  coreutils \
  gawk \
  grep \
  sed \
  libnotify-bin \
  ncurses-bin
```

### Arch Linux and Manjaro

```bash
sudo pacman -S --needed \
  arp-scan \
  tcpdump \
  bind \
  iproute2 \
  iputils \
  procps-ng \
  util-linux \
  coreutils \
  gawk \
  grep \
  sed \
  libnotify \
  ncurses
```

Verify the main dependencies:

```bash
for command in arp-scan tcpdump dig ip ss ps flock logger notify-send; do
  command -v "$command" || echo "Missing: $command"
done
```

---

## Installation

Place the script in a dedicated directory:

```bash
mkdir -p ~/tools/wolfnet-guard
cp wolfnet_guard.sh ~/tools/wolfnet-guard/
cd ~/tools/wolfnet-guard
chmod +x wolfnet_guard.sh
```

Optional system-wide installation:

```bash
sudo install -m 0755 wolfnet_guard.sh /usr/local/bin/wolfnet-guard
```

After system-wide installation, run it as:

```bash
sudo wolfnet-guard --interface eno2
```

If the downloaded script uses the versioned filename, you may keep it or rename it:

```bash
mv wolfnet_guard_v1.1.0.sh wolfnet_guard.sh
chmod +x wolfnet_guard.sh
```

Validate the Bash syntax before the first run:

```bash
bash -n wolfnet_guard.sh
```

Display the built-in help:

```bash
./wolfnet_guard.sh --help
```

---

## Identify the correct interface

List interfaces and addresses:

```bash
ip -br link
ip -br address
```

Typical interface names include:

```text
eno1
eno2
enp3s0
eth0
wlan0
wlp2s0
```

Check which interface carries the default route:

```bash
ip route show default
```

Example result:

```text
default via 192.168.1.1 dev eno2 proto dhcp src 192.168.1.20 metric 100
```

In this example, the interface is `eno2` and the gateway is `192.168.1.1`.

---

## Quick start

Run with the default 15-second interval:

```bash
sudo ./wolfnet_guard.sh --interface eno2
```

Run every 10 seconds:

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --interval 10
```

Press `q` or `Q` to stop the monitor cleanly. You can also use `Ctrl+C`.

The `q`/`Q` control is handled by a dedicated keyboard watcher, so it remains responsive while the main loop is scanning, capturing ARP traffic, or running DNS checks.

---

## Keyboard controls and clean shutdown

WolfNet Guard 1.1.0 supports responsive keyboard-based shutdown:

| Control | Result |
|---|---|
| `q` or `Q` | Requests a clean shutdown from the live dashboard |
| `Ctrl+C` | Requests the same clean shutdown through `SIGINT` |
| `SIGTERM` | Stops cleanly when terminated by a service manager or another process |
| Terminal close | Handles `SIGHUP` and restores the terminal where possible |

The keyboard watcher runs separately from the monitoring cycle. This allows `q` or `Q` to be recognized even while the main process is performing an ARP scan, passive capture, or DNS query.

During shutdown, WolfNet Guard:

1. Stops accepting new monitoring work.
2. Terminates the keyboard-watcher process.
3. Avoids reporting an interrupted scan as a false scan-failure alert.
4. Restores the terminal cursor.
5. Resets terminal formatting.
6. Prints the shutdown reason and log-directory location.
7. Runs cleanup only once.

Example clean-shutdown messages:

```text
WolfNet Guard stopped cleanly (q pressed).
Logs: /var/log/wolfnet-guard
```

```text
WolfNet Guard stopped cleanly (Ctrl+C).
Logs: /var/log/wolfnet-guard
```

> `q` and `Q` require an interactive terminal connected to standard input. When running non-interactively, use `SIGTERM`, `Ctrl+C` from the attached terminal, or your service manager's normal stop command.

---

## Pin the gateway MAC address

Gateway monitoring is strongest when the correct MAC address is supplied from a trusted source.

First identify the default gateway:

```bash
GATEWAY_IP="$(ip -4 route show default dev eno2 | awk 'NR==1 {print $3}')"
echo "$GATEWAY_IP"
```

Populate the neighbor table and inspect the result:

```bash
ping -c 1 "$GATEWAY_IP"
ip neigh show "$GATEWAY_IP" dev eno2
```

Example:

```text
192.168.1.1 lladdr aa:bb:cc:dd:ee:ff REACHABLE
```

Confirm this MAC through a trusted source such as:

- The router administration interface
- The router label or inventory record
- A managed-switch MAC-address table
- A separate trusted administrator workstation

Then pin it:

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --gateway-mac aa:bb:cc:dd:ee:ff
```

The same value can be supplied through an environment variable:

```bash
sudo EXPECTED_GATEWAY_MAC=aa:bb:cc:dd:ee:ff \
  ./wolfnet_guard.sh --interface eno2
```

### Automatic gateway baseline

When no expected MAC is supplied, the first observed gateway MAC is stored in:

```text
/var/lib/wolfnet-guard/gateway.mac
```

The script then compares future observations with that learned value.

> An automatically learned baseline is only trustworthy when the network is known to be clean during the first run. Pinning a manually verified MAC is safer.

---

## Command-line options

```text
Usage: sudo wolfnet_guard.sh [options]

-i, --interface NAME        Network interface; default: eno2
-t, --interval SECONDS      Delay after each cycle; default: 15
    --arp-window SECONDS    Passive ARP capture window; default: 3
    --arp-threshold COUNT   ARP frames before an alert; default: 100
    --cooldown SECONDS      Repeated-alert cooldown; default: 120
    --gateway-mac MAC       Expected default-gateway MAC address
    --no-dns                Disable DNS checks
    --no-passive-arp        Disable passive ARP-rate monitoring
    --no-process-watch      Disable Netcat/Socat and listener checks
    --no-desktop-alerts     Disable notify-send alerts
    --state-dir PATH        Override the persistent-state directory
    --log-dir PATH          Override the log directory
-h, --help                  Display help
```

The scan cycle takes longer than the configured interval because passive ARP capture, ARP scanning, DNS requests, and process checks run before the countdown begins.

The countdown updates once per second and displays `Press q to quit`. The dedicated keyboard watcher also allows `q` or `Q` to request shutdown during long-running checks rather than only during the countdown.

---

## Usage examples

### Standard workstation monitoring

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --interval 10 \
  --gateway-mac aa:bb:cc:dd:ee:ff
```

### More sensitive ARP-rate monitoring

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --interval 8 \
  --arp-window 5 \
  --arp-threshold 60 \
  --cooldown 60
```

Lower thresholds increase sensitivity but can produce more alerts on busy networks.

### Quieter monitoring without desktop notifications

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --interval 20 \
  --no-desktop-alerts
```

### Disable direct DNS monitoring

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --no-dns
```

### Disable passive packet capture

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --no-passive-arp
```

### Disable process and listener monitoring

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --no-process-watch
```

### Use project-local state and logs

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --state-dir /opt/wolfnet-guard/state \
  --log-dir /opt/wolfnet-guard/logs
```

---

## Alert destinations

### Terminal

Alerts appear above or between dashboard refreshes with:

- Timestamp
- Severity
- Alert title
- Alert description
- Terminal bell

### Desktop notifications

When `notify-send` is installed, WolfNet Guard attempts to deliver the notification to the original user who invoked `sudo`.

Disable these notifications when necessary:

```bash
sudo ./wolfnet_guard.sh --interface eno2 --no-desktop-alerts
```

Desktop notifications can fail in some Wayland sessions, remote shells, minimal window managers, or sessions without an accessible D-Bus user bus. Terminal and file logging continue to work.

### Syslog and journald

Follow live events:

```bash
sudo journalctl -f -t wolfnet-guard
```

Show events from the current boot:

```bash
sudo journalctl -b -t wolfnet-guard
```

### Runtime log

```text
/var/log/wolfnet-guard/monitor.log
```

Follow it live:

```bash
sudo tail -f /var/log/wolfnet-guard/monitor.log
```

### Structured event log

```text
/var/log/wolfnet-guard/events.tsv
```

Fields:

```text
timestamp    severity    title    message
```

View aligned columns:

```bash
sudo column -s $'\t' -t /var/log/wolfnet-guard/events.tsv | less -S
```

Follow new structured events:

```bash
sudo tail -f /var/log/wolfnet-guard/events.tsv
```

Show only critical events:

```bash
sudo awk -F '\t' '$2 == "CRITICAL"' /var/log/wolfnet-guard/events.tsv
```

Count events by severity:

```bash
sudo awk -F '\t' '{count[$2]++} END {for (level in count) print level, count[level]}' \
  /var/log/wolfnet-guard/events.tsv
```

---

## Custom alert hook

Set `ALERT_HOOK` to an executable file. WolfNet Guard calls it with three arguments:

```text
$1 = severity
$2 = title
$3 = message
```

Create a basic hook:

```bash
sudo tee /usr/local/bin/wolfnet-alert-hook >/dev/null <<'HOOK'
#!/usr/bin/env bash
set -u

severity="${1:-UNKNOWN}"
title="${2:-Untitled}"
message="${3:-No message}"

printf '%s\t%s\t%s\t%s\n' \
  "$(date '+%Y-%m-%d %H:%M:%S')" \
  "$severity" \
  "$title" \
  "$message" \
  >> /var/log/wolfnet-guard/custom-alerts.tsv
HOOK

sudo chmod 0755 /usr/local/bin/wolfnet-alert-hook
```

Run WolfNet Guard with the hook:

```bash
sudo ALERT_HOOK=/usr/local/bin/wolfnet-alert-hook \
  ./wolfnet_guard.sh --interface eno2
```

The hook is executed once per emitted alert after cooldown filtering. Hook output is discarded by the main script, and a hook failure does not stop monitoring.

Keep credentials outside the hook source code when integrating email, chat, SIEM, or webhook platforms.

---

## Persistent state

Default state directory:

```text
/var/lib/wolfnet-guard
```

| File | Purpose |
|---|---|
| `current_arp.tsv` | Latest normalized ARP-scan result |
| `previous_arp.tsv` | Previous scan used for change comparison |
| `raw_arp.txt` | Raw output from the latest `arp-scan` execution |
| `previous_listeners.txt` | Previous normalized listening-socket list |
| `resolv.hash` | SHA-256 baseline of `/etc/resolv.conf` |
| `gateway.mac` | Automatically learned gateway-MAC baseline |
| `monitor.lock` | Prevents multiple instances using the same state directory |

The state directory is created with mode `700`.

Default log directory:

```text
/var/log/wolfnet-guard
```

The log directory is created with mode `750`.

---

## Reset baselines

Stop WolfNet Guard before changing its state files.

### Reset only the learned gateway MAC

```bash
sudo rm -f /var/lib/wolfnet-guard/gateway.mac
```

On the next run, the script learns the currently observed gateway MAC again unless `--gateway-mac` is supplied.

### Reset the DNS resolver baseline

```bash
sudo rm -f /var/lib/wolfnet-guard/resolv.hash
```

### Reset device and listener comparison state

```bash
sudo rm -f \
  /var/lib/wolfnet-guard/previous_arp.tsv \
  /var/lib/wolfnet-guard/previous_listeners.txt
```

### Reset all state

```bash
sudo rm -rf /var/lib/wolfnet-guard
```

Only reset baselines after verifying that the current gateway, DNS settings, devices, and listeners are legitimate. Resetting during an active incident can make malicious state appear trusted.

---

## Safe validation tests

Perform tests only on systems and networks you are authorized to administer.

### Confirm ARP discovery

```bash
sudo arp-scan --interface=eno2 --localnet --retry=1
```

### Confirm passive ARP visibility

```bash
sudo tcpdump -ni eno2 arp
```

Generate normal ARP activity from another authorized terminal:

```bash
ping -c 2 "$(ip -4 route show default dev eno2 | awk 'NR==1 {print $3}')"
```

### Confirm DNS canaries

```bash
dig +short A one.one.one.one
dig +short A dns.google
dig +short A resolver1.opendns.com
```

### Confirm local Netcat-process detection

In an isolated lab terminal:

```bash
nc -lvnp 4444
```

WolfNet Guard should report the Netcat-style process and its listening socket. Stop the test with `Ctrl+C`.

### Confirm generic new-listener detection

```bash
python3 -m http.server 8088 --bind 0.0.0.0
```

WolfNet Guard should report a new non-loopback listening socket. Stop the test with `Ctrl+C`.

### Confirm gateway mismatch alert logic without spoofing

Run a temporary test using a deliberately incorrect expected MAC:

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --gateway-mac 00:11:22:33:44:55 \
  --cooldown 10
```

This checks the comparison and alert path without performing an ARP attack. Stop the test after confirming the alert, then restart with the verified gateway MAC.

---

## How the monitoring cycle works

Each cycle follows this sequence:

1. Read the local interface identity and default gateway.
2. Capture passive ARP traffic for the configured window.
3. Run an active `arp-scan` across the local IPv4 subnet.
4. Normalize the IP, MAC, and vendor results.
5. Check duplicate IP and duplicate MAC observations.
6. Compare IP-to-MAC mappings with the previous scan.
7. Compare connected-device pairs with the previous scan.
8. Resolve and validate the gateway MAC address.
9. Check resolver configuration and DNS canaries.
10. Inspect local processes and listening sockets.
11. Render the live terminal dashboard.
12. Save current state as the baseline for the next cycle.
13. Run a one-second countdown for the configured interval while continuing to accept `q`/`Q` shutdown input.

The first cycle establishes several baselines. Device-change comparison begins after a previous scan exists.

---

## Understanding ARP alerts

### Duplicate IP claim

The raw ARP scan contains the same IPv4 address with different MAC addresses. Possible causes include:

- ARP spoofing
- Duplicate static-IP configuration
- DHCP conflict
- High-availability transition
- Proxy behavior
- A rapidly changing or unstable network

Recommended checks:

```bash
ip neigh show dev eno2
sudo arp-scan --interface=eno2 --localnet --retry=3
sudo tcpdump -ni eno2 -e arp
```

Compare the suspicious MAC against switch tables, DHCP leases, router records, virtualization platforms, and endpoint inventory.

### Gateway MAC changed

Treat an unexpected gateway-MAC change as high priority, especially on a stable office or home LAN.

Verify through:

```bash
ip route show default
ip neigh show dev eno2
sudo arp-scan --interface=eno2 --localnet
```

Also check:

- Router administrative interface
- Managed-switch forwarding table
- DHCP server leases
- VRRP, HSRP, CARP, or cluster failover events
- Recent router replacement or firmware recovery

### Possible ARP flood

The threshold counts observed ARP frames during the configured capture window. Busy networks, discovery tools, vulnerability scanners, monitoring platforms, large wireless segments, and network loops can all raise the count.

Tune carefully:

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --arp-window 5 \
  --arp-threshold 150
```

First observe normal peak traffic before setting a production threshold.

---

## Understanding DNS alerts

DNS detection is heuristic. WolfNet Guard checks selected public names that are expected to return known IPv4 addresses.

A mismatch can be caused by:

- DNS poisoning or spoofing
- Captive portals
- Security filtering
- ISP redirection
- Split-horizon DNS
- VPN resolver behavior
- Corporate DNS proxies
- Transparent DNS interception
- Legitimate upstream record changes

Direct queries to public resolvers can be blocked by firewalls or policies that force all DNS through a local resolver. In that case, WolfNet Guard emits an informational alert and continues local validation.

The current implementation checks IPv4 `A` records only. It does not validate DNSSEC signatures and does not inspect encrypted DNS such as DoH or DoT.

---

## Understanding Netcat alerts

WolfNet Guard detects Netcat-style tools on the local Linux machine by examining process names, command lines, and listening sockets.

It does **not** reliably determine that a remote host is using Netcat. Netcat has no mandatory port, protocol marker, banner, or unique packet signature. Its traffic can look like ordinary TCP or UDP application traffic.

A detected process can be legitimate. Administrators commonly use Netcat and Socat for:

- Port testing
- File transfer in controlled environments
- Service debugging
- Banner checks
- Temporary listeners
- Network troubleshooting

Investigate the process owner, parent process, command line, listening address, port, start time, open files, and network connections.

Useful commands:

```bash
ps -fp PID
sudo pstree -aps PID
sudo lsof -nP -p PID
sudo ss -lntup
sudo ss -ntup
sudo readlink -f /proc/PID/exe
sudo tr '\0' ' ' < /proc/PID/cmdline; echo
```

Replace `PID` with the actual process ID shown in the alert.

---

## Troubleshooting

### `Run as root`

Use:

```bash
sudo ./wolfnet_guard.sh --interface eno2
```

### `Interface not found`

List available interfaces:

```bash
ip -br link
```

Then pass the correct name:

```bash
sudo ./wolfnet_guard.sh --interface enp3s0
```

### `Missing commands`

Install the listed dependencies for your distribution. Verify each missing command with:

```bash
command -v COMMAND_NAME
```

### No devices are discovered

Check:

```bash
ip -4 address show dev eno2
ip route show dev eno2
sudo arp-scan --interface=eno2 --localnet --retry=3
```

Possible causes:

- Wrong interface
- Interface has no IPv4 address
- Client isolation on Wi-Fi
- VLAN separation
- Running through a routed tunnel
- Unsupported Layer 2 environment
- Insufficient privileges
- Network driver or capture restrictions

### Gateway MAC cannot be resolved

Check:

```bash
ip -4 route show default dev eno2
ping -c 1 "$(ip -4 route show default dev eno2 | awk 'NR==1 {print $3}')"
ip neigh show dev eno2
```

Confirm that the selected interface actually owns the active default route.

### Direct DNS checks fail

Test manually:

```bash
dig @1.1.1.1 +time=2 +tries=1 one.one.one.one A
dig @9.9.9.9 +time=2 +tries=1 dns.google A
```

Your firewall, VPN, ISP, or organization may block direct port 53 traffic. This does not automatically mean DNS spoofing.

### Desktop notifications do not appear

Confirm the package and user session:

```bash
command -v notify-send
notify-send "WolfNet Guard test" "Desktop notification test"
```

Notifications may not cross correctly into Wayland sessions, SSH sessions, containers, or systems without a graphical D-Bus session. Use journald and log files as the reliable alert channels.

### Another instance is already running

WolfNet Guard uses a state-directory lock. Find the running process:

```bash
pgrep -af wolfnet_guard
```

Stop the existing instance safely before starting another one with the same state directory.

To run separate monitors for different interfaces, give each instance a different state directory and preferably a different log directory:

```bash
sudo ./wolfnet_guard.sh \
  --interface eno2 \
  --state-dir /var/lib/wolfnet-guard-eno2 \
  --log-dir /var/log/wolfnet-guard-eno2
```

### Pressing `q` does not quit

Confirm that WolfNet Guard is attached to an interactive terminal:

```bash
test -t 0 && echo "Interactive input available" || echo "No interactive input"
```

Run it directly rather than piping standard input:

```bash
sudo ./wolfnet_guard.sh --interface eno2
```

`q` may not work when the process is started with closed or redirected standard input, from some background-job configurations, or from a service without a terminal. Stop it using one of these methods:

```bash
sudo pkill -TERM -f wolfnet_guard.sh
```

```bash
sudo kill -TERM PID
```

For an attached terminal, `Ctrl+C` remains available.

### The screen refresh behaves badly in a service or redirected terminal

Version 1.1.0 is designed primarily for an interactive terminal. The dashboard calls `clear`, hides and restores the cursor, reads single-key input, and uses terminal-control sequences. Run it directly in a terminal, `tmux`, or `screen`.

When standard input is not a terminal, the keyboard watcher is not started. In that mode, `q`/`Q` is unavailable, but `SIGTERM`, `SIGINT`, and `SIGHUP` still use the clean shutdown path.

A dedicated non-interactive or systemd mode would require a small script change to disable dashboard rendering and optionally redirect output entirely to journald or log files.

---

## Recommended operational workflow

1. Verify the correct monitoring interface.
2. Record the legitimate gateway IP and MAC from a trusted source.
3. Run the monitor while the network is known to be clean.
4. Pin the trusted gateway MAC rather than relying only on automatic learning.
5. Observe normal ARP volume before lowering thresholds.
6. Review informational alerts and identify expected devices and services.
7. Forward critical events to your chosen alerting system through `ALERT_HOOK`.
8. Protect state and log directories from unauthorized modification.
9. Rotate and preserve logs according to your incident-response policy.
10. Investigate alerts using switch, router, DHCP, DNS, endpoint, and packet evidence.

---

## Security and accuracy limitations

- ARP monitoring applies only to the local IPv4 Layer 2 broadcast domain.
- Routed networks and separate VLANs require a monitor inside each segment.
- IPv6 Neighbor Discovery, Router Advertisement spoofing, and DHCPv6 attacks are not monitored.
- DNS checking currently validates selected IPv4 answers, not DNSSEC.
- Direct public-DNS queries may be blocked by legitimate network policy.
- Netcat identification is local-process based and cannot reliably identify remote Netcat usage.
- New-listener detection identifies change, not malicious intent.
- `arp-scan` is active discovery and creates network traffic.
- Sleeping, mobile, wireless, and firewalled devices may appear to leave and rejoin.
- DHCP lease changes can generate IP-to-MAC alerts.
- MAC randomization can create repeated new-device alerts.
- Router HA technologies can legitimately change the observed gateway identity.
- Containers, hypervisors, proxy ARP, and multi-address hosts can trigger duplicate-MAC alerts.
- The in-memory cooldown cache resets whenever the script restarts.
- The tool does not automatically block, quarantine, kill, or modify network traffic.

Automatic response is intentionally avoided because false positives could disconnect legitimate devices or interrupt production services.

---

## Incident-response guidance

When a critical alert appears:

1. Record the timestamp, interface, IP address, MAC address, process, and socket details.
2. Preserve `events.tsv`, `monitor.log`, `raw_arp.txt`, and relevant journald entries.
3. Confirm whether a legitimate network, DHCP, router, VPN, or service change occurred.
4. Compare DHCP leases, switch MAC tables, access-point client lists, and router ARP tables.
5. Capture relevant traffic with an approved incident-response process.
6. Isolate a suspicious endpoint only when authorized and operationally safe.
7. Avoid resetting baselines until evidence has been preserved and reviewed.

Export recent WolfNet Guard journald entries:

```bash
sudo journalctl -t wolfnet-guard --since "1 hour ago" \
  > wolfnet-guard-journal.txt
```

Copy the current evidence files:

```bash
sudo mkdir -p /tmp/wolfnet-evidence
sudo cp -a /var/log/wolfnet-guard /tmp/wolfnet-evidence/
sudo cp -a /var/lib/wolfnet-guard /tmp/wolfnet-evidence/
sudo tar -czf /tmp/wolfnet-evidence.tar.gz -C /tmp wolfnet-evidence
```

Protect and hash the archive according to your normal evidence-handling procedure.

---

## Version history

### 1.1.0

- Added clean `q`/`Q` shutdown from the live interface.
- Added a dedicated keyboard watcher so quit input remains responsive during monitoring work.
- Unified `q`, `Ctrl+C`, `SIGTERM`, and terminal-close handling.
- Added single-run cleanup protection.
- Restores cursor visibility and terminal formatting on shutdown.
- Stops the keyboard watcher during cleanup.
- Prevents interrupted scans and checks from creating false failure alerts.
- Added a visible one-second next-scan countdown.
- Improved distribution-specific dependency guidance, including the Arch Linux and Manjaro `bind` package for `dig`.

### 1.0.0

- Initial defensive LAN-monitoring release.

---

## Suggested future improvements

- IPv6 NDP and Router Advertisement monitoring
- DHCP and rogue-DHCP-server detection
- Device allowlists and approved IP-to-MAC inventory
- JSON and JSON Lines output
- Non-interactive daemon mode
- Native systemd service support
- Config file support
- Email, Slack, Teams, Telegram, and SIEM integrations
- Web dashboard and metrics endpoint
- Packet-ring or asynchronous capture for lower cycle latency
- DNSSEC-aware validation
- Optional packet capture around critical alerts
- Switch CAM-table integration
- Manufacturer and device-history database
- Alert acknowledgment and case tracking

---

## Project files

```text
wolfnet-guard/
├── wolfnet_guard.sh
└── README.md

# Release download filename:
wolfnet_guard_v1.1.0.sh
```

---

## Responsible use

Use WolfNet Guard only on networks and systems that you own or are explicitly authorized to monitor. Follow applicable organizational policies, privacy requirements, employment rules, and local laws.

The script is designed for defensive monitoring and visibility. It does not include exploitation, spoofing, interception, persistence, credential collection, or automatic retaliation capabilities.

---

## Author

**Aung Myat Thu**
