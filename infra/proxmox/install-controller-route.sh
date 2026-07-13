#!/usr/bin/env bash
set -euo pipefail

die() { echo "controller route install failed: $*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "run as root on the Observatory controller"

subnet="${OBSERVATORY_QUARANTINE_SUBNET:-10.253.253.0/24}"
gateway="${OBSERVATORY_PROXMOX_IPV4:-192.168.1.80}"
interface="${OBSERVATORY_CONTROLLER_INTERFACE:-eno1}"
unit=/etc/systemd/system/observatory-quarantine-route.service

[[ "$subnet" == "10.253.253.0/24" ]] || die "this reviewed generation pins 10.253.253.0/24"
[[ "$gateway" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "Proxmox gateway must be literal IPv4"
[[ "$interface" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "invalid controller interface"
[[ ! -e "$unit" ]] || die "$unit already exists; refusing to overwrite"
ip route get "$gateway" | grep -Eq "dev[[:space:]]+$interface([[:space:]]|$)" || die "Proxmox node is not reached through $interface"
ip route show exact "$subnet" | grep -q . && die "$subnet already has a route"

umask 077
cat > "$unit" <<EOF
[Unit]
Description=Route to the ClawScan Observatory quarantine network
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip route add $subnet via $gateway dev $interface
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 0600 "$unit"
systemd-analyze verify "$unit"
systemctl daemon-reload
systemctl enable --now observatory-quarantine-route.service
ip route show exact "$subnet"
