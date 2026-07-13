#!/usr/bin/env bash
set -euo pipefail

die() { echo "quarantine network install failed: $*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "run as root on the selected Proxmox node"

bridge="${OBSERVATORY_QUARANTINE_BRIDGE:-vmbr2}"
subnet="${OBSERVATORY_QUARANTINE_SUBNET:-10.253.253.0/24}"
gateway="${OBSERVATORY_QUARANTINE_GATEWAY:-10.253.253.1}"
controller="${OBSERVATORY_CONTROLLER_IPV4:?set OBSERVATORY_CONTROLLER_IPV4 to the literal controller LAN address}"
relay_port="${OBSERVATORY_RELAY_PORT:-19043}"
uplink="${OBSERVATORY_PROXMOX_UPLINK_BRIDGE:-vmbr0}"

[[ "$bridge" =~ ^vmbr[0-9]{1,4}$ ]] || die "invalid bridge"
[[ "$bridge" != "vmbr0" && "$bridge" != "vmbr1" ]] || die "vmbr0/vmbr1 are never valid quarantine bridges"
[[ "$subnet" == "10.253.253.0/24" && "$gateway" == "10.253.253.1" ]] || die "this reviewed generation pins 10.253.253.0/24"
[[ "$controller" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "controller must be literal IPv4"
[[ "$relay_port" =~ ^[0-9]+$ ]] && ((relay_port >= 1024 && relay_port <= 65535)) || die "invalid relay port"
[[ "$uplink" == "vmbr0" ]] || die "this reviewed generation pins the existing vmbr0 management uplink"

for command in dnsmasq getent ifquery ifup ip nft sysctl systemctl systemd-analyze; do
  command -v "$command" >/dev/null 2>&1 || die "missing command: $command"
done
getent passwd dnsmasq >/dev/null || die "missing dnsmasq service account"
getent group nogroup >/dev/null || die "missing nogroup service group"
grep -Eq '^[[:space:]]*source(-directory)?[[:space:]]+/etc/network/interfaces\.d/' /etc/network/interfaces || \
  die "/etc/network/interfaces does not include interfaces.d; refusing to edit the primary file"
ip route get "$controller" | grep -Eq "dev[[:space:]]+$uplink([[:space:]]|$)" || \
  die "controller is not reached through $uplink"
[[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] || die "IPv4 forwarding must already be enabled"

network_file=/etc/network/interfaces.d/observatory-quarantine
config_dir=/etc/observatory-quarantine
firewall_file="$config_dir/firewall.nft"
dhcp_file="$config_dir/dnsmasq.conf"
firewall_unit=/etc/systemd/system/observatory-quarantine-firewall.service
dhcp_unit=/etc/systemd/system/observatory-quarantine-dhcp.service
render_dir="$(mktemp -d /run/observatory-quarantine-install.XXXXXXXXXX)"
render_network="$render_dir/network"
render_firewall="$render_dir/firewall.nft"
render_dhcp="$render_dir/dnsmasq.conf"
render_firewall_unit="$render_dir/observatory-quarantine-firewall.service"
render_dhcp_unit="$render_dir/observatory-quarantine-dhcp.service"

for path in "$network_file" "$config_dir" "$firewall_unit" "$dhcp_unit"; do
  [[ ! -e "$path" ]] || die "$path already exists; refusing to overwrite"
done
ip link show "$bridge" >/dev/null 2>&1 && die "$bridge already exists; refusing to adopt it"
ip route show exact "$subnet" | grep -q . && die "$subnet already has a route"

umask 077
cat > "$render_network" <<EOF
auto $bridge
iface $bridge inet static
    address $gateway/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware no
EOF

cat > "$render_dhcp" <<EOF
port=0
interface=$bridge
bind-dynamic
dhcp-authoritative
dhcp-range=10.253.253.100,10.253.253.199,255.255.255.0,1h
dhcp-option=option:router,$gateway
dhcp-option=option:dns-server
dhcp-leasefile=/var/lib/observatory-quarantine/dnsmasq.leases
no-hosts
no-resolv
log-dhcp
EOF

cat > "$render_firewall" <<EOF
table inet observatory_quarantine {
  chain input {
    type filter hook input priority -200; policy accept;
    iifname "$bridge" ip saddr != $subnet drop comment "quarantine source anti-spoof"
    iifname "$bridge" udp sport 68 udp dport 67 accept comment "quarantine DHCP request"
    iifname "$bridge" ct state established,related accept
    iifname "$bridge" drop comment "quarantine cannot reach Proxmox host"
  }
  chain output {
    type filter hook output priority -200; policy accept;
    oifname "$bridge" ip daddr != $subnet drop comment "quarantine destination anti-spoof"
    oifname "$bridge" udp sport 67 udp dport 68 accept comment "quarantine DHCP reply"
    oifname "$bridge" ct state established,related accept
    oifname "$bridge" drop comment "Proxmox host cannot initiate into quarantine"
  }
  chain forward {
    type filter hook forward priority -200; policy accept;
    iifname "$bridge" ip saddr != $subnet drop comment "quarantine routed source anti-spoof"
    oifname "$bridge" ip daddr != $subnet drop comment "quarantine routed destination anti-spoof"
    iifname "$bridge" oifname "$uplink" ip daddr $controller tcp dport $relay_port ct state new accept comment "MiniMax relay only"
    iifname "$uplink" oifname "$bridge" ip saddr $controller tcp dport 22 ct state new accept comment "controller SSH only"
    iifname "$bridge" ct state established,related accept
    oifname "$bridge" ct state established,related accept
    iifname "$bridge" drop comment "quarantine egress deny"
    oifname "$bridge" drop comment "quarantine ingress deny"
  }
}
table bridge observatory_quarantine_l2 {
  chain forward {
    type filter hook forward priority -200; policy accept;
    meta ibrname "$bridge" meta obrname "$bridge" drop comment "quarantine guest isolation"
  }
}
EOF

cat > "$render_firewall_unit" <<EOF
[Unit]
Description=ClawScan Observatory quarantine firewall
After=network-pre.target
Before=observatory-quarantine-dhcp.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f $firewall_file
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat > "$render_dhcp_unit" <<EOF
[Unit]
Description=ClawScan Observatory quarantine DHCP
Requires=observatory-quarantine-firewall.service
After=observatory-quarantine-firewall.service network-online.target

[Service]
Type=simple
ExecStartPre=/usr/bin/install -d -m 0750 -o dnsmasq -g nogroup /var/lib/observatory-quarantine
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=$dhcp_file
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/observatory-quarantine
RestrictAddressFamilies=AF_INET AF_NETLINK AF_PACKET
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_CHOWN
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF

chmod 0600 "$render_network" "$render_dhcp" "$render_firewall" "$render_firewall_unit" "$render_dhcp_unit"
ifquery --interfaces="$render_network" "$bridge" >/dev/null
dnsmasq --test --conf-file="$render_dhcp"
nft --check --file "$render_firewall"
systemd-analyze verify "$render_firewall_unit" "$render_dhcp_unit"

# Recheck every destination after all parsers accept the rendered generation.
# A failed preflight therefore leaves no persistent network or service config.
for path in "$network_file" "$config_dir" "$firewall_unit" "$dhcp_unit"; do
  [[ ! -e "$path" ]] || die "$path appeared during preflight; refusing to overwrite"
done
install -d -m 0700 "$config_dir"
install -m 0600 "$render_network" "$network_file"
install -m 0600 "$render_dhcp" "$dhcp_file"
install -m 0600 "$render_firewall" "$firewall_file"
install -m 0600 "$render_firewall_unit" "$firewall_unit"
install -m 0600 "$render_dhcp_unit" "$dhcp_unit"
ifup "$bridge"
systemctl daemon-reload
systemctl enable observatory-quarantine-firewall.service observatory-quarantine-dhcp.service
systemctl start observatory-quarantine-firewall.service
systemctl start observatory-quarantine-dhcp.service

ip -br address show "$bridge"
ip route show exact "$subnet"
nft list table inet observatory_quarantine
nft list table bridge observatory_quarantine_l2
systemctl --no-pager --full status observatory-quarantine-firewall.service observatory-quarantine-dhcp.service
