#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock_file="$script_dir/template.lock"
[[ "${EUID}" -eq 0 ]] || { echo "run on the Proxmox node as root" >&2; exit 2; }
[[ -r "$lock_file" ]] || { echo "missing $lock_file" >&2; exit 2; }
# shellcheck disable=SC1090
source "$lock_file"

template_id="${OBSERVATORY_PROXMOX_TEMPLATE_ID:-9403}"
template_name="${OBSERVATORY_PROXMOX_TEMPLATE_NAME:-clawscan-observatory-runner-v1}"
storage="${OBSERVATORY_PROXMOX_STORAGE:-local-lvm}"
bridge="${OBSERVATORY_PROXMOX_TEMPLATE_BRIDGE:-vmbr2}"
cores="${OBSERVATORY_PROXMOX_CORES:-4}"
memory_mb="${OBSERVATORY_PROXMOX_MEMORY_MB:-8192}"
disk_size="${OBSERVATORY_PROXMOX_DISK_SIZE:-64G}"

die() { echo "error: $*" >&2; exit 1; }
is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }
for command in curl pvesm qemu-img qm sha256sum virt-customize; do
  command -v "$command" >/dev/null 2>&1 || die "missing command: $command"
done
is_uint "$template_id" || die "template ID must be numeric"
is_uint "$cores" || die "core count must be numeric"
is_uint "$memory_mb" || die "memory must be numeric"
[[ "$template_name" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || die "template name must be a lowercase Proxmox-safe name"
[[ "$storage" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid storage name"
[[ "$disk_size" =~ ^[1-9][0-9]*G$ ]] || die "disk size must be a positive whole GiB value such as 64G"
[[ "$bridge" =~ ^vmbr[0-9]{1,4}$ ]] || die "template bridge must be vmbr0..vmbr9999"
[[ "$bridge" != "vmbr0" && "$bridge" != "vmbr1" ]] || die "template bridge must be a dedicated Observatory quarantine bridge, never vmbr0/vmbr1"
qm status "$template_id" >/dev/null 2>&1 && die "VMID $template_id already exists; this builder never replaces templates"

workdir="$(mktemp -d /var/tmp/observatory-template.XXXXXXXXXX)"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

source_image="$workdir/source.img"
custom_image="$workdir/${template_name}.qcow2"
curl --proto '=https' --tlsv1.2 -fL --retry 3 --output "$source_image" "$UBUNTU_IMAGE_URL"
printf '%s  %s\n' "$UBUNTU_IMAGE_SHA256" "$source_image" | sha256sum -c -
qemu-img convert -O qcow2 "$source_image" "$custom_image"

virt-customize -a "$custom_image" --network \
  --mkdir /opt/observatory-template \
  --copy-in "$lock_file:/opt/observatory-template" \
  --copy-in "$script_dir/provision-observatory-guest.sh:/opt/observatory-template" \
  --copy-in "$script_dir/validate-observatory-template.sh:/opt/observatory-template" \
  --run-command 'chmod 0555 /opt/observatory-template/*.sh && chmod 0444 /opt/observatory-template/template.lock' \
  --run-command '/opt/observatory-template/provision-observatory-guest.sh /opt/observatory-template/template.lock' \
  --run-command 'cloud-init clean --logs --machine-id --configs ssh_config'

qm create "$template_id" \
  --name "$template_name" \
  --memory "$memory_mb" \
  --cores "$cores" \
  --net0 "virtio,bridge=${bridge}" \
  --serial0 socket \
  --vga serial0 \
  --agent enabled=1 \
  --ostype l26 \
  --scsihw virtio-scsi-pci

qm importdisk "$template_id" "$custom_image" "$storage"
disk_volume="$(pvesm list "$storage" --vmid "$template_id" | awk -v id="$template_id" 'NR > 1 && $1 ~ ("vm-" id "-disk-") { print $1; exit }')"
[[ -n "$disk_volume" ]] || die "imported disk not found; incomplete VMID $template_id was intentionally left for inspection"
qm set "$template_id" --scsi0 "${disk_volume},discard=on"
qm set "$template_id" --ide2 "${storage}:cloudinit"
qm set "$template_id" --boot c --bootdisk scsi0
qm set "$template_id" --ipconfig0 ip=dhcp --ciuser crabbox
qm resize "$template_id" scsi0 "$disk_size"
qm set "$template_id" --onboot 0 --tags clawscan-observatory
qm template "$template_id"
qm set "$template_id" --protection 1

cat <<EOF
Created Observatory runner template:
  templateId: $template_id
  name: $template_name
  storage: $storage
  templateBridge: $bridge
  runtimeBridge: $bridge
EOF
