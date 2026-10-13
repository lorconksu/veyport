#!/usr/bin/env bash
# Run via explicit guest SSH as sudo. /run/veyport-unlock.key must be a 0600
# tmpfs key transferred from the private controller; never persist it in guest.
set -euo pipefail
role=${1:?role required}
volume_gib=${2:?encrypted volume size required}
[[ $(hostname) == "$role" ]] || { echo 'Wrong guest hostname'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
cloud-init status --wait >/dev/null || true
deadline=$((SECONDS+900))
while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
  ((SECONDS < deadline)) || { echo 'Package initialization deadline'; exit 1; }
  sleep 2
done
apt-get update -qq
apt-get -o DPkg::Lock::Timeout=600 install -y -qq cryptsetup nftables jq openssl curl python3-pip python3-venv > /var/log/veyport-bootstrap-packages.log
systemctl disable --now tailscaled || true
swapoff -a
sed -i '/^[^#].*[[:space:]]swap[[:space:]]/s/^/# veyport lab: /' /etc/fstab
systemctl mask swap.target
systemctl daemon-reload
systemctl enable --now ssh.socket
# Cloud-init templates use LVM. Expand only this newly authorized guest root.
growpart /dev/sda 3 || true
pvresize /dev/sda3
lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv || true
install -d -m700 /var/lib/veyport-lab /srv/veyport
if [[ ! -f /var/lib/veyport-lab/services.luks ]]; then
  truncate -s "${volume_gib}G" /var/lib/veyport-lab/services.luks
  chmod 600 /var/lib/veyport-lab/services.luks
  cryptsetup luksFormat --type luks2 --batch-mode --key-file /run/veyport-unlock.key /var/lib/veyport-lab/services.luks
fi
if [[ ! -e /dev/mapper/veyport-services ]]; then
  cryptsetup open --key-file /run/veyport-unlock.key /var/lib/veyport-lab/services.luks veyport-services
fi
rm -f /run/veyport-unlock.key
if ! blkid /dev/mapper/veyport-services >/dev/null; then
  mkfs.ext4 -q /dev/mapper/veyport-services
fi
mount_options=nodev,nosuid
[[ "$role" == audit-store-lab ]] && mount_options=sync,nodev,nosuid
mountpoint -q /srv/veyport || mount -o "$mount_options" /dev/mapper/veyport-services /srv/veyport
chmod 700 /srv/veyport
install -d -m700 /srv/veyport/{tls,config,data,spool,backup}
cat > /etc/ssh/sshd_config.d/90-veyport-lab.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
systemctl reload ssh.service || true
cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet veyport_lab {
  chain input {
    type filter hook input priority -10; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    ip saddr {10.10.1.95,10.10.1.96,10.10.1.41,10.10.1.42,10.10.1.43} tcp dport 22 accept
EOF
case "$role" in
  veyport-lab)
    echo '    ip saddr {10.10.1.95,10.10.1.96,10.10.1.64} tcp dport {443,8443,8080,9090,2222} accept' >> /etc/nftables.conf ;;
  audit-ingest-lab)
    echo '    ip saddr {10.10.1.59,10.10.1.95,10.10.1.96} tcp dport 8443 accept' >> /etc/nftables.conf ;;
  audit-store-lab)
    echo '    ip saddr {10.10.1.60,10.10.1.95} tcp dport 8333 accept' >> /etc/nftables.conf ;;
  audit-keys-lab)
    echo '    ip saddr {10.10.1.62,10.10.1.95} tcp dport 8200 accept' >> /etc/nftables.conf ;;
  elk-lab)
    echo '    ip saddr 10.10.1.60 tcp dport 5044 accept' >> /etc/nftables.conf
    echo '    ip saddr 10.10.1.95 tcp dport 5601 accept' >> /etc/nftables.conf ;;
  audit-target-lab) ;;
  *) echo 'Unknown role'; exit 1 ;;
esac
cat >> /etc/nftables.conf <<'EOF'
  }
  chain forward {
    type filter hook forward priority -10; policy drop;
  }
  chain output {
    type filter hook output priority -10; policy drop;
    oifname "lo" accept
    ct state established,related accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    ip daddr 10.10.1.12 udp dport 53 accept
    ip daddr 10.10.1.12 tcp dport 53 accept
    udp dport 123 accept
    tcp dport {80,443} accept
    ip daddr {10.10.1.59,10.10.1.96} tcp dport {8080,8443,9090} accept
    ip daddr 10.10.1.60 tcp dport 8443 accept
    ip daddr 10.10.1.62 tcp dport 8333 accept
    ip daddr 10.10.1.63 tcp dport 8200 accept
    ip daddr 10.10.1.61 tcp dport 5044 accept
  }
}
EOF
nft -c -f /etc/nftables.conf
systemctl disable --now docker.socket docker.service || true
systemctl enable --now nftables
nft -f /etc/nftables.conf
echo "$role encrypted volume mounted; firewall active; SSH key only"
