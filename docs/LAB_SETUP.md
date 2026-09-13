# Fedora/libvirt/Debian Lab Setup

This guide builds the environment used to demonstrate the PAM MVP from a
fresh clone. It is secret-free: choose passwords interactively and never add
them to documentation, shell history, source, or Git.

The tested environment was a Fedora Linux host, QEMU/KVM with libvirt's system
connection, and a Debian 13 minimal guest. These are reference choices, not a
claim that every distribution, address, or fingerprint is identical.

## 1. Host prerequisites

Install the Fedora virtualization tools appropriate to the host release. A
typical starting point is:

```bash
sudo dnf install @virtualization virt-install virt-manager
```

Also install Python with `venv` support, Git, and an OpenSSH client. Docker is
not required. Package group/names can change between Fedora releases; consult
the current distribution documentation if the example is unavailable.

Validate hardware acceleration and the system libvirt connection:

```bash
test -c /dev/kvm
ls -l /dev/kvm
virt-host-validate qemu
virsh -c qemu:///system uri
virsh -c qemu:///system net-list --all
```

Modern libvirt installations may use modular, socket-activated daemons rather
than one monolithic service. On such a Fedora host, these sockets cover the
QEMU, network, and storage drivers:

```bash
sudo systemctl enable --now virtqemud.socket
sudo systemctl enable --now virtnetworkd.socket
sudo systemctl enable --now virtstoraged.socket
```

If the host uses monolithic `libvirtd`, follow that host's service layout
instead. Libvirt documents both modes and recommends socket activation where
systemd is available.

The default NAT network should be active and configured to autostart:

```bash
virsh -c qemu:///system net-info default
sudo virsh -c qemu:///system net-start default
sudo virsh -c qemu:///system net-autostart default
```

Run `net-start` only when `net-info` reports the network inactive; an already
active network will correctly reject a second start.

## 2. Create the Debian target

Download a Debian 13 (`trixie`) amd64 netinst image from Debian and verify its
published checksum/signature before use. A later Debian 13 point release is
expected to be suitable; the MVP does not depend on one exact patch release.

Create a guest with these tested baseline resources:

- name: `linux-server-1`
- 2 virtual CPUs
- 2 GiB RAM
- 20 GiB disk
- libvirt `default` NAT network
- no desktop environment
- SSH server and standard system utilities

Using virt-manager is the simplest interactive route. An equivalent
`virt-install` outline is:

```bash
sudo virt-install \
    --connect qemu:///system \
    --name linux-server-1 \
    --vcpus 2 \
    --memory 2048 \
    --disk size=20,bus=virtio \
    --network network=default,model=virtio \
    --cdrom /path/to/debian-13-amd64-netinst.iso \
    --graphics spice
```

Choose a supported OS variant reported by `osinfo-query os` if the local tool
requires one. Complete the installer through the console and select the SSH
server and standard system utilities tasks, without a desktop.

## 3. Configure the target

At the guest console, use the administrative account selected during install.
Commands may need to be run as root if `sudo` is not installed yet:

```bash
sudo apt update
sudo apt install openssh-server sudo
sudo hostnamectl set-hostname linux-server-1
sudo adduser pamadmin
sudo usermod -aG sudo pamadmin
sudo systemctl enable --now ssh
systemctl status ssh --no-pager
sudo ss -ltnp
id pamadmin
```

Set the `pamadmin` password only at the interactive prompt. Do not put it in a
command, file, runbook, or shell variable. Confirm that SSH listens on port 22
and that `id pamadmin` shows the intended `sudo` group membership.

## 4. Discover and optionally reserve the guest address

From the Fedora host:

```bash
sudo virsh -c qemu:///system domiflist linux-server-1
sudo virsh -c qemu:///system domifaddr linux-server-1 --source lease
sudo virsh -c qemu:///system net-dhcp-leases default
```

The tested guest used `192.168.122.227`. That address is only an example;
another engineer must use the address assigned to their guest.

For a stable lab address, first record the guest NIC MAC from `domiflist`,
choose an unused address within the default network, and inspect the current
network definition and leases:

```bash
sudo virsh -c qemu:///system net-dumpxml default
sudo virsh -c qemu:///system net-dhcp-leases default
```

Libvirt supports a persistent live DHCP reservation with `net-update`. Replace
the example MAC, name, and IP only after confirming that they belong to this
guest and do not conflict:

```bash
sudo virsh -c qemu:///system net-update default add ip-dhcp-host \
    "<host mac='52:54:00:00:00:00' name='linux-server-1' ip='192.168.122.227'/>" \
    --live --config
```

Renew the guest lease or reboot the guest after making a reservation.

## 5. Validate SSH manually

Set a shell variable to the address discovered above, then connect:

```bash
TARGET_IP=192.168.122.227
ssh "pamadmin@${TARGET_IP}"
whoami
hostname
id
exit
```

Expected identity/hostname for the example are `pamadmin` and
`linux-server-1`. This validation uses the target password interactively and
is separate from the PAM broker flow.

## 6. Acquire and verify the host fingerprint

The fingerprint must be established through a trusted route. On the guest
console, inspect the public host key directly:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

You may independently scan the presented public key from the Fedora host, but
do not trust an unauthenticated network scan by itself:

```bash
ssh-keyscan -t ed25519 "${TARGET_IP}" > /tmp/linux-server-1.ed25519.pub
ssh-keygen -lf /tmp/linux-server-1.ed25519.pub -E sha256
```

Compare the two SHA256 fingerprints exactly. The completed tested lab used:

```text
SHA256:sN8IiNCiH3HWetmR/J3uRvPfer4s0AcIP3BebXieUuI
```

That value identifies only the tested guest. A rebuilt or different guest has
its own key and must not reuse this pin.

## 7. Optional baseline snapshot

After Debian, networking, SSH, hostname, and `pamadmin` are verified, an
optional libvirt snapshot makes negative lab recovery convenient. Snapshot
support depends on the storage format and VM state. For a compatible stopped
guest, an example is:

```bash
sudo virsh -c qemu:///system shutdown linux-server-1
sudo virsh -c qemu:///system domstate linux-server-1
sudo virsh -c qemu:///system snapshot-create-as linux-server-1 pam-baseline \
    --description "Debian SSH PAM target baseline"
```

Wait for a shut-off state before taking an offline snapshot. Use virt-manager
or the libvirt documentation when the storage pool does not support this
command. The application does not create, revert, or depend on snapshots.

## 8. Project and virtual environment

From a fresh clone:

```bash
git clone <repository-url>
cd pam-mvp
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The implementation targets Python 3.11 or newer. The runtime dependency file
contains the pinned crypto, SSH, and Argon2 libraries. The automated test
runner is a development dependency and must be available separately to run
the test suite; dependency packaging is a remaining publication-hardening
item.

## 9. Provision the local runtime

Export only the non-secret metadata discovered above:

```bash
TARGET_IP=192.168.122.227
TARGET_FINGERPRINT='SHA256:sN8IiNCiH3HWetmR/J3uRvPfer4s0AcIP3BebXieUuI'
python -m src.tools.provision_lab \
    --runtime-dir ./runtime/lab \
    --target-host "${TARGET_IP}" \
    --host-key-fingerprint "${TARGET_FINGERPRINT}"
```

The tool prompts, without echo, for the PAM application password and then the
target `pamadmin` password. It has no password argument or environment-secret
fallback.

The current provisioning defaults contain the tested example host and
fingerprint. They are lab-specific conveniences. On another machine, passing
`--target-host` and `--host-key-fingerprint` is mandatory in practice; do not
silently accept defaults that describe a different VM.

Provisioning is intentionally one-shot. If an expected artifact already
exists, the tool aborts rather than overwrite security data. If provisioning
of a brand-new runtime fails partway, inspect it and remove that fresh failed
directory manually before retrying; never point cleanup at an established
runtime.

Expected layout:

```text
runtime/lab/          # 0700
  vault.key           # 0600
  audit.key           # 0600
  auth.db             # 0600
  config.db           # 0600
  vault.db            # 0600
  audit.db             # created as 0600 on first access/audit write
```

`runtime/`, `*.db`, and `*.key` are Git-ignored. The files remain operational
secrets despite the ignore rules; do not copy or publish the directory.

Continue with [Successful E2E](LAB_E2E.md). Negative scenarios must use
isolated copies as described in [Negative E2E](LAB_NEGATIVE_E2E.md).

## Troubleshooting: guest DNS works but TCP internet does not

In the tested Fedora environment, the guest could reach the libvirt gateway
and resolve DNS, but guest TCP internet traffic did not traverse NAT. An
interaction between Docker-managed and libvirt-managed nftables rules was
involved. Switching libvirt's network firewall backend to iptables
compatibility mode resolved that specific host.

Do not make that change preemptively and do not disable the firewall. First
locate the failure:

```bash
ip route
ping -c 2 192.168.122.1
getent hosts deb.debian.org
curl -I https://deb.debian.org/
```

On the Fedora host, inspect the libvirt network and firewall state:

```bash
sudo virsh -c qemu:///system net-info default
sudo virsh -c qemu:///system net-dumpxml default
sudo firewall-cmd --get-active-zones
sudo nft list ruleset
sudo journalctl -u virtnetworkd --since today
```

If the same symptom and Docker/libvirt rules conflict are confirmed, review
`/etc/libvirt/network.conf` and the host's libvirt/firewalld documentation.
The tested compatibility setting was:

```ini
firewall_backend = "iptables"
```

After deliberately editing that host configuration, restart only the modular
network daemon, confirm the network state, and retest:

```bash
sudo systemctl restart virtnetworkd.service
sudo virsh -c qemu:///system net-info default
```

This changes host networking behavior and may not be appropriate on another
Fedora/libvirt version. Back up the configuration, understand the existing
firewall ownership, and revert if it does not address the diagnosed problem.

## Upstream references

- [Libvirt daemon modes and socket activation](https://libvirt.org/daemons.html)
- [`virtqemud` manual](https://www.libvirt.org/manpages/virtqemud.html)
- [Libvirt network firewall behavior](https://libvirt.org/firewall.html)
- [Libvirt networking and DHCP host entries](https://wiki.libvirt.org/Networking.html)
- [`virsh` command reference](https://libvirt.org/manpages/virsh.html)
- [Debian 13 amd64 installation guide](https://www.debian.org/releases/trixie/amd64/)
- [Debian network-install images](https://www.debian.org/CD/netinst/)
