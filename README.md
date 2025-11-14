## Why this project?

Setting up a Kubernetes cluster on cloud providers like AWS EKS and GCP GKE might seem straightforward, but it comes with significant hidden costs and complexity. Beyond the advertised control plane fees, you'll face egress charges, idle resource costs, vendor lock-in, and the operational overhead of managing multiple abstraction layers.

Many organizations are moving away from managed services to regain control over their infrastructure and costs.

This project provides a simple, cost-effective alternative by running Kubernetes clusters on **bare metal servers** on [Hetzner](https://www.hetzner.com/). You get:

- **Significant cost savings** compared to cloud provider managed services
- **Control over your infrastructure** more independence with no vendor lock-in
- **Fewer abstraction layers** for better transparency, predictability and troubleshooting
- **Enhanced performance** with direct hardware access

This is an **MVP** that demonstrates the core concepts. We welcome contributions to improve automation, add features, enhance security, and expand documentation. Your contributions will help make this a more robust solution for the community.


- [Overview](#overview)
- [Inventory Configuration](#inventory-configuration)
  - [Host-level Variables](#host-level-variables)
  - [Group-level Variables](#group-level-variables)
- [Cluster setup](#cluster-setup)
- [Single-server setup](#single-server-setup)
- [Disk encryption](#disk-encryption)
- [Bastion host](#bastion-host)
- [utils CLI](#utils-cli)
  - [Setup](#setup)
  - [Commands overview](#commands-overview)
  - [Examples](#examples)
  - [Tests](#tests)
- [Helpful Fedora CoreOS Commands](#helpful-fedora-coreos-commands)
- [Troubleshooting](#troubleshooting)
  - [Cannot boot server in Rescue Mode after installing Fedora CoreOS](#cannot-boot-server-in-rescue-mode-after-installing-fedora-coreos)
  - [Server fails to connect to another server over VLAN IP](#server-fails-to-connect-to-another-server-over-vlan-ip)
- [On-premises setup](#on-premises-setup)
- [E2E tests using Vagrant](#e2e-tests-using-vagrant)
  - [Requirements](#requirements)
  - [Install dependencies (macOS)](#install-dependencies-macos)
  - [Run](#run)
  - [Troubleshooting](#troubleshooting-1)

# Overview

Automates deploying K3S (single-server or HA) on Hetzner dedicated servers with [Fedora CoreOS](https://fedoraproject.org/coreos/) using Ansible. Includes network and security setup:

- **WireGuard native backend**: Uses WireGuard as a backend for Flannel, which helps secure communication between nodes in a cluster. 
- **vSwitch Integration**: Connects all nodes using Hetzner's [vSwitch]((https://docs.hetzner.com/robot/dedicated-server/network/vswitch)) technology, establishing a virtual layer 2 network (VLAN) with IP range `10.100.100.0/25` (up to **100** nodes allowed due to vSwitch limits).
- **Robot API Management**: Includes a `utils.py` CLI tool for managing servers, firewall rules and vSwitches via the Robot WebService API.
- **Firewall**: When using [10G uplink](https://docs.hetzner.com/robot/dedicated-server/network/10g-uplink/) (strongly recommended), the Robot firewall is not available, therefore firewall rules are also configured at the host level using nftables.
- **Audit**: Includes basic audit rules for both K3S and Fedora CoreOS.
- **RAID 1 (mirrored NVMe)**: Each machine should have 2 NVMe drives enabled.
- **Cloudflare Full (strict) and AOP**: `artifacts/butane-k3s-custom-resources.yml` contains manifests that configures Authenticated Origin Pulls (mTLS) with Full (strict) mode for Traefik on port 443.
- **Fedora CoreOS**: designed for running containerized workloads securely and at scale, offering an immutable, minimal and automatically updating operating system that enhances reliability and security.
- **Reboot Coordination**:  [fleetlock](https://github.com/poseidon/fleetlock) reboot coordinator for the nodes in the cluster.
- **Disk Encryption**: Encrypt disks with LUKS using [Tang](https://github.com/latchset/tang)
- **CIS Hardening**: based on [K3S CIS Hardening Guide](https://docs.k3s.io/security/hardening-guide) (partial implementation)
- **Bastion host:** In line with the "secure by default" principle, SSH access to Ansible hosts is restricted to a defined set of IPv4 addresses.

## Inventory Configuration

The `inventory.yml` file defines the structure of your K3S cluster. It contains host-level variables (per server) and group-level variables (shared across all servers). Below is a comprehensive reference of all available keys and their possible values (examples may be redacted, e.g `...`).

### Host-level Variables

These variables are defined under `hetzner_k3s_metal.hosts.<hostname>` for each server:

| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `ansible_host` | String (IPv4 address) | Yes | The public IP address of the dedicated Hetzner server that Ansible will connect to. | `195.202.160.120` |
| `ansible_password` | String | Yes | SSH password for connecting to the server. This is typically the rescue password from Hetzner. The `utils.py provision` command will automatically set this to the rescue password. | `abWL4(t7U...` |
| `ansible_user` | String | No (defaults to `root`) | SSH username for connecting to the server. | `root` |
| `ansible_port` | Integer | No (defaults to `22`) | SSH port number for connecting to the server. | `2222` |
| `ansible_ssh_common_args` | String | No | Additional SSH connection arguments. Can be used at the host level to override group-level settings or for E2E testing. | `'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'` |
| `setup` | String | Yes | Defines the role of the node in the K3S cluster. Must be either `master` or `worker`. | `master` |
| `vlan_ip` | String (IP address) | Yes | IP address assigned to the server on the VLAN network. Must be in the range `10.100.100.1` to `10.100.100.126` (vSwitch supports up to 100 nodes). | `10.100.100.1` |

### Group-level Variables

These variables are defined under `hetzner_k3s_metal.vars` and apply to all hosts:

| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `bastion_ips` | List of strings (CIDR notation) | Yes | List of allowed IPv4 networks in CIDR notation that can access the servers via SSH. Maximum of 3 entries due to Hetzner firewall limits. See [Bastion host](#bastion-host) section for more details. | `[ "8.8.4.4/32", "8.8.8.8/32" ]` |
| `ansible_ssh_common_args` | String | No (required if using bastion host) | SSH ProxyCommand configuration for routing connections through a bastion host. See [Bastion host](#bastion-host) section for detailed explanation. | `'-o ProxyCommand="ssh -p 22 -i ~/.ssh/bastion -W %h:%p -q root@46.62.251.149"'` |
| `tang_url` | String (URL) | No (defaults to empty string to disable encryption) | URL of the Tang server for disk encryption with LUKS. Leave as empty string `""` to disable disk encryption. Must not include a trailing slash `/`. See [Disk encryption](#disk-encryption) section for more details. | `"https://my-tang-server.mydomain.com"` or `""` |
| `tang_thumbprint` | String | No (defaults to empty string if encryption disabled) | Thumbprint from the Tang server. Required if `tang_url` is set. Leave as empty string `""` if disk encryption is disabled. See [Disk encryption](#disk-encryption) section for more details. | `"l3fZGUCmnQF_OA..."` or `""` |
| `rescue_passphrase` | String (64+ characters) | No (required if `tang_url` is set) | Rescue passphrase for LUKS disk encryption. Must be at least 64 characters long. Required when `tang_url` is set. See [Disk encryption](#disk-encryption) section for more details. | `"aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3..."` |
| `vlan` | Integer | Yes | VLAN ID for the Hetzner vSwitch. Must be a number between 4000 and 4091. | `4060` |
| `k3s_token` | String (100 characters) | Yes | 100-character alphanumeric token used for joining K3S nodes to the cluster. Generate one using `./utils.py token`. | `C31g5p0U03FbB9ZcTqXV5nwKnlDCTah6SPY...` |
| `first_master` | String (hostname) | Yes | Hostname of the first master node in the cluster. This node will be the initial K3S server, and other nodes will join to it. | `shadrach` |
| `ssh_authorized_key` | String (SSH public key) | Yes | SSH public key that will be added to the `authorized_keys` file on all servers for passwordless SSH access. | `"ssh-ed25519 AAAAC3Nza..."` |
| `cf_origin_cert` | String (PEM certificate) | Yes | Cloudflare Origin Certificate in PEM format for Authenticated Origin Pulls (mTLS). This certificate is used by Traefik on port 443. See [Cluster setup](#cluster-setup) section for instructions on obtaining this certificate. | `-----BEGIN CERTIFICATE-----...` |
| `cf_origin_cert_key` | String (PEM private key) | Yes | Private key corresponding to the Cloudflare Origin Certificate. This key is used by Traefik on port 443 for Authenticated Origin Pulls (mTLS). | `-----BEGIN PRIVATE KEY-----...` |
| `e2e_test` | Boolean | No (for E2E testing only) | Boolean flag used for end-to-end testing with Vagrant. Set to `true` to enable E2E test mode. Not used in production deployments. | `true` |

## Cluster setup
1. Setup [utils CLI](#utils-cli) (see section below) and install Ansible (e.g `brew install ansible`)
2. Create the file `inventory.yml` (`vlan_ip` should be in the range `10.100.100.1 - 10.100.100.126`):
```yaml
hetzner_k3s_metal:
  hosts:
    shadrach:
      ansible_host: 195.201.160.126
      ansible_password: --REPLACE_ME--
      setup: master
      vlan_ip: 10.100.100.1
    meshach:
      ansible_host: 195.201.10.252
      ansible_password: --REPLACE_ME--
      setup: master
      vlan_ip: 10.100.100.2
    abednego:
      ansible_host: 94.130.9.179
      ansible_password: --REPLACE_ME--
      setup: master
      vlan_ip: 10.100.100.3
    jenego:
      ansible_host: 95.130.9.180
      ansible_password: --REPLACE_ME--
      setup: worker
      vlan_ip: 10.100.100.4
  vars:
    tang_url: ""
    tang_thumbprint: ""
    rescue_passphrase: ""
    vlan: 4060
    k3s_token: --REPLACE_ME--
    first_master: shadrach
    ssh_authorized_key: --REPLACE_ME--
    cf_origin_cert: |-
      -----REPLACE ME-----
      MIIEojCCA4qgAwIBAgIUAXfr9nn8G9w...
    cf_origin_cert_key: |-
      -----REPLACE ME-----
      G9w0BAQEFAgAwIBAgIUAASCBKcwggSj.....
    bastion_ips: --REPLACE_ME--
    ansible_ssh_common_args: --REPLACE_ME--
```
3. Setup a [bastion host](#bastion-host) (see section below), then update `bastion_ips` and `ansible_ssh_common_args`.
4. Run `./utils.py token` to generate a K3S token, then update `k3s_token`.
5. Run `./utils.py provision_all` to provision all servers (`ansible_password` will be set to its rescue password automatically).
6. Set `first_master` to the host name of the 1st K3S master node in the cluster.
7. Enable [Full (strict) mode](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/) and [Authenticated Origin Pulls (mTLS)](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/) for your domain on your Cloudflare and save the certifcate to `cf_origin_cert` and private key to `cf_origin_cert_key`.
8. Run `ansible-playbook playbooks/k3s_metal.yml` and wait for the machines to reboot.

**Note:** If you want to bootstrap only one node within a cluster:
```
./utils.py provision $HOST
ansible-playbook playbooks/k3s_metal.yml --limit "$HOST"
```

## Single-server setup

1. Follow the same steps from **Cluster setup** and set `inventory.yml` to :
```yaml
hetzner_k3s_metal:
  hosts:
    shadrach:
      ansible_host: 195.201.160.126
      ansible_password: --REPLACE_ME--
      setup: master
      vlan_ip: 10.100.100.1
  vars:
    tang_url: ""
    tang_thumbprint: ""
    rescue_passphrase: ""
    vlan: 4060
    k3s_token: --REPLACE_ME--
    first_master: shadrach
    ssh_authorized_key: --REPLACE_ME--
    cf_origin_cert: |-
      -----REPLACE ME-----
      MIIEojCCA4qgAwIBAgIUAXfr9nn8G9w...
    cf_origin_cert_key: |-
      -----REPLACE ME-----
      G9w0BAQEFAgAwIBAgIUAASCBKcwggSj.....
    bastion_ips: --REPLACE_ME--
    ansible_ssh_common_args: --REPLACE_ME--
```

## Disk encryption
To enable disk encryption with LUKS you will need a [Tang server](https://github.com/latchset/tang) running.
You may follow the instructions at https://github.com/cisnerosf/tang-server to set up your personal Tang server.

To enable encryption:

1. Set `tang_url` to the address of your Tang server (no trailing slash `/`).
2. Run `tang-show-keys 8000` inside the Tang server container and save the output to `tang_thumbprint`.
3. Generate a rescue passphrase that is at least 64 characters long (e.g `openssl rand -hex 32`) and then update `rescue_passphrase`.
4. Follow the same steps from [Cluster setup](#cluster-setup).

```yaml
hetzner_k3s_metal:
  hosts:
    shadrach:
      ansible_host: 195.201.160.126
      ansible_password: --REPLACE_ME--
      setup: master
      vlan_ip: 10.100.100.1
  vars:
    tang_url: "https://my-tang-server.mydomain.com"
    tang_thumbprint: "l3fZGUCmnvKQF_OA6VZF9jf8z2s"
    rescue_passphrase: aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5jK7lM9nO1pQ3rS5tU7vW9xY1zA3bC5dE7fG9hI1jK3lM5nO7pQ9
    vlan: 4060
    ...
```

## Bastion host
In line with the **secure by default** principle, SSH access to Ansible hosts must be limited to a defined set of IPv4 addresses. 
You may use either your VPN's public IP (if fixed) or a dedicated bastion host — for example, a low-cost Hetzner cloud VM (under €5/month).

1. Set `bastion_ips` to allowed IPv4 networks in CIDR notation (max 3 entries due to Hetzner firewall limits).
2. If you use a VM as a bastion host, configure Ansible host var `ansible_ssh_common_args` to use SSH's builtin `ProxyCommand` so connections route through the bastion.
```yaml
hetzner_k3s_metal:
  hosts:
    shadrach:
      ansible_host: 195.201.160.126
      ansible_password: --REPLACE_ME--
      setup: master
      vlan_ip: 10.100.100.1
  vars:
    ...
    bastion_ips: [ "8.8.8.8/32", "8.8.4.4/32" ]
    ansible_ssh_common_args: '-o ProxyCommand="ssh -p 22 -i ~/.ssh/bastion -W %h:%p -q user@8.8.8.8"'
```

**ansible_ssh_common_args** breakdown:
- `-p 22`: bastion host SSH port
- `-i ~/.ssh/bastion`: bastion host SSH key
- `-W`: tells SSH to forward stdin and stdout
- `%h:%p`: `%h` actual inventory host, `%p` actual inventory host SSH port
- `-q user@8.8.8.8`: bastion username and hostname

To connect to a host through a bastion using SSH's built-in `ProxyCommand`, e.g:
1. Export env SSH_PROXY: `export SSH_PROXY='ssh -p 22 -i ~/.ssh/bastion -W %h:%p -q user@8.8.8.8'`
2. Connect to the host using SSH: `ssh -i ~/.ssh/hetzner -o ProxyCommand="$SSH_PROXY" coreuser@8.8.4.4`


## `utils` CLI

Helps configure Hetzner dedicated servers and vSwitches via the [Robot WebService API](https://robot.hetzner.com/doc/webservice/en.html#preface).

### Setup

1. Create a Webservice user account in the [Hetzner Robot](https://robot.hetzner.com/preferences/index) panel under `Webservice and app settings`
2. Export the credentials:
    ```bash
    export ROBOT_WEBSERVICE_USER="your_webservice_username"
    export ROBOT_WEBSERVICE_PASS="your_webservice_password"
    ```
3. Install dependencies: `pip3 install -r requirements.txt`

### Commands overview

- **token**: Generate a 100-character alphanumeric token (used for joining K3S nodes to a cluster).
- **clear_known_hosts**: Remove all inventory IPs from `~/.ssh/known_hosts`.
- **rescue <host> [-d]**: Enable rescue mode for a host. Use `-d` to deactivate.
- **rescue_all [-d]**: Enable rescue mode for all hosts. Use `-d` to deactivate rescue mode instead.
- **reset <host>**: Trigger a hard reset (reboot) for a host.
- **reset_all**: Hard reset all hosts in `inventory.yml`.
- **set_vswitch <host>**: Create or reuse a vSwitch for the VLAN specified in `inventory.yml` and assigns it to the server.
- **set_vswitch_all**: Configure vSwitch on all hosts. Create or reuse a vSwitch for the VLAN specified in `inventory.yml` and assigns all servers to it.
- **firewall <host>**: Configure firewall rules for a specific host. Sets up firewall rules including SSH/HTTPS access, NTP, K3S HA ports, Kubelet metrics, and Flannel WireGuard backend.
- **set_firewall_all**: Configure firewall rules for all hosts in `inventory.yml`. Applies the same K3S-specific firewall configuration to all servers.
- **provision**: Run, in order: `rescue` (enable), `reset`, `set_vswitch`, `firewall`, then `clear_known_hosts` for a host.
- **provision_all**: Run, in order: `rescue_all` (enable), `reset_all`, `set_vswitch_all`, `set_firewall_all`, then `clear_known_hosts` for all hosts.

### Examples

```shell
./utils.py token
./utils.py clear_known_hosts
./utils.py rescue $HOST
./utils.py rescue $HOST -d
./utils.py rescue_all
./utils.py rescue_all -d
./utils.py reset $HOST
./utils.py reset_all
./utils.py set_vswitch $HOST
./utils.py set_vswitch_all
./utils.py firewall $HOST
./utils.py set_firewall_all
./utils.py provision $HOST
./utils.py provision_all
```

### Tests
```shell
# Install testing dependencies
pip install -r requirements-test.txt

# Run tests with coverage report
pytest --cov=utils --cov-report=html --cov-report=term-missing
```

## Helpful Fedora CoreOS commands
- Check NTP status: `sudo chronyc tracking`
- List all rules in nftables `sudo nft list ruleset`
- Delete table in nftables `sudo nft delete table inet hostfirewall`
- Check systemd service status: `sudo systemctl status service-name.service`
- See systemd service logs for current boot: `sudo journalctl -u service-name.service -r -n 100 -b`
- Install packages: `sudo rpm-ostree install --apply-live --allow-inactive --assumeyes tcpdump`
- Check NVMe health: `sudo rpm-ostree install --apply-live --allow-inactive --assumeyes smartmontools && sudo smartctl -x /dev/nvme1n1`
- Check RAID sync progress: `sudo cat /proc/mdstat`

## Troubleshooting

### Cannot boot server in Rescue Mode after installing Fedora CoreOS

1. Check if the server is booting using UEFI firmware: `[ -d /sys/firmware/efi ] && echo UEFI || echo BIOS`
2. If UEFI, get the name of the UEFI partitions: `sudo blkid | egrep -i 'vfat|efi|esp'`
3. Disable UEFI:
  ```
  # 1st disk
  sudo mount /dev/nvme0n1p2 /boot/efi/
  sudo mv /boot/efi/EFI /boot/efi/EFI_disabled
  sudo umount /boot/efi/

  # 2nd disk
  sudo mount /dev/nvme1n1p2 /boot/efi/
  sudo mv /boot/efi/EFI /boot/efi/EFI_disabled
  sudo umount /boot/efi/
  ```
4. Enable Rescue Mode and reboot the machine.

### Server fails to connect to another server over VLAN IP

1. Go to the Hetzner dashboard at https://robot.hetzner.com/vswitch/index
2. Verify that your vSwitch is configured with the correct VLAN ID that matches the `vlan` variable in your `inventory.yml` file
3. Check the server assignments for your vSwitch:
   - If the problematic server is missing from the vSwitch, add it using: `./utils.py set_vswitch <hostname>`
4. Check if the server is assigned to other vSwitches, remove it from the incorrect vSwitch(s) in the dashboard


## On-premises setup

If you're deploying an on‑prem Kubernetes cluster on private cloud infrastructure, automating OS installation across nodes accelerates setup and reduces human error. PXE provisioning is a widely used, reliable approach: a DHCP/TFTP service provides network boot files so machines can boot via the network and perform unattended OS installs.

Canonical’s MAAS (Metal-as-a-Service) is a full-featured open-source platform that provides DHCP, TFTP, PXE orchestration, image management, and hardware discovery to provision and manage bare-metal servers at scale.

[MAAS](https://canonical.com/maas/docs) provides functionality analogous to [Hetzner’s Rescue System](https://docs.hetzner.com/robot/dedicated-server/troubleshooting/hetzner-rescue-system/).

## E2E tests using Vagrant

### Requirements
- ansible >= 12.1.0
- python >= 3.13 (try [pyenv](https://github.com/pyenv/pyenv))
- qemu >= 10.1.2
- vagrant >= 2.4.9
- vagrant-qemu >= 0.3.12

### Install dependencies (macOS)
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/hashicorp-vagrant qemu ansible
vagrant plugin install vagrant-qemu
```

### Run
1. Start VM: `vagrant up`
2. Run playbook: `ansible-playbook -i e2e-inventory.yml ./playbooks/k3s_metal.yml`
3. Run `chmod 600 e2e-ssh.key && ssh -p 2222 -i e2e-ssh.key -o UserKnownHostsFile=/dev/null coreuser@127.0.0.1` to SSH into CoreOS
4. Destroy the VM: `vagrant destroy`

### Troubleshooting
1. Install socat: `brew install socat`
2. Connect to serial console: `socat - UNIX-CONNECT:$HOME/.vagrant.d/tmp/vagrant-qemu/$(cat .vagrant/machines/default/qemu/id)/qemu_socket_serial`
