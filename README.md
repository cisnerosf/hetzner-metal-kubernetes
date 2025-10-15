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
- [Cluster setup](#cluster-setup)
- [utils CLI](#utils-cli)
  - [Setup](#setup)
  - [Commands overview](#commands-overview)
  - [Examples](#examples)
  - [Tests](#tests)
- [Helpful Fedora CoreOS Commands](#helpful-fedora-coreos-commands)
- [Troubleshooting](#troubleshooting)
  - [Cannot boot server in Rescue Mode after installing Fedora CoreOS](#cannot-boot-server-in-rescue-mode-after-installing-fedora-coreos)
  - [Server fails to connect to another server over VLAN IP](#server-fails-to-connect-to-another-server-over-vlan-ip)
- [Todo](#todo)

# Overview

Automates deploying K3S (single-server or HA) on Hetzner dedicated servers with [Fedora CoreOS](https://fedoraproject.org/coreos/) using Ansible. Includes network and security setup:

- **WireGuard native backend**: Uses WireGuard as a backend for Flannel, which helps secure communication between nodes in a cluster. 
- **vSwitch Integration**: Connects all nodes using Hetzner's [vSwitch]((https://docs.hetzner.com/robot/dedicated-server/network/vswitch)) technology, establishing a virtual layer 2 network (VLAN) with IP range `10.100.100.0/25` (up to **100** nodes allowed due to vSwitch limits).
- **Robot API Management**: Includes a `utils.py` CLI tool for managing servers, firewall rules and vSwitches via the Robot WebService API.
- **Firewall**: When using [10G uplink](https://docs.hetzner.com/robot/dedicated-server/network/10g-uplink/) (strongly recommended), the Robot firewall is not available, therefore firewall rules are also configured at the host level using nftables.
- **Audit**: Includes basic audit rules for both K3S and Fedora CoreOS.
- **RAID 1 (mirrored NVMe)**: Each machine should have 2 NVMe drives enabled.
- **Cloudflare Full (strict) and AOP**: `artifacts/butane-k3s-manifests.yml` contains manifests that configures Authenticated Origin Pulls (mTLS) with Full (strict) mode for Traefik on port 443.
- **Fedora CoreOS**: designed for running containerized workloads securely and at scale, offering an immutable, minimal and automatically updating operating system that enhances reliability and security.
- **Reboot Coordination**:  [fleetlock](https://github.com/poseidon/fleetlock) reboot coordinator for the nodes in the cluster.
- **Disk Encryption**: Encrypt disks using LUKS with TPM2.

## Cluster setup
1. Setup `utils` CLI (see section below) and install Ansible (`brew update; brew install ansible;`)
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
    disk_encryption: false
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
```
3. Run `./utils.py token` to generate a K3S token, then update `k3s_token`.
4. Run `./utils.py provision_all` to provision all servers, then set each host’s `ansible_password` to its rescue password.
5. Set `first_master` to the host name of the 1st K3S master node in the cluster.
6. Enable [Full (strict) mode](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/) and [Authenticated Origin Pulls (mTLS)](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/) for your domain on your Cloudflare and save the certifcate to `cf_origin_cert` and private key to `cf_origin_cert_key`.
7. Set `disk_encryption` to `true` to enable disk encryption. **Requires:** TPM2 enabled via [KVM console](https://docs.hetzner.com/robot/dedicated-server/maintenance/kvm-console/).
8. Run `ansible-playbook playbooks/k3s_metal.yml` and wait for the machines to reboot.

**Note:** For single-server setup, set `inventory.yml` to:
```yaml
hetzner_k3s_metal:
  hosts:
    shadrach:
      ansible_host: 195.201.160.126
      ansible_password: --REPLACE_ME--
      setup: master
      vlan_ip: 10.100.100.1
  vars:
    disk_encryption: false
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
```

**Note:** If you want to bootstrap only one node within a cluster:
```
./utils.py provision $HOST
ansible-playbook playbooks/k3s_metal.yml --limit "$HOST"
```

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

## Todo

- [ ] Implement [K3S Hardening Guide](https://docs.k3s.io/security/hardening-guide)
- [ ] Extend [rancher-monitoring](https://github.com/rancher/charts/tree/dev-v2.12/charts/rancher-monitoring) Helm chart to seamlessly set up log management and metrics during the cluster bootstrapping process:
  - [ ] Integrate Grafana Loki
  - [ ] Integrate Grafana Alloy
  - [ ] Enable HA deployment mode
