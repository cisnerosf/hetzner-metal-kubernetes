#!/usr/bin/env python3

import argparse
import json
import os
import re
import time
import random
import sys
from pathlib import Path
import urllib.parse
import yaml
import requests


ALPHANUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
HETZNER_API_BASE = "https://robot-ws.your-server.de"
WAIT_TIME = 5


def _load_inventory(inventory_path):
    """Load and parse inventory YAML file, returning hosts and vlan data."""
    if not inventory_path.exists():
        raise FileNotFoundError(f"inventory file not found: {inventory_path}")

    with inventory_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    hetzner_data = data.get("hetzner_k3s_metal", {})
    hosts = hetzner_data.get("hosts", {}) or {}
    vlan = hetzner_data.get("vars", {}).get("vlan")

    # Validate vlan range (4000-4091) if present
    if vlan is not None:
        try:
            vlan_int = int(vlan)
            if vlan_int < 4000 or vlan_int > 4091:
                raise ValueError(f"Invalid vlan {vlan}: must be between 4000 and 4091")
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid vlan {vlan}: must be a number between 4000 and 4091") from e

    return hosts, vlan


def _safe_file_replace(file_path, new_content, backup_suffix=".tmp"):
    """Safely replace file content by writing to a temporary file first."""
    if not file_path.exists():
        return False

    tmp_path = file_path.with_suffix(backup_suffix)
    try:
        with tmp_path.open("w", encoding="utf-8") as f:
            f.writelines(new_content)
        os.replace(tmp_path, file_path)
        return True
    except Exception:
        # Clean up temp file if something went wrong
        if tmp_path.exists():
            tmp_path.unlink()
        return False

class HetznerRobotClient:
    """Simple client for Hetzner Robot WebService API."""

    def __init__(self, user=None, password=None, api_base=HETZNER_API_BASE):
        self.user = user or os.environ.get("ROBOT_WEBSERVICE_USER")
        self.password = password or os.environ.get("ROBOT_WEBSERVICE_PASS")
        self.api_base = api_base
        self._server_list_cache = None  # Cache for /server response

    def has_credentials(self):
        return bool(self.user and self.password)

    def _request(self, endpoint, method="GET", data=None, headers=None):
        headers = {"Accept": "application/json", "User-Agent": "utils-cli/1.0", **(headers or {})}
        url = f"{self.api_base}{endpoint}"
        try:
            resp = getattr(requests, method.lower())(url, auth=(self.user, self.password), data=data, headers=headers, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except (requests.exceptions.HTTPError, requests.exceptions.RequestException, ValueError) as e:
            print(f"Request error: {e}", file=sys.stderr)
            return None

    def find_server_number_by_ip(self, target_ip):
        """Return server_number that matches the given IP and is ready & not cancelled."""
        if not self.has_credentials():
            print("ROBOT_WEBSERVICE_USER and ROBOT_WEBSERVICE_PASS must be set", file=sys.stderr)
            return None

        # Use cache if available, otherwise fetch from API
        if self._server_list_cache is None:
            self._server_list_cache = self._request("/server")

        data = self._server_list_cache
        if not isinstance(data, list):
            print("Unexpected API response format", file=sys.stderr)
            return None

        for item in data:
            server = item.get("server", {}) if isinstance(item, dict) else {}
            if (server.get("server_ip") == target_ip and
                server.get("status") == "ready" and
                server.get("cancelled") is False):
                return server.get("server_number")
        print("No matching server found in Hetzner", file=sys.stderr)
        return None

    def get_boot(self, server_number):
        return self._request(f"/boot/{server_number}")

    def enable_rescue(self, server_number, os_name="linux"):
        return self._request(f"/boot/{server_number}/rescue", method="POST", data={"os": os_name})

    def disable_rescue(self, server_number):
        return self._request(f"/boot/{server_number}/rescue", method="DELETE")

    def reset_hard(self, server_number):
        return self._request(f"/reset/{server_number}", method="POST", data={"type": "hw"})

    def get_vswitches(self):
        return self._request("/vswitch")

    def create_vswitch(self, vlan, name):
        payload = {"vlan": str(vlan), "name": name}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self._request("/vswitch", method="POST", data=payload, headers=headers)

    def get_vswitch_details(self, vswitch_number):
        return self._request(f"/vswitch/{vswitch_number}")

    def assign_server_to_vswitch(self, vswitch_number, server_ips):
        """Assign one or more servers to a vswitch.

        Args:
            vswitch_number: The vswitch ID to assign servers to
            server_ips: Either a single IP string or a list of IP strings
        """
        # Handle both single IP and list of IPs for backward compatibility
        if isinstance(server_ips, str):
            server_ips = [server_ips]

        # Build payload with multiple server[] entries
        payload = {}
        for i, ip in enumerate(server_ips):
            payload[f"server[{i}]"] = ip

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        url = f"{self.api_base}/vswitch/{vswitch_number}/server"
        try:
            resp = requests.post(url, auth=(self.user, self.password), data=payload, headers=headers, timeout=30)
            resp.raise_for_status()
            return {"success": True}
        except (requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            print(f"Request error: {e}", file=sys.stderr)
            return None

    def check_vswitch_servers_ready(self, vswitch_number, max_wait_time=300, check_interval=10):
        """Check if all servers in a vswitch have finished processing."""
        start_time = time.time()

        while time.time() - start_time < max_wait_time:
            vswitch_details = self.get_vswitch_details(vswitch_number)
            if vswitch_details is None:
                print(f"Failed to get vswitch details for vswitch {vswitch_number}", file=sys.stderr)
                return False

            servers = vswitch_details.get("server", [])
            if not isinstance(servers, list) or not servers:
                return True

            processing_servers = [f"server {s.get('server_number')} (status: {s.get('status')})"
                                for s in servers if isinstance(s, dict) and s.get("status") == "processing"]

            if not processing_servers:
                print(f"No servers are processing in vswitch {vswitch_number}")
                return True

            print(f"Waiting for servers to finish processing in vswitch {vswitch_number}: {', '.join(processing_servers)}")
            time.sleep(check_interval)

        print(f"Timeout waiting for servers to finish processing in vswitch {vswitch_number} after {max_wait_time} seconds", file=sys.stderr)
        return False

    def _find_or_create_vswitch(self, vlan):
        """Find existing vswitch or create new one for the given VLAN."""
        vswitches = self.get_vswitches()
        if vswitches is None:
            return None

        # Find existing vswitch or create new one
        existing_vswitch = next((v for v in vswitches if isinstance(v, dict) and
                                v.get("vlan") == vlan and v.get("cancelled") is False), None)

        if existing_vswitch is None:
            vswitch_name = f"k3s-cluster-{vlan}"
            result = self.create_vswitch(vlan, vswitch_name)
            if result is None:
                return None
            vswitch_number = result.get("id")
            if vswitch_number is None:
                print("Failed to get vswitch number from creation response", file=sys.stderr)
                return None
            print(f"Created new vswitch '{vswitch_name}' with vlan {vlan} (ID: {vswitch_number})")
        else:
            vswitch_number = existing_vswitch.get("id")
            if vswitch_number is None:
                print("Failed to get vswitch number from existing vswitch", file=sys.stderr)
                return None
            print(f"Found existing vswitch with vlan {vlan}: {existing_vswitch.get('name', 'unnamed')} (ID: {vswitch_number})")

        return vswitch_number

    def set_vswitch(self, server_number, vlan, server_ip):
        """Configure vswitch for a given server number."""
        vswitch_number = self._find_or_create_vswitch(vlan)
        if vswitch_number is None:
            return None

        vswitch_details = self.get_vswitch_details(vswitch_number)
        if vswitch_details is None:
            return None

        # Check if server is already assigned
        servers = vswitch_details.get("server", [])
        server_already_assigned = any(isinstance(s, dict) and s.get("server_number") == server_number for s in servers)

        if server_already_assigned:
            print(f"Server {server_number} is already assigned to vswitch {vswitch_number}")
            return (True, False)

        # Assign server to vswitch
        print(f"Checking if all servers in vswitch {vswitch_number} are ready before assignment...")
        if not self.check_vswitch_servers_ready(vswitch_number):
            print(f"Cannot assign server {server_number} to vswitch {vswitch_number}: not all servers are ready", file=sys.stderr)
            return None

        print(f"Assigning server {server_number} (IP: {server_ip}) to vswitch {vswitch_number}")
        assign_result = self.assign_server_to_vswitch(vswitch_number, server_ip)
        if assign_result is None:
            return None
        print(f"Successfully assigned server {server_number} to vswitch {vswitch_number}")
        print("Waiting for vswitch assignment to be processed...")
        time.sleep(30)
        return (True, True)

    def set_vswitch_batch(self, server_data, vlan):
        """Configure vswitch for multiple servers in a batch operation.

        Args:
            server_data: List of tuples (host_name, server_number, server_ip)
            vlan: VLAN number for the vswitch

        Returns:
            Tuple of (success_count, total_count) or None on error
        """
        vswitch_number = self._find_or_create_vswitch(vlan)
        if vswitch_number is None:
            return None

        # Get current vswitch details to check existing assignments
        vswitch_details = self.get_vswitch_details(vswitch_number)
        if vswitch_details is None:
            return None

        # Check which servers are already assigned
        servers = vswitch_details.get("server", [])
        assigned_server_numbers = {s.get("server_number") for s in servers if isinstance(s, dict)}

        # Filter out already assigned servers
        unassigned_servers = [(host, server_num, ip) for host, server_num, ip in server_data
                             if server_num not in assigned_server_numbers]

        if not unassigned_servers:
            print("All servers are already assigned to the vswitch")
            return (len(server_data), len(server_data))

        # Check if vswitch is ready for new assignments
        print(f"Checking if all servers in vswitch {vswitch_number} are ready before batch assignment...")
        if not self.check_vswitch_servers_ready(vswitch_number):
            print(f"Cannot assign servers to vswitch {vswitch_number}: not all servers are ready", file=sys.stderr)
            return None

        # Prepare batch assignment
        unassigned_ips = [ip for _, _, ip in unassigned_servers]
        unassigned_hosts = [host for host, _, _ in unassigned_servers]

        print(f"Batch assigning {len(unassigned_ips)} servers to vswitch {vswitch_number}: {', '.join(unassigned_hosts)}")

        # Perform batch assignment
        assign_result = self.assign_server_to_vswitch(vswitch_number, unassigned_ips)
        if assign_result is None:
            return None

        print(f"Successfully batch assigned {len(unassigned_ips)} servers to vswitch {vswitch_number}")
        print("Waiting for vswitch assignment to be processed...")
        time.sleep(30)

        return (len(unassigned_ips), len(server_data))

    def get_firewall(self, server_number):
        """Get firewall configuration for a server."""
        return self._request(f"/firewall/{server_number}")

    def set_firewall(self, server_number, firewall_data):
        """Set firewall configuration for a server."""
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self._request(f"/firewall/{server_number}", method="POST", data=firewall_data, headers=headers)

    def wait_for_firewall_ready(self, server_number, max_wait_time=300, check_interval=5):
        """Wait for firewall status to not be 'in process'."""
        start_time = time.time()

        while time.time() - start_time < max_wait_time:
            firewall_data = self.get_firewall(server_number)
            if firewall_data is None:
                print(f"Failed to get firewall status for server {server_number}", file=sys.stderr)
                return False

            firewall_status = firewall_data.get("firewall", {}).get("status")
            if firewall_status != "in process":
                print(f"Firewall status is now: {firewall_status}")
                return True

            print(f"Firewall is still in process, waiting... (status: {firewall_status})")
            time.sleep(check_interval)

        print(f"Timeout waiting for firewall to be ready after {max_wait_time} seconds", file=sys.stderr)
        return False


def command_token(_):
    token = "".join(random.choices(ALPHANUM, k=100))
    print(token)
    return 0


def parse_inventory_ips(inventory_path):
    """Extract all IP addresses from inventory file."""
    hosts, _ = _load_inventory(inventory_path)
    return [host_cfg.get("ansible_host", "").strip()
            for host_cfg in hosts.values()
            if isinstance(host_cfg, dict) and host_cfg.get("ansible_host")]


def get_host_ip_from_inventory(inventory_path, host_name):
    """Get IP address for a specific host from inventory file."""
    hosts, _ = _load_inventory(inventory_path)
    if host_name not in hosts or not isinstance(hosts[host_name], dict):
        raise KeyError(f"host not found in inventory: {host_name}")

    ip = hosts[host_name].get("ansible_host")
    if not ip:
        raise KeyError(f"host '{host_name}' missing ansible_host in inventory")
    return str(ip).strip()


def _update_inventory_password(inventory_path, host_name, new_password):
    """Update the ansible_password for a specific host in inventory.yml."""
    if not inventory_path.exists():
        print(f"Inventory file not found: {inventory_path}", file=sys.stderr)
        return False

    try:
        with inventory_path.open("r", encoding="utf-8") as f:
            content = f.read()

        hosts, _ = _load_inventory(inventory_path)
        if host_name not in hosts:
            print(f"Host '{host_name}' not found in inventory", file=sys.stderr)
            return False

        # Always quote the new password to prevent YAML parsing issues
        quoted_new_password = f'"{new_password}"'

        # Create a more flexible pattern that handles both quoted and unquoted passwords
        # Look for the host block and ansible_password line, then capture the entire password value
        pattern = rf"(\s+{re.escape(host_name)}:\s*\n(?:[^\n]*\n)*?\s+ansible_password:\s*)(.*?)(\s*\n)"
        match = re.search(pattern, content, re.MULTILINE)

        if match:
            # Replace the captured password with the new quoted password
            new_content = content[:match.start(2)] + quoted_new_password + content[match.end(2):]
        else:
            print(f"Warning: Could not find ansible_password for {host_name} to update", file=sys.stderr)
            return False

        with inventory_path.open("w", encoding="utf-8") as f:
            f.write(new_content)

        print(f"Updated ansible_password for {host_name} in inventory.yml")
        return True

    except Exception as e:
        print(f"Failed to update inventory: {e}", file=sys.stderr)
        return False


def remove_ips_from_known_hosts(ips, known_hosts_path):
    """Remove IP addresses from SSH known_hosts file."""
    if not known_hosts_path.exists():
        return 0

    with known_hosts_path.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    kept_lines = [line for line in lines if not any(ip in line for ip in ips)]
    removed_count = len(lines) - len(kept_lines)

    if removed_count > 0 and not _safe_file_replace(known_hosts_path, kept_lines):
        print(f"Warning: Failed to update {known_hosts_path}", file=sys.stderr)

    return removed_count


def _get_server_number_for_host(client, host):
    """Get server number for a host from inventory using the API client."""
    inventory_path = Path.cwd() / "inventory.yml"
    try:
        target_ip = get_host_ip_from_inventory(inventory_path, host)
        return client.find_server_number_by_ip(target_ip)
    except (FileNotFoundError, KeyError) as e:
        print(str(e), file=sys.stderr)
        return None


def _handle_command_error(func, *args, **kwargs):
    """Helper to handle common command error patterns."""
    try:
        return func(*args, **kwargs)
    except (FileNotFoundError, KeyError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 1


def command_clear_known_hosts(args):
    inventory_path = Path.cwd() / "inventory.yml"
    ips = parse_inventory_ips(inventory_path)

    if not ips:
        print("No IPs found under hetzner_k3s_metal.hosts in inventory.yml")
        return 0

    known_hosts = Path.home() / ".ssh" / "known_hosts"
    removed = remove_ips_from_known_hosts(ips, known_hosts)
    print(f"Removed {removed} entr(ies) from {known_hosts}")
    return 0


def command_rescue(args):
    """Enable or disable rescue mode for a specific host."""
    client = args.client
    server_number = _get_server_number_for_host(client, args.host)
    if server_number is None:
        return 1

    boot_data = client.get_boot(server_number)
    if boot_data is None:
        return 1

    rescue = boot_data.get("boot", {}).get("rescue", {})
    is_active = rescue.get("active") is True

    if args.deactivate:
        if not is_active:
            print("Rescue mode is not active.")
            return 0
        result = client.disable_rescue(server_number)
        if result is None:
            return 1
        print("Rescue mode deactivated successfully.")
        return 0

    if is_active:
        password = rescue.get("password", "(not set)")
        print(f"The server has rescue mode already enabled. The password is: {password}")
        return 0

    rescue_response = client.enable_rescue(server_number, os_name="linux")
    if rescue_response is None:
        return 1
    password = rescue_response.get("rescue", {}).get("password", "(not set)")
    print(f"Rescue mode enabled. The password is: {password}")

    inventory_path = Path.cwd() / "inventory.yml"
    if not _update_inventory_password(inventory_path, args.host, password):
        print(f"Warning: Failed to update inventory.yml with new password for {args.host}", file=sys.stderr)

    return 0


def command_reset(args):
    """Trigger a hard reset for a specific host."""
    client = args.client
    server_number = _get_server_number_for_host(client, args.host)
    if server_number is None:
        return 1
    result = client.reset_hard(server_number)
    if result is None:
        return 1
    print(f"Reset request sent successfully for server {server_number}")
    return 0


def command_vswitch(args):
    """Configure Hetzner vswitch for a specific host."""
    client = args.client
    server_number = _get_server_number_for_host(client, args.host)
    if server_number is None:
        return 1

    inventory_path = Path.cwd() / "inventory.yml"
    server_ip = get_host_ip_from_inventory(inventory_path, args.host)
    _, vlan = _load_inventory(inventory_path)

    if vlan is None:
        print("vlan not found in inventory.yml under hetzner_k3s_metal.vars", file=sys.stderr)
        return 1

    result = client.set_vswitch(server_number, vlan, server_ip)
    if result is None:
        return 1

    _, server_was_assigned = result
    if server_was_assigned:
        print(f"Vswitch configured successfully for server {server_number}")

    return 0


def command_firewall(args):
    """Configure firewall for a specific host."""
    client = args.client
    server_number = _get_server_number_for_host(client, args.host)
    if server_number is None:
        return 1

    # Check current firewall status
    print(f"Checking firewall status for server {server_number}...")
    firewall_data = client.get_firewall(server_number)
    if firewall_data is None:
        return 1

    current_status = firewall_data.get("firewall", {}).get("status")
    print(f"Current firewall status: {current_status}")

    # Wait for firewall to not be in process
    if current_status == "in process":
        print("Firewall is currently in process, waiting for it to be ready...")
        if not client.wait_for_firewall_ready(server_number):
            return 1

    # Build form-urlencoded data for firewall configuration
    firewall_data = []

    # Basic firewall settings
    firewall_data.append(("status", "active"))
    firewall_data.append(("filter_ipv6", "true"))
    firewall_data.append(("whitelist_hos", "true"))
    firewall_data.append(("port", "main"))

    # Input rules
    input_rules = [
        {
            "ip_version": "ipv4",
            "name": "tcp established",
            "dst_port": "1024-65535",
            "protocol": "tcp",
            "tcp_flags": "ack",
            "action": "accept"
        },
        {
            "ip_version": "ipv4",
            "name": "ssh https",
            "dst_port": "22,443,4449",
            "protocol": "tcp",
            "action": "accept"
        },
        {
            "ip_version": "ipv4",
            "name": "ntp cloudflare",
            "src_ip": "162.159.200.0/25",
            "dst_port": "1024-65535",
            "src_port": "123",
            "protocol": "udp",
            "action": "accept"
        },
        {
            "ip_version": "ipv4",
            "name": "K3S HA",
            "src_ip": "10.100.100.0/25",
            "dst_port": "2379,2380,6443",
            "protocol": "tcp",
            "action": "accept"
        },
        {
            "ip_version": "ipv4",
            "name": "Kubelet metrics",
            "src_ip": "10.100.100.0/25",
            "dst_port": "10250,9796,9200",
            "protocol": "tcp",
            "action": "accept"
        },
        {
            "ip_version": "ipv4",
            "name": "K3S Wireguard",
            "src_ip": "10.100.100.0/25",
            "dst_port": "51820",
            "protocol": "udp",
            "action": "accept"
        }
    ]

    # Add input rules to form data
    for i, rule in enumerate(input_rules):
        for key, value in rule.items():
            firewall_data.append((f"rules[input][{i}][{key}]", str(value)))

    # Output rules
    output_rules = [
        {
            "name": "Allow all",
            "action": "accept"
        }
    ]

    # Add output rules to form data
    for i, rule in enumerate(output_rules):
        for key, value in rule.items():
            firewall_data.append((f"rules[output][{i}][{key}]", str(value)))

    # Convert to form-urlencoded string
    form_data = urllib.parse.urlencode(firewall_data)

    # Send POST request to set firewall configuration
    print(f"Setting firewall configuration for server {server_number}...")
    result = client.set_firewall(server_number, form_data)
    if result is None:
        return 1

    print(f"Firewall configuration updated successfully for server {server_number}")
    return 0


def command_set_firewall_all(args):
    return _run_command_on_all_hosts(command_firewall, "set firewall", args.client)


def _run_command_on_all_hosts(command_func, operation_name, client, deactivate=False):
    """Helper function to run a command on all hosts in the inventory."""
    inventory_path = Path.cwd() / "inventory.yml"
    hosts, _ = _load_inventory(inventory_path)

    if not hosts:
        print("No hosts found in inventory.yml")
        return 0

    success_count = 0
    total_count = len(hosts)

    for host_name in hosts.keys():
        print(f"Processing {host_name}...")
        args = argparse.Namespace(host=host_name, client=client, deactivate=deactivate)
        result = command_func(args)
        if result == 0:
            success_count += 1
        else:
            print(f"  Failed to {operation_name} {host_name}", file=sys.stderr)

    print(f"\n{operation_name.title()} completed: {success_count}/{total_count} hosts processed successfully")
    return 0 if success_count == total_count else 1


def command_reset_all(args):
    return _run_command_on_all_hosts(command_reset, "reset", args.client)


def command_rescue_all(args):
    return _run_command_on_all_hosts(command_rescue, "enable rescue mode", args.client, deactivate=args.deactivate)


def command_set_vswitch_all(args):
    """Configure vswitch for all hosts in inventory using batch assignment."""
    client = args.client
    inventory_path = Path.cwd() / "inventory.yml"
    hosts, vlan = _load_inventory(inventory_path)

    if not hosts:
        print("No hosts found in inventory.yml")
        return 0

    if vlan is None:
        print("vlan not found in inventory.yml under hetzner_k3s_metal.vars", file=sys.stderr)
        return 1

    # Get all server numbers and IPs
    server_data = []
    for host_name in hosts.keys():
        server_number = _get_server_number_for_host(client, host_name)
        if server_number is None:
            print(f"Failed to get server number for {host_name}", file=sys.stderr)
            continue

        server_ip = get_host_ip_from_inventory(inventory_path, host_name)
        if server_ip is None:
            print(f"Failed to get IP for {host_name}", file=sys.stderr)
            continue

        server_data.append((host_name, server_number, server_ip))

    if not server_data:
        print("No valid server data found", file=sys.stderr)
        return 1

    # Use the new batch method
    result = client.set_vswitch_batch(server_data, vlan)
    if result is None:
        return 1

    success_count, total_count = result
    print(f"Batch vswitch assignment completed: {success_count}/{total_count} servers processed")
    return 0


def _run_provision_steps(steps, operation_name):
    """Helper to run provision steps with error handling."""
    for i, (step_name, step_func, step_args) in enumerate(steps, 1):
        print(f"\n=== Step {i}/{len(steps)}: {step_name} ===")
        result = step_func(step_args)
        if result != 0:
            print(f"{operation_name}: {step_name} failed", file=sys.stderr)
            return 1
        if i < len(steps):  # Don't sleep after the last step
            time.sleep(WAIT_TIME)
    return 0


def command_provision(args):
    """Run rescue, reset, set_vswitch, firewall, then clear_known_hosts in order for a specific host."""
    client = args.client
    host = args.host

    # Define steps for single host provision
    steps = [
        ("rescue", command_rescue, argparse.Namespace(host=host, client=client, deactivate=False)),
        ("reset", command_reset, argparse.Namespace(host=host, client=client)),
        ("set_vswitch", command_vswitch, argparse.Namespace(host=host, client=client)),
        ("firewall", command_firewall, argparse.Namespace(host=host, client=client)),
    ]

    result = _run_provision_steps(steps, f"provision {host}")
    if result != 0:
        return result

    # Clear known_hosts for specific host
    print(f"\n=== Step 5/5: clear_known_hosts for {host} ===")
    try:
        inventory_path = Path.cwd() / "inventory.yml"
        target_ip = get_host_ip_from_inventory(inventory_path, host)
        known_hosts = Path.home() / ".ssh" / "known_hosts"
        removed = remove_ips_from_known_hosts([target_ip], known_hosts)
        print(f"Removed {removed} entr(ies) from {known_hosts} for {host}")
    except (FileNotFoundError, KeyError) as e:
        print(f"Warning: Could not clear known_hosts for {host}: {e}", file=sys.stderr)

    print(f"\nprovision {host}: completed successfully")
    return 0


def command_provision_all(args):
    """Run rescue_all, reset_all, set_vswitch_all, set_firewall_all, then clear_known_hosts in order for all hosts."""
    client = args.client

    # Define steps for all hosts provision
    steps = [
        ("rescue_all", command_rescue_all, argparse.Namespace(client=client, deactivate=False)),
        ("reset_all", command_reset_all, argparse.Namespace(client=client)),
        ("set_vswitch_all", command_set_vswitch_all, argparse.Namespace(client=client)),
        ("set_firewall_all", command_set_firewall_all, argparse.Namespace(client=client)),
        ("clear_known_hosts", command_clear_known_hosts, argparse.Namespace()),
    ]

    result = _run_provision_steps(steps, "provision_all")
    if result != 0:
        return result

    print("\nprovision_all: completed successfully")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="utils", description="Utilities CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    # Define command configurations
    commands = [
        ("token", "Generate a K3S short token", command_token, []),
        ("clear_known_hosts", "Remove all host IP entries from ~/.ssh/known_hosts", command_clear_known_hosts, []),
        ("rescue", "Enable rescue mode for a host", command_rescue, [
            ("host", "Hostname inside inventory.yml"),
            ("-d", {"dest": "deactivate", "action": "store_true", "help": "Deactivate rescue mode instead of enabling it"})
        ]),
        ("reset", "Reboot a host", command_reset, [("host", "Hostname inside inventory.yml")]),
        ("set_vswitch", "Configure vswitch for a host", command_vswitch, [("host", "Hostname inside inventory.yml")]),
        ("firewall", "Configure firewall for a host", command_firewall, [("host", "Hostname inside inventory.yml")]),
        ("reset_all", "Reboot all hosts in inventory.yml", command_reset_all, []),
        ("rescue_all", "Enable rescue mode for all hosts in inventory.yml", command_rescue_all, [
            ("-d", {"dest": "deactivate", "action": "store_true", "help": "Deactivate rescue mode instead of enabling it for all hosts"})
        ]),
        ("set_vswitch_all", "Configure vswitch for all hosts in inventory.yml", command_set_vswitch_all, []),
        ("set_firewall_all", "Configure firewall for all hosts in inventory.yml", command_set_firewall_all, []),
        ("provision", "Run rescue, reset, set_vswitch, firewall, then clear_known_hosts for a specific host", command_provision, [
            ("host", "Hostname inside inventory.yml")
        ]),
        ("provision_all", "Run rescue_all, reset_all, set_vswitch_all, set_firewall_all, then clear_known_hosts", command_provision_all, []),
    ]

    # Create parsers from configuration
    for name, help_text, func, args in commands:
        p = sub.add_parser(name, help=help_text)
        for arg in args:
            if isinstance(arg, tuple):
                if len(arg) == 2 and isinstance(arg[1], str):
                    p.add_argument(arg[0], help=arg[1])
                elif len(arg) == 2 and isinstance(arg[1], dict):
                    p.add_argument(arg[0], **arg[1])
                else:
                    p.add_argument(arg[0], **arg[1])
        p.set_defaults(func=func)

    return parser


def main(argv):
    """CLI entrypoint for utils."""
    parser = build_parser()
    args = parser.parse_args(argv)
    # Inject API client into args for commands that require it
    args.client = HetznerRobotClient()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
