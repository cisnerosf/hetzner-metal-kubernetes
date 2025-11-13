"""Tests for CLI command functions."""

import argparse
from pathlib import Path
from urllib.parse import parse_qsl
from unittest.mock import Mock, patch

from utils import (
    command_clear_known_hosts,
    command_rescue,
    command_reset,
    command_vswitch,
    command_firewall,
    command_set_firewall_all,
    command_provision,
    command_provision_all,
    _run_command_on_all_hosts,
    _run_provision_steps
)


class TestCommandClearKnownHosts:
    """Test cases for command_clear_known_hosts function."""

    def test_clear_known_hosts_success(self, inventory_file, mock_home_dir):
        """Test successful known_hosts clearing."""
        # Create mock known_hosts file
        known_hosts = mock_home_dir / ".ssh" / "known_hosts"
        known_hosts.parent.mkdir(parents=True, exist_ok=True)
        known_hosts.write_text("94.130.9.179 ssh-rsa AAAAB3NzaC1yc2E...\n167.235.180.96 ssh-rsa AAAAB3NzaC1yc2E...\nother.host.com ssh-rsa AAAAB3NzaC1yc2E...\n")

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_clear_known_hosts(None)

        assert result == 0
        # Verify IPs were removed
        content = known_hosts.read_text()
        assert "94.130.9.179" not in content
        assert "167.235.180.96" not in content
        assert "other.host.com" in content  # Should remain

    def test_clear_known_hosts_no_ips(self, temp_dir):
        """Test known_hosts clearing when no IPs found."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {},
                "vars": {
                    "bastion_ips": ["8.8.8.8/32"]
                }
            }
        }

        inventory_file = temp_dir / "inventory.yml"
        with inventory_file.open("w") as f:
            import yaml
            yaml.dump(inventory_data, f)

        with patch('utils.Path.cwd', return_value=temp_dir):
            with patch('builtins.print') as mock_print:
                result = command_clear_known_hosts(None)

        assert result == 0
        mock_print.assert_called_with("No IPs found under hetzner_k3s_metal.hosts in inventory.yml")

    def test_clear_known_hosts_no_known_hosts_file(self, inventory_file, mock_home_dir):
        """Test known_hosts clearing when known_hosts file doesn't exist."""
        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_clear_known_hosts(None)

        assert result == 0


class TestCommandRescue:
    """Test cases for command_rescue function."""

    def test_rescue_enable_success(self, mock_robot_client, inventory_file):
        """Test successful rescue mode enablement."""
        # Mock boot data with rescue not active
        mock_robot_client.get_boot.return_value = {
            "boot": {
                "rescue": {
                    "active": False,
                    "password": None
                }
            }
        }

        # Mock rescue enable response
        mock_robot_client.enable_rescue.return_value = {
            "rescue": {
                "active": True,
                "password": "new_rescue_password_123"
            }
        }

        args = argparse.Namespace(host="shadrach", client=mock_robot_client, deactivate=False)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('utils._update_inventory_password', return_value=True) as mock_update:
                with patch('builtins.print') as mock_print:
                    result = command_rescue(args)

        assert result == 0
        mock_robot_client.enable_rescue.assert_called_once_with(321, os_name="linux")
        mock_update.assert_called_once_with(inventory_file, "shadrach", "new_rescue_password_123")
        mock_print.assert_called_with("Rescue mode enabled. The password is: new_rescue_password_123")

    def test_rescue_already_active(self, mock_robot_client, inventory_file):
        """Test rescue command when rescue mode is already active."""
        # Mock boot data with rescue already active
        mock_robot_client.get_boot.return_value = {
            "boot": {
                "rescue": {
                    "active": True,
                    "password": "existing_password"
                }
            }
        }

        args = argparse.Namespace(host="shadrach", client=mock_robot_client, deactivate=False)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print') as mock_print:
                result = command_rescue(args)

        assert result == 0
        mock_print.assert_called_with("The server has rescue mode already enabled. The password is: existing_password")

    def test_rescue_deactivate_success(self, mock_robot_client, inventory_file):
        """Test successful rescue mode deactivation."""
        # Mock boot data with rescue active
        mock_robot_client.get_boot.return_value = {
            "boot": {
                "rescue": {
                    "active": True,
                    "password": "existing_password"
                }
            }
        }

        mock_robot_client.disable_rescue.return_value = {"success": True}

        args = argparse.Namespace(host="shadrach", client=mock_robot_client, deactivate=True)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print') as mock_print:
                result = command_rescue(args)

        assert result == 0
        mock_robot_client.disable_rescue.assert_called_once_with(321)
        mock_print.assert_called_with("Rescue mode deactivated successfully.")

    def test_rescue_deactivate_not_active(self, mock_robot_client, inventory_file):
        """Test rescue deactivation when rescue mode is not active."""
        # Mock boot data with rescue not active
        mock_robot_client.get_boot.return_value = {
            "boot": {
                "rescue": {
                    "active": False,
                    "password": None
                }
            }
        }

        args = argparse.Namespace(host="shadrach", client=mock_robot_client, deactivate=True)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print') as mock_print:
                result = command_rescue(args)

        assert result == 0
        mock_print.assert_called_with("Rescue mode is not active.")

    def test_rescue_server_not_found(self, mock_robot_client, inventory_file):
        """Test rescue command when server is not found."""
        mock_robot_client.find_server_number_by_ip.return_value = None

        args = argparse.Namespace(host="shadrach", client=mock_robot_client, deactivate=False)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_rescue(args)

        assert result == 1

    def test_rescue_api_failure(self, mock_robot_client, inventory_file):
        """Test rescue command when API calls fail."""
        mock_robot_client.get_boot.return_value = None

        args = argparse.Namespace(host="shadrach", client=mock_robot_client, deactivate=False)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_rescue(args)

        assert result == 1


class TestCommandReset:
    """Test cases for command_reset function."""

    def test_reset_success(self, mock_robot_client, inventory_file):
        """Test successful server reset."""
        mock_robot_client.reset_hard.return_value = {"reset": {"type": "hw", "server_number": 321}}

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print') as mock_print:
                result = command_reset(args)

        assert result == 0
        mock_robot_client.reset_hard.assert_called_once_with(321)
        mock_print.assert_called_with("Reset request sent successfully for server 321")

    def test_reset_server_not_found(self, mock_robot_client, inventory_file):
        """Test reset command when server is not found."""
        mock_robot_client.find_server_number_by_ip.return_value = None

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_reset(args)

        assert result == 1

    def test_reset_api_failure(self, mock_robot_client, inventory_file):
        """Test reset command when API call fails."""
        mock_robot_client.reset_hard.return_value = None

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_reset(args)

        assert result == 1


class TestCommandVswitch:
    """Test cases for command_vswitch function."""

    def test_vswitch_success(self, mock_robot_client, inventory_file):
        """Test successful vSwitch configuration."""
        mock_robot_client.set_vswitch.return_value = (True, True)

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print') as mock_print:
                result = command_vswitch(args)

        assert result == 0
        mock_robot_client.set_vswitch.assert_called_once_with(321, 4077, "94.130.9.179")
        mock_print.assert_called_with("Vswitch configured successfully for server 321")

    def test_vswitch_server_already_assigned(self, mock_robot_client, inventory_file):
        """Test vSwitch command when server is already assigned."""
        mock_robot_client.set_vswitch.return_value = (True, False)

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_vswitch(args)

        assert result == 0

    def test_vswitch_server_not_found(self, mock_robot_client, inventory_file):
        """Test vSwitch command when server is not found."""
        mock_robot_client.find_server_number_by_ip.return_value = None

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_vswitch(args)

        assert result == 1

    def test_vswitch_no_vlan(self, mock_robot_client, temp_dir):
        """Test vSwitch command when vlan is not configured."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "shadrach": {
                        "ansible_host": "94.130.9.179",
                        "ansible_password": "test_password_1"
                    }
                },
                "vars": {
                    "bastion_ips": ["8.8.8.8/32"]
                }
            }
        }

        inventory_file = temp_dir / "inventory.yml"
        with inventory_file.open("w") as f:
            import yaml
            yaml.dump(inventory_data, f)

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=temp_dir):
            with patch('sys.stderr') as mock_stderr:
                result = command_vswitch(args)

        assert result == 1
        mock_stderr.write.assert_called()

    def test_vswitch_api_failure(self, mock_robot_client, inventory_file):
        """Test vSwitch command when API call fails."""
        mock_robot_client.set_vswitch.return_value = None

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_vswitch(args)

        assert result == 1


class TestRunCommandOnAllHosts:
    """Test cases for _run_command_on_all_hosts function."""

    def test_run_command_on_all_hosts_success(self, inventory_file):
        """Test successful command execution on all hosts."""
        mock_client = Mock()
        mock_command_func = Mock(return_value=0)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print') as mock_print:
                result = _run_command_on_all_hosts(mock_command_func, "test operation", mock_client)

        assert result == 0
        assert mock_command_func.call_count == 2  # Two hosts in inventory
        mock_print.assert_called_with("\nTest Operation completed: 2/2 hosts processed successfully")

    def test_run_command_on_all_hosts_partial_failure(self, inventory_file):
        """Test command execution with partial failures."""
        mock_client = Mock()
        mock_command_func = Mock(side_effect=[0, 1])  # First succeeds, second fails

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print') as mock_print:
                result = _run_command_on_all_hosts(mock_command_func, "test operation", mock_client)

        assert result == 1
        assert mock_command_func.call_count == 2
        mock_print.assert_called_with("\nTest Operation completed: 1/2 hosts processed successfully")

    def test_run_command_on_all_hosts_no_hosts(self, temp_dir):
        """Test command execution when no hosts are found."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {},
                "vars": {
                    "bastion_ips": ["8.8.8.8/32"]
                }
            }
        }

        inventory_file = temp_dir / "inventory.yml"
        with inventory_file.open("w") as f:
            import yaml
            yaml.dump(inventory_data, f)

        mock_client = Mock()
        mock_command_func = Mock()

        with patch('utils.Path.cwd', return_value=temp_dir):
            with patch('builtins.print') as mock_print:
                result = _run_command_on_all_hosts(mock_command_func, "test operation", mock_client)

        assert result == 0
        mock_command_func.assert_not_called()
        mock_print.assert_called_with("No hosts found in inventory.yml")


class TestRunProvisionSteps:
    """Test cases for _run_provision_steps function."""

    def test_run_provision_steps_success(self):
        """Test successful provision steps execution."""
        steps = [
            ("step1", Mock(return_value=0), None),
            ("step2", Mock(return_value=0), None),
            ("step3", Mock(return_value=0), None)
        ]

        with patch('builtins.print'):
            with patch('time.sleep'):
                result = _run_provision_steps(steps, "test operation")

        assert result == 0
        for _, step_func, _ in steps:
            step_func.assert_called_once()

    def test_run_provision_steps_failure(self):
        """Test provision steps execution with failure."""
        steps = [
            ("step1", Mock(return_value=0), None),
            ("step2", Mock(return_value=1), None),  # This step fails
            ("step3", Mock(return_value=0), None)
        ]

        with patch('builtins.print'):
            with patch('time.sleep'):
                result = _run_provision_steps(steps, "test operation")

        assert result == 1
        steps[0][1].assert_called_once()  # First step called
        steps[1][1].assert_called_once()  # Second step called
        steps[2][1].assert_not_called()   # Third step not called due to failure


class TestCommandProvision:
    """Test cases for command_provision function."""

    def test_provision_success(self, mock_robot_client, inventory_file):
        """Test successful single host provision."""
        # Mock all command functions to succeed
        with patch('utils.command_rescue', return_value=0) as mock_rescue, \
             patch('utils.command_reset', return_value=0) as mock_reset, \
             patch('utils.command_vswitch', return_value=0) as mock_vswitch, \
             patch('utils.command_firewall', return_value=0) as mock_firewall, \
             patch('utils.remove_ips_from_known_hosts', return_value=1) as mock_remove, \
             patch('utils.get_host_ip_from_inventory', return_value="94.130.9.179"), \
             patch('utils.Path.cwd', return_value=inventory_file.parent), \
             patch('pathlib.Path.home', return_value=Path("/tmp")), \
             patch('builtins.print'), \
             patch('time.sleep'):

            args = argparse.Namespace(host="shadrach", client=mock_robot_client)
            result = command_provision(args)

        assert result == 0
        mock_rescue.assert_called_once()
        mock_reset.assert_called_once()
        mock_vswitch.assert_called_once()
        mock_firewall.assert_called_once()
        mock_remove.assert_called_once()

    def test_provision_step_failure(self, mock_robot_client, inventory_file):
        """Test provision when a step fails."""
        with patch('utils.command_rescue', return_value=1), \
             patch('utils.Path.cwd', return_value=inventory_file.parent), \
             patch('builtins.print'), \
             patch('time.sleep'):

            args = argparse.Namespace(host="shadrach", client=mock_robot_client)
            result = command_provision(args)

        assert result == 1


class TestCommandProvisionAll:
    """Test cases for command_provision_all function."""

    def test_provision_all_success(self, mock_robot_client, inventory_file):
        """Test successful all hosts provision."""
        with patch('utils.command_rescue_all', return_value=0) as mock_rescue_all, \
             patch('utils.command_reset_all', return_value=0) as mock_reset_all, \
             patch('utils.command_set_vswitch_all', return_value=0) as mock_vswitch_all, \
             patch('utils.command_set_firewall_all', return_value=0) as mock_firewall_all, \
             patch('utils.command_clear_known_hosts', return_value=0) as mock_clear, \
             patch('utils.Path.cwd', return_value=inventory_file.parent), \
             patch('builtins.print'), \
             patch('time.sleep'):

            args = argparse.Namespace(client=mock_robot_client)
            result = command_provision_all(args)

        assert result == 0
        mock_rescue_all.assert_called_once()
        mock_reset_all.assert_called_once()
        mock_vswitch_all.assert_called_once()
        mock_firewall_all.assert_called_once()
        mock_clear.assert_called_once()

    def test_provision_all_step_failure(self, mock_robot_client, inventory_file):
        """Test provision_all when a step fails."""
        with patch('utils.command_rescue_all', return_value=1), \
             patch('utils.Path.cwd', return_value=inventory_file.parent), \
             patch('builtins.print'), \
             patch('time.sleep'):

            args = argparse.Namespace(client=mock_robot_client)
            result = command_provision_all(args)

        assert result == 1


class TestCommandFirewall:
    """Test cases for command_firewall function."""

    def test_firewall_success(self, mock_robot_client, inventory_file):
        """Test successful firewall configuration."""
        # Mock firewall data with status not "in process"
        mock_robot_client.get_firewall.return_value = {
            "firewall": {
                "status": "active",
                "filter_ipv6": True,
                "whitelist_hos": True,
                "port": "main"
            }
        }
        mock_robot_client.set_firewall.return_value = {"success": True}

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print') as mock_print:
                result = command_firewall(args)

        assert result == 0
        mock_robot_client.get_firewall.assert_called_once_with(321)
        mock_robot_client.set_firewall.assert_called_once()
        mock_print.assert_any_call("Current firewall status: active")
        mock_print.assert_any_call("Firewall configuration updated successfully for server 321")

    def test_firewall_wait_for_ready(self, mock_robot_client, inventory_file):
        """Test firewall configuration when waiting for ready status."""
        # Mock firewall data with status "in process" initially, then "active"
        mock_robot_client.get_firewall.side_effect = [
            {"firewall": {"status": "in process"}},
            {"firewall": {"status": "active"}}
        ]
        mock_robot_client.wait_for_firewall_ready.return_value = True
        mock_robot_client.set_firewall.return_value = {"success": True}

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print') as mock_print:
                result = command_firewall(args)

        assert result == 0
        mock_robot_client.wait_for_firewall_ready.assert_called_once_with(321)
        mock_robot_client.set_firewall.assert_called_once()

    def test_firewall_wait_timeout(self, mock_robot_client, inventory_file):
        """Test firewall configuration when wait times out."""
        # Mock firewall data with status "in process"
        mock_robot_client.get_firewall.return_value = {
            "firewall": {"status": "in process"}
        }
        mock_robot_client.wait_for_firewall_ready.return_value = False

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_firewall(args)

        assert result == 1
        mock_robot_client.wait_for_firewall_ready.assert_called_once_with(321)
        mock_robot_client.set_firewall.assert_not_called()

    def test_firewall_server_not_found(self, mock_robot_client, inventory_file):
        """Test firewall command when server is not found."""
        mock_robot_client.find_server_number_by_ip.return_value = None

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_firewall(args)

        assert result == 1

    def test_firewall_api_failure(self, mock_robot_client, inventory_file):
        """Test firewall command when API calls fail."""
        mock_robot_client.get_firewall.return_value = None

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_firewall(args)

        assert result == 1

    def test_firewall_set_failure(self, mock_robot_client, inventory_file):
        """Test firewall command when set firewall fails."""
        mock_robot_client.get_firewall.return_value = {
            "firewall": {"status": "active"}
        }
        mock_robot_client.set_firewall.return_value = None

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            result = command_firewall(args)

        assert result == 1

    def test_firewall_includes_bastion_rules(self, mock_robot_client, inventory_file):
        """Test that firewall configuration includes bastion SSH rules."""
        mock_robot_client.get_firewall.return_value = {
            "firewall": {"status": "active"}
        }
        mock_robot_client.set_firewall.return_value = {"success": True}

        args = argparse.Namespace(host="shadrach", client=mock_robot_client)

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('builtins.print'):
                result = command_firewall(args)

        assert result == 0
        mock_robot_client.set_firewall.assert_called_once()

        # Get the form data that was passed to set_firewall
        call_args = mock_robot_client.set_firewall.call_args
        form_data = call_args[0][1]  # Second argument is the form data

        parsed_form_data = dict(parse_qsl(form_data))

        # Verify bastion rules are included
        assert parsed_form_data["rules[input][0][name]"] == "ssh bastion 0"
        assert parsed_form_data["rules[input][0][src_ip]"] == "8.8.8.8/32"
        assert parsed_form_data["rules[input][0][dst_port]"] == "22"
        assert parsed_form_data["rules[input][0][protocol]"] == "tcp"
        assert parsed_form_data["rules[input][0][action]"] == "accept"


class TestCommandSetFirewallAll:
    """Test cases for command_set_firewall_all function."""

    def test_set_firewall_all_success(self, inventory_file):
        """Test successful firewall configuration on all hosts."""
        mock_client = Mock()

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('utils._run_command_on_all_hosts', return_value=0) as mock_run_all:
                args = argparse.Namespace(client=mock_client)
                result = command_set_firewall_all(args)

        assert result == 0
        mock_run_all.assert_called_once_with(command_firewall, "set firewall", mock_client)

    def test_set_firewall_all_failure(self, inventory_file):
        """Test firewall configuration on all hosts with failures."""
        mock_client = Mock()

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('utils._run_command_on_all_hosts', return_value=1) as mock_run_all:
                args = argparse.Namespace(client=mock_client)
                result = command_set_firewall_all(args)

        assert result == 1
        mock_run_all.assert_called_once_with(command_firewall, "set firewall", mock_client)
