"""Integration tests for utils CLI tool."""

from unittest.mock import Mock, patch
import yaml

from utils import main


class TestIntegration:
    """Integration tests that test multiple components working together."""

    def test_full_rescue_workflow(self, temp_dir, mock_hetzner_api_responses):
        """Test complete rescue workflow from CLI to API."""
        # Create test inventory
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "test-server": {
                        "ansible_host": "94.130.9.179",
                        "ansible_password": "old_password"
                    }
                },
                "vars": {
                    "vlan": 4077
                }
            }
        }

        inventory_file = temp_dir / "inventory.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        # Mock the HetznerRobotClient to return realistic responses
        with patch('utils.HetznerRobotClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            # Mock API responses
            mock_client.find_server_number_by_ip.return_value = 321
            mock_client.get_boot.return_value = {
                "boot": {
                    "rescue": {
                        "active": False,
                        "password": None
                    }
                }
            }
            mock_client.enable_rescue.return_value = {
                "rescue": {
                    "active": True,
                    "password": "new_rescue_password_123"
                }
            }

            # Change to test directory
            with patch('utils.Path.cwd', return_value=temp_dir):
                result = main(["rescue", "test-server"])

        assert result == 0
        mock_client.find_server_number_by_ip.assert_called_once_with("94.130.9.179")
        mock_client.get_boot.assert_called_once_with(321)
        mock_client.enable_rescue.assert_called_once_with(321, os_name="linux")

        # Verify inventory was updated
        with inventory_file.open("r") as f:
            updated_inventory = yaml.safe_load(f)

        assert updated_inventory["hetzner_k3s_metal"]["hosts"]["test-server"]["ansible_password"] == "new_rescue_password_123"

    def test_full_vswitch_workflow(self, temp_dir, mock_hetzner_api_responses):
        """Test complete vSwitch workflow from CLI to API."""
        # Create test inventory
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "test-server": {
                        "ansible_host": "94.130.9.179",
                        "ansible_password": "test_password"
                    }
                },
                "vars": {
                    "vlan": 4077
                }
            }
        }

        inventory_file = temp_dir / "inventory.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        # Mock the HetznerRobotClient
        with patch('utils.HetznerRobotClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            # Mock API responses for vSwitch workflow
            mock_client.find_server_number_by_ip.return_value = 321
            mock_client.get_vswitches.return_value = [
                {
                    "id": 123,
                    "vlan": 4077,
                    "cancelled": False,
                    "name": "existing-vswitch"
                }
            ]
            mock_client.get_vswitch_details.return_value = {
                "server": []
            }
            mock_client.check_vswitch_servers_ready.return_value = True
            mock_client.assign_server_to_vswitch.return_value = {"success": True}
            mock_client.set_vswitch.return_value = (True, True)

            # Change to test directory
            with patch('utils.Path.cwd', return_value=temp_dir):
                with patch('time.sleep'):  # Skip sleep in tests
                    result = main(["set_vswitch", "test-server"])

        assert result == 0
        mock_client.find_server_number_by_ip.assert_called_once_with("94.130.9.179")
        # The set_vswitch method should have been called, which internally calls get_vswitches
        mock_client.set_vswitch.assert_called_once_with(321, 4077, "94.130.9.179")

    def test_set_vswitch_all_batch_integration(self, temp_dir, mock_hetzner_api_responses):
        """Test batch vswitch assignment for all hosts integration."""
        # Create test inventory with multiple hosts
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "test-server-1": {
                        "ansible_host": "94.130.9.179",
                        "ansible_password": "test-pass-1"
                    },
                    "test-server-2": {
                        "ansible_host": "94.130.9.180",
                        "ansible_password": "test-pass-2"
                    },
                    "test-server-3": {
                        "ansible_host": "94.130.9.181",
                        "ansible_password": "test-pass-3"
                    }
                },
                "vars": {
                    "vlan": 4077
                }
            }
        }

        inventory_path = temp_dir / "inventory.yml"
        with open(inventory_path, 'w') as f:
            yaml.dump(inventory_data, f)

        with patch('utils.HetznerRobotClient') as mock_client_class:
            mock_client = mock_client_class.return_value

            # Mock server number lookups
            mock_client.find_server_number_by_ip.side_effect = [321, 322, 323]

            # Mock vswitch operations
            mock_client.get_vswitches.return_value = [
                {
                    "id": 123,
                    "vlan": 4077,
                    "cancelled": False,
                    "name": "existing-vswitch"
                }
            ]
            mock_client.get_vswitch_details.return_value = {
                "server": []  # No servers assigned yet
            }
            mock_client.check_vswitch_servers_ready.return_value = True
            mock_client.assign_server_to_vswitch.return_value = {"success": True}

            # Change to test directory
            with patch('utils.Path.cwd', return_value=temp_dir):
                with patch('time.sleep'):  # Skip sleep in tests
                    result = main(["set_vswitch_all"])

        assert result == 0
        # Verify that assign_server_to_vswitch was called once with all three IPs
        mock_client.assign_server_to_vswitch.assert_called_once_with(123, ["94.130.9.179", "94.130.9.180", "94.130.9.181"])

    def test_provision_workflow_integration(self, temp_dir, mock_hetzner_api_responses):
        """Test complete provision workflow integration."""
        # Create test inventory
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "test-server": {
                        "ansible_host": "94.130.9.179",
                        "ansible_password": "old_password"
                    }
                },
                "vars": {
                    "vlan": 4077
                }
            }
        }

        inventory_file = temp_dir / "inventory.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        # Create mock known_hosts file
        known_hosts = temp_dir / ".ssh" / "known_hosts"
        known_hosts.parent.mkdir(parents=True, exist_ok=True)
        known_hosts.write_text("94.130.9.179 ssh-rsa AAAAB3NzaC1yc2E...\nother.host.com ssh-rsa AAAAB3NzaC1yc2E...\n")

        # Mock the HetznerRobotClient
        with patch('utils.HetznerRobotClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            # Mock all API responses for provision workflow
            mock_client.find_server_number_by_ip.return_value = 321

            # Rescue step
            mock_client.get_boot.return_value = {
                "boot": {
                    "rescue": {
                        "active": False,
                        "password": None
                    }
                }
            }
            mock_client.enable_rescue.return_value = {
                "rescue": {
                    "active": True,
                    "password": "new_rescue_password_123"
                }
            }

            # Reset step
            mock_client.reset_hard.return_value = {
                "reset": {
                    "type": "hw",
                    "server_number": 321
                }
            }

            # vSwitch step
            mock_client.get_vswitches.return_value = []
            mock_client.create_vswitch.return_value = {"id": 124}
            mock_client.get_vswitch_details.return_value = {"server": []}
            mock_client.check_vswitch_servers_ready.return_value = True
            mock_client.assign_server_to_vswitch.return_value = {"success": True}
            mock_client.set_vswitch.return_value = (True, True)

            # Change to test directory and mock home directory
            with patch('utils.Path.cwd', return_value=temp_dir), \
                 patch('pathlib.Path.home', return_value=temp_dir), \
                 patch('builtins.print'), \
                 patch('time.sleep'):  # Skip all sleeps in tests

                result = main(["provision", "test-server"])

        assert result == 0

        # Verify all API calls were made
        mock_client.find_server_number_by_ip.assert_called_with("94.130.9.179")
        mock_client.get_boot.assert_called_with(321)
        mock_client.enable_rescue.assert_called_with(321, os_name="linux")
        mock_client.reset_hard.assert_called_with(321)
        mock_client.set_vswitch.assert_called_with(321, 4077, "94.130.9.179")

        # Verify inventory was updated
        with inventory_file.open("r") as f:
            updated_inventory = yaml.safe_load(f)

        assert updated_inventory["hetzner_k3s_metal"]["hosts"]["test-server"]["ansible_password"] == "new_rescue_password_123"

        # Verify known_hosts was updated
        known_hosts_content = known_hosts.read_text()
        assert "94.130.9.179" not in known_hosts_content
        assert "other.host.com" in known_hosts_content

    def test_error_handling_integration(self, temp_dir):
        """Test error handling across the entire workflow."""
        # Create test inventory
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "test-server": {
                        "ansible_host": "94.130.9.179",
                        "ansible_password": "test_password"
                    }
                },
                "vars": {
                    "vlan": 4077
                }
            }
        }

        inventory_file = temp_dir / "inventory.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        # Mock the HetznerRobotClient to simulate API failure
        with patch('utils.HetznerRobotClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            # Mock API failure
            mock_client.find_server_number_by_ip.return_value = None

            # Change to test directory
            with patch('utils.Path.cwd', return_value=temp_dir):
                result = main(["rescue", "test-server"])

        assert result == 1

    def test_multi_host_workflow(self, temp_dir, mock_hetzner_api_responses):
        """Test workflow with multiple hosts."""
        # Create test inventory with multiple hosts
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "server1": {
                        "ansible_host": "94.130.9.179",
                        "ansible_password": "password1"
                    },
                    "server2": {
                        "ansible_host": "167.235.180.96",
                        "ansible_password": "password2"
                    }
                },
                "vars": {
                    "vlan": 4077
                }
            }
        }

        inventory_file = temp_dir / "inventory.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        # Mock the HetznerRobotClient
        with patch('utils.HetznerRobotClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client

            # Mock API responses for both servers
            def mock_find_server(ip):
                if ip == "94.130.9.179":
                    return 321
                if ip == "167.235.180.96":
                    return 421
                return None

            mock_client.find_server_number_by_ip.side_effect = mock_find_server
            mock_client.reset_hard.return_value = {"reset": {"type": "hw"}}

            # Change to test directory
            with patch('utils.Path.cwd', return_value=temp_dir):
                with patch('builtins.print'):
                    result = main(["reset_all"])

        assert result == 0
        assert mock_client.reset_hard.call_count == 2
        mock_client.reset_hard.assert_any_call(321)
        mock_client.reset_hard.assert_any_call(421)
