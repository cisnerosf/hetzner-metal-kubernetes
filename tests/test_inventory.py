"""Tests for inventory parsing and manipulation functions."""

from unittest.mock import patch
import yaml
import pytest

from utils import (
    _load_inventory,
    parse_inventory_ips,
    get_host_ip_from_inventory,
    _update_inventory_password
)


class TestLoadInventory:
    """Test cases for _load_inventory function."""

    def test_load_inventory_success(self, inventory_file, sample_inventory):
        """Test successful inventory loading."""
        hosts, vlan, bastion_ips = _load_inventory(inventory_file)

        assert isinstance(hosts, dict)
        assert len(hosts) == 2
        assert "shadrach" in hosts
        assert "meshach" in hosts
        assert vlan == 4077
        assert bastion_ips == ["8.8.8.8/32"]

    def test_load_inventory_file_not_found(self, temp_dir):
        """Test inventory loading when file doesn't exist."""
        non_existent_file = temp_dir / "nonexistent.yml"

        with pytest.raises(FileNotFoundError) as exc_info:
            _load_inventory(non_existent_file)

        assert "inventory file not found" in str(exc_info.value)

    def test_load_inventory_empty_file(self, temp_dir):
        """Test inventory loading with empty file."""
        empty_file = temp_dir / "empty.yml"
        empty_file.touch()

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(empty_file)
        assert "bastion_ips is required" in str(exc_info.value)

    def test_load_inventory_invalid_yaml(self, temp_dir):
        """Test inventory loading with invalid YAML."""
        invalid_file = temp_dir / "invalid.yml"
        with invalid_file.open("w") as f:
            f.write("invalid: yaml: content: [")

        with pytest.raises(yaml.YAMLError):
            _load_inventory(invalid_file)

    def test_load_inventory_valid_vlan(self, temp_dir):
        """Test inventory loading with valid vlan values."""
        test_cases = [4000, 4091, 4050]

        for vlan_value in test_cases:
            inventory_data = {
                "hetzner_k3s_metal": {
                    "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                    "vars": {
                        "vlan": vlan_value,
                        "bastion_ips": ["8.8.8.8/32"]
                    }
                }
            }

            inventory_file = temp_dir / f"test_{vlan_value}.yml"
            with inventory_file.open("w") as f:
                yaml.dump(inventory_data, f)

            _, vlan, _ = _load_inventory(inventory_file)
            assert vlan == vlan_value

    def test_load_inventory_invalid_vlan_too_low(self, temp_dir):
        """Test inventory loading with vlan too low."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "vlan": 3999,
                    "bastion_ips": ["8.8.8.8/32"]
                }
            }
        }

        inventory_file = temp_dir / "invalid_low.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(inventory_file)

        assert "Invalid vlan 3999: must be a number between 4000 and 4091" in str(exc_info.value)

    def test_load_inventory_invalid_vlan_too_high(self, temp_dir):
        """Test inventory loading with vlan too high."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "vlan": 4092,
                    "bastion_ips": ["8.8.8.8/32"]
                }
            }
        }

        inventory_file = temp_dir / "invalid_high.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(inventory_file)

        assert "Invalid vlan 4092: must be a number between 4000 and 4091" in str(exc_info.value)

    def test_load_inventory_invalid_vlan_type(self, temp_dir):
        """Test inventory loading with invalid vlan type."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "vlan": "not_a_number",
                    "bastion_ips": ["8.8.8.8/32"]
                }
            }
        }

        inventory_file = temp_dir / "invalid_type.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(inventory_file)

        assert "Invalid vlan not_a_number: must be a number between 4000 and 4091" in str(exc_info.value)

    def test_load_inventory_no_vlan(self, temp_dir):
        """Test inventory loading without vlan specified."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "bastion_ips": ["8.8.8.8/32"]
                }
            }
        }

        inventory_file = temp_dir / "no_vlan.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        _, vlan, _ = _load_inventory(inventory_file)
        assert vlan is None

    def test_load_inventory_no_hosts(self, temp_dir):
        """Test inventory loading without hosts."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "vars": {
                    "vlan": 4077,
                    "bastion_ips": ["8.8.8.8/32"]
                }
            }
        }

        inventory_file = temp_dir / "no_hosts.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        hosts, vlan, _ = _load_inventory(inventory_file)
        assert hosts == {}
        assert vlan == 4077

    def test_load_inventory_bastion_ips_valid(self, temp_dir):
        """Test inventory loading with valid bastion_ips."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "bastion_ips": ["8.8.8.8/32", "192.168.1.1/32"]
                }
            }
        }

        inventory_file = temp_dir / "bastion_valid.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        _, _, bastion_ips = _load_inventory(inventory_file)
        assert bastion_ips == ["8.8.8.8/32", "192.168.1.1/32"]

    def test_load_inventory_bastion_ips_empty_list(self, temp_dir):
        """Test inventory loading with empty bastion_ips list."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "bastion_ips": []
                }
            }
        }

        inventory_file = temp_dir / "bastion_empty.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(inventory_file)

        assert "bastion_ips must contain at least one IPv4 CIDR address" in str(exc_info.value)

    def test_load_inventory_bastion_ips_too_many(self, temp_dir):
        """Test inventory loading with too many bastion_ips."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "bastion_ips": ["1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32", "4.4.4.4/32"]
                }
            }
        }

        inventory_file = temp_dir / "bastion_too_many.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(inventory_file)

        assert "bastion_ips must contain at most 3 IPv4 CIDR addresses" in str(exc_info.value)

    def test_load_inventory_bastion_ips_invalid_cidr(self, temp_dir):
        """Test inventory loading with invalid CIDR in bastion_ips."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "bastion_ips": ["999.999.999.999/32"]
                }
            }
        }

        inventory_file = temp_dir / "bastion_invalid.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(inventory_file)

        assert "is not a valid IPv4 CIDR address" in str(exc_info.value)

    def test_load_inventory_bastion_ips_missing_cidr_notation(self, temp_dir):
        """Test inventory loading with IP address missing CIDR notation."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "bastion_ips": ["8.8.8.8"]
                }
            }
        }

        inventory_file = temp_dir / "bastion_missing_cidr.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(inventory_file)

        assert "is missing CIDR notation" in str(exc_info.value)
        assert "8.8.8.8" in str(exc_info.value)

    def test_load_inventory_bastion_ips_not_list(self, temp_dir):
        """Test inventory loading with bastion_ips not being a list."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "bastion_ips": "8.8.8.8/32"
                }
            }
        }

        inventory_file = temp_dir / "bastion_not_list.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(inventory_file)

        assert "bastion_ips must be a list" in str(exc_info.value)

    def test_load_inventory_missing_bastion_ips(self, temp_dir):
        """Test inventory loading when bastion_ips is missing."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {"test": {"ansible_host": "1.2.3.4"}},
                "vars": {
                    "vlan": 4077
                }
            }
        }

        inventory_file = temp_dir / "missing_bastion.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(ValueError) as exc_info:
            _load_inventory(inventory_file)

        assert "bastion_ips is required" in str(exc_info.value)


class TestParseInventoryIps:
    """Test cases for parse_inventory_ips function."""

    def test_parse_inventory_ips_success(self, inventory_file):
        """Test successful IP parsing from inventory."""
        ips = parse_inventory_ips(inventory_file)

        assert isinstance(ips, list)
        assert len(ips) == 2
        assert "94.130.9.179" in ips
        assert "167.235.180.96" in ips

    def test_parse_inventory_ips_no_hosts(self, temp_dir):
        """Test IP parsing with no hosts."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "vars": {"vlan": 4077, "bastion_ips": ["8.8.8.8/32"]}
            }
        }

        inventory_file = temp_dir / "no_hosts.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        ips = parse_inventory_ips(inventory_file)
        assert ips == []

    def test_parse_inventory_ips_missing_ansible_host(self, temp_dir):
        """Test IP parsing with hosts missing ansible_host."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "host1": {"ansible_password": "pass1"},
                    "host2": {"ansible_host": "1.2.3.4"}
                },
                "vars": {"bastion_ips": ["8.8.8.8/32"]}
            }
        }

        inventory_file = temp_dir / "missing_host.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        ips = parse_inventory_ips(inventory_file)
        assert ips == ["1.2.3.4"]

    def test_parse_inventory_ips_empty_ansible_host(self, temp_dir):
        """Test IP parsing with empty ansible_host values."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "host1": {"ansible_host": ""},
                    "host2": {"ansible_host": "   "},
                    "host3": {"ansible_host": "1.2.3.4"}
                },
                "vars": {"bastion_ips": ["8.8.8.8/32"]}
            }
        }

        inventory_file = temp_dir / "empty_host.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        ips = parse_inventory_ips(inventory_file)
        assert ips == ["", "1.2.3.4"]  # Empty string is included for empty ansible_host


class TestGetHostIpFromInventory:
    """Test cases for get_host_ip_from_inventory function."""

    def test_get_host_ip_success(self, inventory_file):
        """Test successful host IP retrieval."""
        ip = get_host_ip_from_inventory(inventory_file, "shadrach")
        assert ip == "94.130.9.179"

    def test_get_host_ip_not_found(self, inventory_file):
        """Test host IP retrieval when host doesn't exist."""
        with pytest.raises(KeyError) as exc_info:
            get_host_ip_from_inventory(inventory_file, "nonexistent")

        assert "host not found in inventory: nonexistent" in str(exc_info.value)

    def test_get_host_ip_missing_ansible_host(self, temp_dir):
        """Test host IP retrieval when ansible_host is missing."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "test_host": {"ansible_password": "pass1"}
                },
                "vars": {"bastion_ips": ["8.8.8.8/32"]}
            }
        }

        inventory_file = temp_dir / "missing_ansible_host.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        with pytest.raises(KeyError) as exc_info:
            get_host_ip_from_inventory(inventory_file, "test_host")

        assert "host 'test_host' missing ansible_host in inventory" in str(exc_info.value)

    def test_get_host_ip_strips_whitespace(self, temp_dir):
        """Test that host IP strips whitespace."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "test_host": {"ansible_host": "  1.2.3.4  "}
                },
                "vars": {"bastion_ips": ["8.8.8.8/32"]}
            }
        }

        inventory_file = temp_dir / "whitespace.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        ip = get_host_ip_from_inventory(inventory_file, "test_host")
        assert ip == "1.2.3.4"


class TestUpdateInventoryPassword:
    """Test cases for _update_inventory_password function."""

    def test_update_inventory_password_success(self, inventory_file):
        """Test successful password update."""
        result = _update_inventory_password(inventory_file, "shadrach", "new_password_123")

        assert result is True

        # Verify the password was actually updated
        with inventory_file.open("r") as f:
            content = f.read()
            assert "new_password_123" in content
            assert "test_password_1" not in content

    def test_update_inventory_password_file_not_found(self, temp_dir):
        """Test password update when file doesn't exist."""
        non_existent_file = temp_dir / "nonexistent.yml"

        result = _update_inventory_password(non_existent_file, "shadrach", "new_password")
        assert result is False

    def test_update_inventory_password_host_not_found(self, inventory_file):
        """Test password update when host doesn't exist."""
        result = _update_inventory_password(inventory_file, "nonexistent", "new_password")
        assert result is False

    def test_update_inventory_password_no_existing_password(self, temp_dir):
        """Test password update when host has no existing password."""
        inventory_data = {
            "hetzner_k3s_metal": {
                "hosts": {
                    "test_host": {"ansible_host": "1.2.3.4"}
                }
            }
        }

        inventory_file = temp_dir / "no_password.yml"
        with inventory_file.open("w") as f:
            yaml.dump(inventory_data, f)

        result = _update_inventory_password(inventory_file, "test_host", "new_password")
        assert result is False

    def test_update_inventory_password_preserves_formatting(self, inventory_file):
        """Test that password update preserves YAML formatting."""
        result = _update_inventory_password(inventory_file, "shadrach", "new_password_123")
        assert result is True

        # Read updated content
        with inventory_file.open("r") as f:
            updated_content = f.read()

        # Verify the structure is preserved (basic check)
        assert "ansible_host:" in updated_content
        assert "ansible_password:" in updated_content
        assert "setup:" in updated_content
        assert "vlan_ip:" in updated_content

    def test_update_inventory_password_handles_exception(self, inventory_file):
        """Test password update exception handling."""
        # Mock the Path.open method to raise an exception
        with patch('pathlib.Path.open', side_effect=IOError("Permission denied")):
            result = _update_inventory_password(inventory_file, "shadrach", "new_password")

        # Function should handle exception gracefully and return False
        assert result is False
