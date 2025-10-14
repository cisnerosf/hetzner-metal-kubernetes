"""Pytest configuration and shared fixtures for utils CLI tests."""

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import yaml
import pytest

from utils import HetznerRobotClient


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_inventory():
    """Sample inventory data matching the project structure."""
    return {
        "hetzner_k3s_metal": {
            "hosts": {
                "shadrach": {
                    "ansible_host": "94.130.9.179",
                    "ansible_password": "test_password_1",
                    "setup": "master",
                    "vlan_ip": "10.100.100.1"
                },
                "meshach": {
                    "ansible_host": "167.235.180.96",
                    "ansible_password": "test_password_2",
                    "setup": "master",
                    "vlan_ip": "10.100.100.2"
                }
            },
            "vars": {
                "vlan": 4077,
                "k3s_token": "test_token_123",
                "first_master": "shadrach"
            }
        }
    }


@pytest.fixture
def inventory_file(temp_dir, sample_inventory):
    """Create a temporary inventory.yml file for testing."""
    inventory_path = temp_dir / "inventory.yml"
    with inventory_path.open("w", encoding="utf-8") as f:
        yaml.dump(sample_inventory, f, default_flow_style=False)
    return inventory_path


@pytest.fixture
def mock_hetzner_api_responses():
    """Mock responses for Hetzner Robot API endpoints based on documentation."""
    return {
        # GET /server - List all servers
        "servers": [
            {
                "server": {
                    "server_ip": "94.130.9.179",
                    "server_ipv6_net": "2a01:f48:111:4221::",
                    "server_number": 321,
                    "server_name": "shadrach",
                    "product": "DS 3000",
                    "dc": "NBG1-DC1",
                    "traffic": "5 TB",
                    "status": "ready",
                    "cancelled": False,
                    "paid_until": "2024-12-31",
                    "ip": ["94.130.9.179"],
                    "subnet": [
                        {
                            "ip": "2a01:4f8:111:4221::",
                            "mask": "64"
                        }
                    ]
                }
            },
            {
                "server": {
                    "server_ip": "167.235.180.96",
                    "server_ipv6_net": "2a01:f48:111:4222::",
                    "server_number": 421,
                    "server_name": "meshach",
                    "product": "X5",
                    "dc": "FSN1-DC10",
                    "traffic": "2 TB",
                    "status": "ready",
                    "cancelled": False,
                    "paid_until": "2024-12-31",
                    "ip": ["167.235.180.96"],
                    "subnet": None
                }
            }
        ],

        # GET /boot/{server-number} - Boot configuration
        "boot_config": {
            "boot": {
                "rescue": {
                    "active": False,
                    "password": None
                },
                "linux": {
                    "active": True,
                    "dist": "ubuntu",
                    "arch": "64"
                }
            }
        },

        # POST /boot/{server-number}/rescue - Enable rescue mode
        "rescue_enabled": {
            "rescue": {
                "active": True,
                "password": "new_rescue_password_123"
            }
        },

        # GET /vswitch - List vSwitches
        "vswitches": [
            {
                "id": 123,
                "name": "k3s-cluster-4077",
                "vlan": 4077,
                "cancelled": False,
                "server": [
                    {
                        "server_ip": "94.130.9.179",
                        "server_number": 321,
                        "status": "ready"
                    }
                ],
                "subnet": [
                    {
                        "ip": "10.100.100.0",
                        "mask": 24,
                        "gateway": "10.100.100.1"
                    }
                ]
            }
        ],

        # POST /vswitch - Create vSwitch
        "vswitch_created": {
            "id": 124,
            "name": "k3s-cluster-4078",
            "vlan": 4078,
            "cancelled": False
        },

        # GET /vswitch/{vswitch-id} - vSwitch details
        "vswitch_details": {
            "id": 123,
            "name": "k3s-cluster-4077",
            "vlan": 4077,
            "cancelled": False,
            "server": [
                {
                    "server_ip": "94.130.9.179",
                    "server_number": 321,
                    "status": "ready"
                }
            ],
            "subnet": [
                {
                    "ip": "10.100.100.0",
                    "mask": 24,
                    "gateway": "10.100.100.1"
                }
            ]
        },

        # POST /reset/{server-number} - Server reset
        "reset_response": {
            "reset": {
                "type": "hw",
                "server_number": 321
            }
        }
    }


@pytest.fixture
def mock_requests():
    """Mock requests library for HTTP calls."""
    with patch('utils.requests') as mock_req:
        yield mock_req


@pytest.fixture
def mock_robot_client(mock_requests, mock_hetzner_api_responses):
    """Create a mocked HetznerRobotClient with predefined responses."""

    client = Mock(spec=HetznerRobotClient)
    client.user = "test_user"
    client.password = "test_pass"
    client.api_base = "https://robot-ws.your-server.de"

    # Mock the _request method to return predefined responses
    def mock_request(endpoint, method="GET", data=None, headers=None):
        if endpoint == "/server":
            return mock_hetzner_api_responses["servers"]
        if endpoint.startswith("/boot/") and method == "GET":
            return mock_hetzner_api_responses["boot_config"]
        if endpoint.endswith("/rescue") and method == "POST":
            return mock_hetzner_api_responses["rescue_enabled"]
        if endpoint == "/vswitch" and method == "GET":
            return mock_hetzner_api_responses["vswitches"]
        if endpoint == "/vswitch" and method == "POST":
            return mock_hetzner_api_responses["vswitch_created"]
        if endpoint.startswith("/vswitch/") and method == "GET":
            return mock_hetzner_api_responses["vswitch_details"]
        if endpoint.startswith("/reset/") and method == "POST":
            return mock_hetzner_api_responses["reset_response"]
        return None

    client._request = mock_request
    client.find_server_number_by_ip.return_value = 321
    client.get_boot.return_value = mock_hetzner_api_responses["boot_config"]
    client.enable_rescue.return_value = mock_hetzner_api_responses["rescue_enabled"]
    client.disable_rescue.return_value = {"success": True}
    client.reset_hard.return_value = mock_hetzner_api_responses["reset_response"]
    client.get_vswitches.return_value = mock_hetzner_api_responses["vswitches"]
    client.create_vswitch.return_value = mock_hetzner_api_responses["vswitch_created"]
    client.get_vswitch_details.return_value = mock_hetzner_api_responses["vswitch_details"]
    client.assign_server_to_vswitch.return_value = {"success": True}
    client.check_vswitch_servers_ready.return_value = True
    client.set_vswitch.return_value = (True, True)

    return client


@pytest.fixture
def mock_environment():
    """Mock environment variables for testing."""
    with patch.dict(os.environ, {
        'ROBOT_WEBSERVICE_USER': 'test_user',
        'ROBOT_WEBSERVICE_PASS': 'test_pass'
    }):
        yield


@pytest.fixture
def mock_known_hosts_file(temp_dir):
    """Create a mock SSH known_hosts file for testing."""
    known_hosts_path = temp_dir / "known_hosts"
    known_hosts_content = """94.130.9.179 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...
167.235.180.96 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...
other.host.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...
"""
    with known_hosts_path.open("w") as f:
        f.write(known_hosts_content)
    return known_hosts_path


@pytest.fixture
def mock_home_dir(temp_dir):
    """Mock the home directory for SSH known_hosts testing."""
    with patch('pathlib.Path.home', return_value=temp_dir):
        yield temp_dir
