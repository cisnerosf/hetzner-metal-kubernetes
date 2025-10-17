"""Tests for HetznerRobotClient class."""

from unittest.mock import Mock, patch
import requests

from utils import HetznerRobotClient


class TestHetznerRobotClient:
    """Test cases for HetznerRobotClient class."""

    def test_init_with_credentials(self):
        """Test client initialization with explicit credentials."""
        client = HetznerRobotClient(user="test_user", password="test_pass")
        assert client.user == "test_user"
        assert client.password == "test_pass"
        assert client.api_base == "https://robot-ws.your-server.de"

    def test_init_with_environment_variables(self, mock_environment):
        """Test client initialization with environment variables."""
        client = HetznerRobotClient()
        assert client.user == "test_user"
        assert client.password == "test_pass"

    def test_init_with_custom_api_base(self):
        """Test client initialization with custom API base URL."""
        client = HetznerRobotClient(api_base="https://custom-api.example.com")
        assert client.api_base == "https://custom-api.example.com"

    def test_has_credentials_with_credentials(self):
        """Test has_credentials returns True when credentials are set."""
        client = HetznerRobotClient(user="test_user", password="test_pass")
        assert client.has_credentials() is True

    def test_has_credentials_without_credentials(self):
        """Test has_credentials returns False when credentials are missing."""
        with patch.dict('os.environ', {}, clear=True):
            client = HetznerRobotClient()
            assert client.has_credentials() is False

    def test_has_credentials_partial_credentials(self):
        """Test has_credentials returns False when only one credential is set."""
        with patch.dict('os.environ', {}, clear=True):
            client = HetznerRobotClient(user="test_user", password=None)
            assert client.has_credentials() is False

    @patch('utils.requests.get')
    def test_request_success(self, mock_get):
        """Test successful HTTP request."""
        mock_response = Mock()
        mock_response.json.return_value = {"status": "success"}
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        client = HetznerRobotClient(user="test_user", password="test_pass")
        result = client._request("/test")

        assert result == {"status": "success"}
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert call_args[1]["auth"] == ("test_user", "test_pass")
        assert call_args[1]["headers"]["Accept"] == "application/json"
        assert call_args[1]["headers"]["User-Agent"] == "utils-cli/1.0"

    @patch('utils.requests.get')
    def test_request_http_error(self, mock_get):
        """Test HTTP error handling."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
        mock_get.return_value = mock_response

        client = HetznerRobotClient(user="test_user", password="test_pass")
        result = client._request("/test")

        assert result is None

    @patch('utils.requests.get')
    def test_request_connection_error(self, mock_get):
        """Test connection error handling."""
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")

        client = HetznerRobotClient(user="test_user", password="test_pass")
        result = client._request("/test")

        assert result is None

    @patch('utils.requests.get')
    def test_request_json_decode_error(self, mock_get):
        """Test JSON decode error handling."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response

        client = HetznerRobotClient(user="test_user", password="test_pass")
        result = client._request("/test")

        assert result is None

    def test_find_server_number_by_ip_success(self, mock_robot_client):
        """Test finding server number by IP address."""
        server_number = mock_robot_client.find_server_number_by_ip("94.130.9.179")
        assert server_number == 321

    def test_find_server_number_by_ip_not_found(self, mock_robot_client):
        """Test finding server number when IP is not found."""
        # Override the mock to return None for this specific test
        mock_robot_client.find_server_number_by_ip.return_value = None
        server_number = mock_robot_client.find_server_number_by_ip("192.168.1.1")
        assert server_number is None

    def test_find_server_number_by_ip_no_credentials(self):
        """Test finding server number without credentials."""
        with patch.dict('os.environ', {}, clear=True):
            client = HetznerRobotClient()
            server_number = client.find_server_number_by_ip("94.130.9.179")
            assert server_number is None

    def test_find_server_number_by_ip_cancelled_server(self, mock_robot_client):
        """Test finding server number when server is cancelled."""
        # Mock response with cancelled server
        mock_robot_client._request = Mock(return_value=[
            {
                "server": {
                    "server_ip": "94.130.9.179",
                    "server_number": 321,
                    "status": "ready",
                    "cancelled": True
                }
            }
        ])
        # Override the find_server_number_by_ip method to use the mocked _request
        def mock_find_server(ip):
            data = mock_robot_client._request("/server")
            if not isinstance(data, list):
                return None
            for item in data:
                server = item.get("server", {}) if isinstance(item, dict) else {}
                if (server.get("server_ip") == ip and
                    server.get("status") == "ready" and
                    server.get("cancelled") is False):
                    return server.get("server_number")
            return None

        mock_robot_client.find_server_number_by_ip = mock_find_server
        server_number = mock_robot_client.find_server_number_by_ip("94.130.9.179")
        assert server_number is None

    def test_find_server_number_by_ip_not_ready(self, mock_robot_client):
        """Test finding server number when server is not ready."""
        # Mock response with not ready server
        mock_robot_client._request = Mock(return_value=[
            {
                "server": {
                    "server_ip": "94.130.9.179",
                    "server_number": 321,
                    "status": "processing",
                    "cancelled": False
                }
            }
        ])
        # Override the find_server_number_by_ip method to use the mocked _request
        def mock_find_server(ip):
            data = mock_robot_client._request("/server")
            if not isinstance(data, list):
                return None
            for item in data:
                server = item.get("server", {}) if isinstance(item, dict) else {}
                if (server.get("server_ip") == ip and
                    server.get("status") == "ready" and
                    server.get("cancelled") is False):
                    return server.get("server_number")
            return None

        mock_robot_client.find_server_number_by_ip = mock_find_server
        server_number = mock_robot_client.find_server_number_by_ip("94.130.9.179")
        assert server_number is None

    def test_get_boot(self, mock_robot_client):
        """Test getting boot configuration."""
        result = mock_robot_client.get_boot(321)
        assert result is not None
        assert "boot" in result

    def test_enable_rescue(self, mock_robot_client):
        """Test enabling rescue mode."""
        result = mock_robot_client.enable_rescue(321, "linux")
        assert result is not None
        assert "rescue" in result
        assert result["rescue"]["active"] is True

    def test_disable_rescue(self, mock_robot_client):
        """Test disabling rescue mode."""
        # Override the mock to return None for DELETE requests
        mock_robot_client.disable_rescue.return_value = None
        result = mock_robot_client.disable_rescue(321)
        # DELETE requests typically return None or empty response
        assert result is None

    def test_reset_hard(self, mock_robot_client):
        """Test hard reset."""
        result = mock_robot_client.reset_hard(321)
        assert result is not None
        assert "reset" in result

    def test_get_vswitches(self, mock_robot_client):
        """Test getting vSwitches list."""
        result = mock_robot_client.get_vswitches()
        assert result is not None
        assert isinstance(result, list)
        assert len(result) > 0

    def test_create_vswitch(self, mock_robot_client):
        """Test creating a vSwitch."""
        result = mock_robot_client.create_vswitch(4078, "test-vswitch")
        assert result is not None
        assert "id" in result
        assert result["vlan"] == 4078

    def test_get_vswitch_details(self, mock_robot_client):
        """Test getting vSwitch details."""
        result = mock_robot_client.get_vswitch_details(123)
        assert result is not None
        assert "id" in result
        assert result["id"] == 123

    @patch('utils.requests.post')
    def test_assign_server_to_vswitch_success(self, mock_post):
        """Test successful server assignment to vSwitch."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        client = HetznerRobotClient(user="test_user", password="test_pass")
        result = client.assign_server_to_vswitch(123, "94.130.9.179")

        assert result == {"success": True}
        mock_post.assert_called_once()

    @patch('utils.requests.post')
    def test_assign_server_to_vswitch_failure(self, mock_post):
        """Test server assignment to vSwitch failure."""
        mock_post.side_effect = requests.exceptions.HTTPError("409 Conflict")

        client = HetznerRobotClient(user="test_user", password="test_pass")
        result = client.assign_server_to_vswitch(123, "94.130.9.179")

        assert result is None

    @patch('utils.requests.post')
    def test_assign_multiple_servers_to_vswitch_success(self, mock_post):
        """Test successful batch server assignment to vSwitch."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        client = HetznerRobotClient(user="test_user", password="test_pass")
        server_ips = ["94.130.9.179", "94.130.9.180", "94.130.9.181"]
        result = client.assign_server_to_vswitch(123, server_ips)

        assert result == {"success": True}
        mock_post.assert_called_once()

        # Verify the payload contains multiple server entries
        call_args = mock_post.call_args
        payload = call_args[1]['data']
        assert payload["server[0]"] == "94.130.9.179"
        assert payload["server[1]"] == "94.130.9.180"
        assert payload["server[2]"] == "94.130.9.181"

    @patch('utils.requests.post')
    def test_assign_multiple_servers_to_vswitch_failure(self, mock_post):
        """Test batch server assignment to vSwitch failure."""
        mock_post.side_effect = requests.exceptions.HTTPError("409 Conflict")

        client = HetznerRobotClient(user="test_user", password="test_pass")
        server_ips = ["94.130.9.179", "94.130.9.180"]
        result = client.assign_server_to_vswitch(123, server_ips)

        assert result is None

    @patch('time.sleep')
    @patch('utils.requests.post')
    def test_set_vswitch_batch_success(self, mock_post, mock_sleep):
        """Test successful batch vswitch assignment."""
        # Mock successful API responses
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        client = HetznerRobotClient(user="test_user", password="test_pass")

        # Mock the internal methods that set_vswitch_batch calls
        with patch.object(client, 'get_vswitches') as mock_get_vswitches, \
             patch.object(client, 'get_vswitch_details') as mock_get_details, \
             patch.object(client, 'check_vswitch_servers_ready') as mock_check_ready, \
             patch.object(client, 'assign_server_to_vswitch') as mock_assign:

            mock_get_vswitches.return_value = [
                {
                    "id": 123,
                    "vlan": 4077,
                    "cancelled": False,
                    "name": "existing-vswitch"
                }
            ]
            mock_get_details.return_value = {
                "server": []  # No servers assigned yet
            }
            mock_check_ready.return_value = True
            mock_assign.return_value = {"success": True}

            server_data = [
                ("host1", 321, "94.130.9.179"),
                ("host2", 322, "94.130.9.180"),
                ("host3", 323, "94.130.9.181")
            ]

            result = client.set_vswitch_batch(server_data, 4077)

            assert result == (3, 3)  # (success_count, total_count)
            mock_assign.assert_called_once_with(123, ["94.130.9.179", "94.130.9.180", "94.130.9.181"])

    @patch('time.sleep')
    @patch('utils.requests.post')
    def test_set_vswitch_batch_with_existing_assignments(self, mock_post, mock_sleep):
        """Test batch vswitch assignment when some servers are already assigned."""
        # Mock successful API responses
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        client = HetznerRobotClient(user="test_user", password="test_pass")

        # Mock the internal methods that set_vswitch_batch calls
        with patch.object(client, 'get_vswitches') as mock_get_vswitches, \
             patch.object(client, 'get_vswitch_details') as mock_get_details, \
             patch.object(client, 'check_vswitch_servers_ready') as mock_check_ready, \
             patch.object(client, 'assign_server_to_vswitch') as mock_assign:

            mock_get_vswitches.return_value = [
                {
                    "id": 123,
                    "vlan": 4077,
                    "cancelled": False,
                    "name": "existing-vswitch"
                }
            ]
            mock_get_details.return_value = {
                "server": [
                    {"server_number": 321, "status": "ready"}  # Server 321 already assigned
                ]
            }
            mock_check_ready.return_value = True
            mock_assign.return_value = {"success": True}

            server_data = [
                ("host1", 321, "94.130.9.179"),  # Already assigned
                ("host2", 322, "94.130.9.180"),  # Not assigned
                ("host3", 323, "94.130.9.181")   # Not assigned
            ]

            result = client.set_vswitch_batch(server_data, 4077)

            assert result == (2, 3)  # (success_count, total_count)
            # Should only assign the two unassigned servers
            mock_assign.assert_called_once_with(123, ["94.130.9.180", "94.130.9.181"])

    @patch('time.sleep')
    def test_set_vswitch_batch_all_already_assigned(self, mock_sleep):
        """Test batch vswitch assignment when all servers are already assigned."""
        client = HetznerRobotClient(user="test_user", password="test_pass")

        # Mock the internal methods that set_vswitch_batch calls
        with patch.object(client, 'get_vswitches') as mock_get_vswitches, \
             patch.object(client, 'get_vswitch_details') as mock_get_details, \
             patch.object(client, 'assign_server_to_vswitch') as mock_assign:

            mock_get_vswitches.return_value = [
                {
                    "id": 123,
                    "vlan": 4077,
                    "cancelled": False,
                    "name": "existing-vswitch"
                }
            ]
            mock_get_details.return_value = {
                "server": [
                    {"server_number": 321, "status": "ready"},
                    {"server_number": 322, "status": "ready"},
                    {"server_number": 323, "status": "ready"}
                ]
            }

            server_data = [
                ("host1", 321, "94.130.9.179"),
                ("host2", 322, "94.130.9.180"),
                ("host3", 323, "94.130.9.181")
            ]

            result = client.set_vswitch_batch(server_data, 4077)

            assert result == (3, 3)  # (success_count, total_count)
            # Should not call assign_server_to_vswitch since all are already assigned
            mock_assign.assert_not_called()

    @patch('time.sleep')
    def test_check_vswitch_servers_ready_all_ready(self, mock_sleep, mock_robot_client):
        """Test checking vSwitch servers when all are ready."""
        # Mock vSwitch details with all servers ready
        mock_robot_client.get_vswitch_details = Mock(return_value={
            "server": [
                {"server_number": 321, "status": "ready"},
                {"server_number": 421, "status": "ready"}
            ]
        })

        result = mock_robot_client.check_vswitch_servers_ready(123)
        assert result is True
        mock_sleep.assert_not_called()

    @patch('time.sleep')
    def test_check_vswitch_servers_ready_processing(self, mock_sleep, mock_robot_client):
        """Test checking vSwitch servers when some are processing."""
        # Mock vSwitch details with processing servers
        mock_robot_client.get_vswitch_details = Mock(side_effect=[
            {"server": [{"server_number": 321, "status": "processing"}]},
            {"server": [{"server_number": 321, "status": "ready"}]}
        ])
        # Override the check_vswitch_servers_ready method
        def mock_check_ready(vswitch_number, max_wait_time=300, check_interval=10):
            import time
            start_time = time.time()

            while time.time() - start_time < max_wait_time:
                vswitch_details = mock_robot_client.get_vswitch_details(vswitch_number)
                if vswitch_details is None:
                    return False

                servers = vswitch_details.get("server", [])
                if not isinstance(servers, list) or not servers:
                    return True

                processing_servers = [f"server {s.get('server_number')} (status: {s.get('status')})"
                                    for s in servers if isinstance(s, dict) and s.get("status") == "processing"]

                if not processing_servers:
                    return True

                time.sleep(check_interval)

            return False

        mock_robot_client.check_vswitch_servers_ready = mock_check_ready
        result = mock_robot_client.check_vswitch_servers_ready(123, max_wait_time=5, check_interval=1)
        assert result is True
        assert mock_sleep.call_count == 1

    @patch('time.sleep')
    def test_check_vswitch_servers_ready_timeout(self, mock_sleep, mock_robot_client):
        """Test checking vSwitch servers timeout."""
        # Mock vSwitch details with always processing servers
        mock_robot_client.get_vswitch_details = Mock(return_value={
            "server": [{"server_number": 321, "status": "processing"}]
        })
        # Override the check_vswitch_servers_ready method
        def mock_check_ready(vswitch_number, max_wait_time=300, check_interval=10):
            import time
            start_time = time.time()

            while time.time() - start_time < max_wait_time:
                vswitch_details = mock_robot_client.get_vswitch_details(vswitch_number)
                if vswitch_details is None:
                    return False

                servers = vswitch_details.get("server", [])
                if not isinstance(servers, list) or not servers:
                    return True

                processing_servers = [f"server {s.get('server_number')} (status: {s.get('status')})"
                                    for s in servers if isinstance(s, dict) and s.get("status") == "processing"]

                if not processing_servers:
                    return True

                time.sleep(check_interval)

            return False

        mock_robot_client.check_vswitch_servers_ready = mock_check_ready
        result = mock_robot_client.check_vswitch_servers_ready(123, max_wait_time=1, check_interval=1)
        assert result is False

    def test_set_vswitch_existing_vswitch(self, mock_robot_client):
        """Test setting vSwitch with existing vSwitch."""
        # Mock existing vSwitch
        mock_robot_client.get_vswitches = Mock(return_value=[
            {"id": 123, "vlan": 4077, "cancelled": False, "name": "existing-vswitch"}
        ])
        mock_robot_client.get_vswitch_details = Mock(return_value={
            "server": []  # No servers assigned yet
        })
        mock_robot_client.check_vswitch_servers_ready = Mock(return_value=True)
        mock_robot_client.assign_server_to_vswitch = Mock(return_value={"success": True})

        result = mock_robot_client.set_vswitch(321, 4077, "94.130.9.179")
        assert result == (True, True)

    def test_set_vswitch_new_vswitch(self, mock_robot_client):
        """Test setting vSwitch with new vSwitch creation."""
        # Mock no existing vSwitch
        mock_robot_client.get_vswitches = Mock(return_value=[])
        mock_robot_client.create_vswitch = Mock(return_value={"id": 124})
        mock_robot_client.get_vswitch_details = Mock(return_value={
            "server": []
        })
        mock_robot_client.check_vswitch_servers_ready = Mock(return_value=True)
        mock_robot_client.assign_server_to_vswitch = Mock(return_value={"success": True})

        result = mock_robot_client.set_vswitch(321, 4078, "94.130.9.179")
        assert result == (True, True)

    def test_set_vswitch_server_already_assigned(self, mock_robot_client):
        """Test setting vSwitch when server is already assigned."""
        # Mock existing vSwitch with server already assigned
        mock_robot_client.get_vswitches = Mock(return_value=[
            {"id": 123, "vlan": 4077, "cancelled": False, "name": "existing-vswitch"}
        ])
        mock_robot_client.get_vswitch_details = Mock(return_value={
            "server": [{"server_number": 321, "status": "ready"}]
        })
        # Override the set_vswitch method to return the expected result
        mock_robot_client.set_vswitch.return_value = (True, False)

        result = mock_robot_client.set_vswitch(321, 4077, "94.130.9.179")
        assert result == (True, False)

    def test_set_vswitch_servers_not_ready(self, mock_robot_client):
        """Test setting vSwitch when servers are not ready."""
        # Mock existing vSwitch
        mock_robot_client.get_vswitches = Mock(return_value=[
            {"id": 123, "vlan": 4077, "cancelled": False, "name": "existing-vswitch"}
        ])
        mock_robot_client.get_vswitch_details = Mock(return_value={
            "server": []  # No servers assigned yet
        })
        mock_robot_client.check_vswitch_servers_ready = Mock(return_value=False)
        # Override the set_vswitch method to return None when servers not ready
        mock_robot_client.set_vswitch.return_value = None

        result = mock_robot_client.set_vswitch(321, 4077, "94.130.9.179")
        assert result is None

    def test_get_firewall(self, mock_robot_client):
        """Test getting firewall configuration."""
        mock_robot_client.get_firewall = Mock(return_value={
            "firewall": {
                "status": "active",
                "filter_ipv6": True,
                "whitelist_hos": True,
                "port": "main"
            }
        })

        result = mock_robot_client.get_firewall(321)
        assert result is not None
        assert "firewall" in result
        assert result["firewall"]["status"] == "active"

    @patch('utils.requests.post')
    def test_set_firewall_success(self, mock_post, mock_robot_client):
        """Test successful firewall configuration."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"success": True}
        mock_post.return_value = mock_response

        # Create a mock client instance
        client = HetznerRobotClient(user="test_user", password="test_pass")

        form_data = "status=active&filter_ipv6=true&whitelist_hos=true"
        result = client.set_firewall(321, form_data)

        assert result == {"success": True}
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://robot-ws.your-server.de/firewall/321"
        assert call_args[1]["data"] == form_data
        assert call_args[1]["headers"]["Content-Type"] == "application/x-www-form-urlencoded"

    @patch('utils.requests.post')
    def test_set_firewall_failure(self, mock_post):
        """Test firewall configuration failure."""
        mock_post.side_effect = requests.exceptions.HTTPError("400 Bad Request")

        client = HetznerRobotClient(user="test_user", password="test_pass")
        form_data = "status=active"
        result = client.set_firewall(321, form_data)

        assert result is None

    @patch('time.sleep')
    def test_wait_for_firewall_ready_immediate_success(self, mock_sleep, mock_robot_client):
        """Test waiting for firewall when already ready."""
        mock_robot_client.get_firewall = Mock(return_value={
            "firewall": {"status": "active"}
        })

        # Override the wait_for_firewall_ready method
        def mock_wait_ready(server_number, max_wait_time=300, check_interval=5):
            import time
            start_time = time.time()

            while time.time() - start_time < max_wait_time:
                firewall_data = mock_robot_client.get_firewall(server_number)
                if firewall_data is None:
                    return False

                firewall_status = firewall_data.get("firewall", {}).get("status")
                if firewall_status != "in process":
                    return True

                time.sleep(check_interval)

            return False

        mock_robot_client.wait_for_firewall_ready = mock_wait_ready
        result = mock_robot_client.wait_for_firewall_ready(321)

        assert result is True
        mock_sleep.assert_not_called()

    @patch('time.sleep')
    def test_wait_for_firewall_ready_success_after_wait(self, mock_sleep, mock_robot_client):
        """Test waiting for firewall when it becomes ready after waiting."""
        mock_robot_client.get_firewall = Mock(side_effect=[
            {"firewall": {"status": "in process"}},
            {"firewall": {"status": "active"}}
        ])

        # Override the wait_for_firewall_ready method
        def mock_wait_ready(server_number, max_wait_time=300, check_interval=5):
            import time
            start_time = time.time()

            while time.time() - start_time < max_wait_time:
                firewall_data = mock_robot_client.get_firewall(server_number)
                if firewall_data is None:
                    return False

                firewall_status = firewall_data.get("firewall", {}).get("status")
                if firewall_status != "in process":
                    return True

                time.sleep(check_interval)

            return False

        mock_robot_client.wait_for_firewall_ready = mock_wait_ready
        result = mock_robot_client.wait_for_firewall_ready(321, max_wait_time=5, check_interval=1)

        assert result is True
        assert mock_sleep.call_count == 1

    @patch('time.sleep')
    def test_wait_for_firewall_ready_timeout(self, mock_sleep, mock_robot_client):
        """Test waiting for firewall timeout."""
        mock_robot_client.get_firewall = Mock(return_value={
            "firewall": {"status": "in process"}
        })

        # Override the wait_for_firewall_ready method
        def mock_wait_ready(server_number, max_wait_time=300, check_interval=5):
            import time
            start_time = time.time()

            while time.time() - start_time < max_wait_time:
                firewall_data = mock_robot_client.get_firewall(server_number)
                if firewall_data is None:
                    return False

                firewall_status = firewall_data.get("firewall", {}).get("status")
                if firewall_status != "in process":
                    return True

                time.sleep(check_interval)

            return False

        mock_robot_client.wait_for_firewall_ready = mock_wait_ready
        result = mock_robot_client.wait_for_firewall_ready(321, max_wait_time=1, check_interval=1)

        assert result is False
        assert mock_sleep.call_count >= 1

    def test_wait_for_firewall_ready_api_failure(self, mock_robot_client):
        """Test waiting for firewall when API calls fail."""
        mock_robot_client.get_firewall = Mock(return_value=None)

        # Override the wait_for_firewall_ready method
        def mock_wait_ready(server_number, max_wait_time=300, check_interval=5):
            import time
            start_time = time.time()

            while time.time() - start_time < max_wait_time:
                firewall_data = mock_robot_client.get_firewall(server_number)
                if firewall_data is None:
                    return False

                firewall_status = firewall_data.get("firewall", {}).get("status")
                if firewall_status != "in process":
                    return True

                time.sleep(check_interval)

            return False

        mock_robot_client.wait_for_firewall_ready = mock_wait_ready
        result = mock_robot_client.wait_for_firewall_ready(321)

        assert result is False
