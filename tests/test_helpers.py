"""Tests for utility helper functions."""

from unittest.mock import patch
import pytest

from utils import (
    _safe_file_replace,
    remove_ips_from_known_hosts,
    command_token,
    _get_server_number_for_host,
    _handle_command_error
)


class TestSafeFileReplace:
    """Test cases for _safe_file_replace function."""

    def test_safe_file_replace_success(self, temp_dir):
        """Test successful file replacement."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("original content")

        new_content = ["new line 1\n", "new line 2\n"]
        result = _safe_file_replace(test_file, new_content)

        assert result is True
        assert test_file.read_text() == "new line 1\nnew line 2\n"

    def test_safe_file_replace_file_not_found(self, temp_dir):
        """Test file replacement when file doesn't exist."""
        non_existent_file = temp_dir / "nonexistent.txt"

        result = _safe_file_replace(non_existent_file, ["content"])
        assert result is False

    def test_safe_file_replace_cleanup_on_error(self, temp_dir):
        """Test that temp file is cleaned up on error."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("original content")

        # Mock os.replace to raise an exception
        with patch('os.replace', side_effect=OSError("Permission denied")):
            result = _safe_file_replace(test_file, ["new content"])

        assert result is False
        # Verify temp file was cleaned up
        temp_files = list(temp_dir.glob("*.tmp"))
        assert len(temp_files) == 0

    def test_safe_file_replace_custom_backup_suffix(self, temp_dir):
        """Test file replacement with custom backup suffix."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("original content")

        new_content = ["new content\n"]
        result = _safe_file_replace(test_file, new_content, backup_suffix=".backup")

        assert result is True
        assert test_file.read_text() == "new content\n"
        # Verify backup file was created and cleaned up
        backup_file = temp_dir / "test.backup"
        assert not backup_file.exists()


class TestRemoveIpsFromKnownHosts:
    """Test cases for remove_ips_from_known_hosts function."""

    def test_remove_ips_success(self, mock_known_hosts_file):
        """Test successful IP removal from known_hosts."""
        ips_to_remove = ["94.130.9.179", "167.235.180.96"]

        removed_count = remove_ips_from_known_hosts(ips_to_remove, mock_known_hosts_file)

        assert removed_count == 2

        # Verify the IPs were removed
        with mock_known_hosts_file.open("r") as f:
            content = f.read()
            assert "94.130.9.179" not in content
            assert "167.235.180.96" not in content
            assert "other.host.com" in content  # Should remain

    def test_remove_ips_file_not_found(self, temp_dir):
        """Test IP removal when known_hosts file doesn't exist."""
        non_existent_file = temp_dir / "nonexistent_known_hosts"

        removed_count = remove_ips_from_known_hosts(["1.2.3.4"], non_existent_file)
        assert removed_count == 0

    def test_remove_ips_no_matches(self, mock_known_hosts_file):
        """Test IP removal when no IPs match."""
        ips_to_remove = ["192.168.1.1", "10.0.0.1"]

        removed_count = remove_ips_from_known_hosts(ips_to_remove, mock_known_hosts_file)
        assert removed_count == 0

    def test_remove_ips_partial_matches(self, mock_known_hosts_file):
        """Test IP removal with partial matches."""
        ips_to_remove = ["94.130.9.179", "192.168.1.1"]  # One exists, one doesn't

        removed_count = remove_ips_from_known_hosts(ips_to_remove, mock_known_hosts_file)
        assert removed_count == 1

    def test_remove_ips_empty_list(self, mock_known_hosts_file):
        """Test IP removal with empty IP list."""
        removed_count = remove_ips_from_known_hosts([], mock_known_hosts_file)
        assert removed_count == 0

    def test_remove_ips_preserves_other_entries(self, mock_known_hosts_file):
        """Test that IP removal preserves other entries."""
        ips_to_remove = ["94.130.9.179"]

        removed_count = remove_ips_from_known_hosts(ips_to_remove, mock_known_hosts_file)

        assert removed_count == 1

        # Verify other entries are preserved
        with mock_known_hosts_file.open("r") as f:
            content = f.read()
            assert "167.235.180.96" in content
            assert "other.host.com" in content

    def test_remove_ips_handles_write_error(self, mock_known_hosts_file):
        """Test IP removal when file write fails."""
        ips_to_remove = ["94.130.9.179"]

        # Mock _safe_file_replace to return False (simulating write failure)
        with patch('utils._safe_file_replace', return_value=False):
            removed_count = remove_ips_from_known_hosts(ips_to_remove, mock_known_hosts_file)

        assert removed_count == 1  # Still counts as removed from memory


class TestCommandToken:
    """Test cases for command_token function."""

    def test_command_token_generates_token(self):
        """Test that command_token generates a token."""
        with patch('sys.stdout') as mock_stdout:
            result = command_token(None)

        assert result == 0
        # Verify that print was called (token was generated)
        mock_stdout.write.assert_called()

    def test_command_token_length(self):
        """Test that generated token has correct length."""
        with patch('builtins.print') as mock_print:
            command_token(None)

        # Get the token that was printed
        call_args = mock_print.call_args[0]
        token = call_args[0]

        assert len(token) == 100
        assert token.isalnum()  # Should only contain alphanumeric characters


class TestGetServerNumberForHost:
    """Test cases for _get_server_number_for_host function."""

    def test_get_server_number_success(self, mock_robot_client, inventory_file):
        """Test successful server number retrieval."""
        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            server_number = _get_server_number_for_host(mock_robot_client, "shadrach")

        assert server_number == 321

    def test_get_server_number_host_not_found(self, mock_robot_client, inventory_file):
        """Test server number retrieval when host not found in inventory."""
        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            with patch('sys.stderr') as mock_stderr:
                server_number = _get_server_number_for_host(mock_robot_client, "nonexistent")

        assert server_number is None
        mock_stderr.write.assert_called()

    def test_get_server_number_inventory_not_found(self, mock_robot_client, temp_dir):
        """Test server number retrieval when inventory file not found."""
        with patch('utils.Path.cwd', return_value=temp_dir):
            with patch('sys.stderr') as mock_stderr:
                server_number = _get_server_number_for_host(mock_robot_client, "shadrach")

        assert server_number is None
        mock_stderr.write.assert_called()

    def test_get_server_number_api_failure(self, inventory_file):
        """Test server number retrieval when API fails."""
        # Create a client that will fail to find the server
        from unittest.mock import Mock
        mock_client = Mock()
        mock_client.find_server_number_by_ip.return_value = None

        with patch('utils.Path.cwd', return_value=inventory_file.parent):
            server_number = _get_server_number_for_host(mock_client, "shadrach")

        assert server_number is None
        # The function should have called the client's find_server_number_by_ip method
        mock_client.find_server_number_by_ip.assert_called_once_with("94.130.9.179")


class TestHandleCommandError:
    """Test cases for _handle_command_error function."""

    def test_handle_command_error_success(self):
        """Test successful command execution."""
        def test_func():
            return "success"

        result = _handle_command_error(test_func)
        assert result == "success"

    def test_handle_command_error_file_not_found(self):
        """Test command error handling for FileNotFoundError."""
        def test_func():
            raise FileNotFoundError("File not found")

        with patch('sys.stderr') as mock_stderr:
            result = _handle_command_error(test_func)

        assert result == 1
        mock_stderr.write.assert_called()

    def test_handle_command_error_key_error(self):
        """Test command error handling for KeyError."""
        def test_func():
            raise KeyError("Key not found")

        with patch('sys.stderr') as mock_stderr:
            result = _handle_command_error(test_func)

        assert result == 1
        mock_stderr.write.assert_called()

    def test_handle_command_error_value_error(self):
        """Test command error handling for ValueError."""
        def test_func():
            raise ValueError("Invalid value")

        with patch('sys.stderr') as mock_stderr:
            result = _handle_command_error(test_func)

        assert result == 1
        mock_stderr.write.assert_called()

    def test_handle_command_error_other_exception(self):
        """Test command error handling for other exceptions."""
        def test_func():
            raise RuntimeError("Unexpected error")

        # Should not catch other exceptions
        with pytest.raises(RuntimeError):
            _handle_command_error(test_func)

    def test_handle_command_error_with_args(self):
        """Test command error handling with function arguments."""
        def test_func(arg1, arg2, kwarg1=None):
            return f"{arg1}-{arg2}-{kwarg1}"

        result = _handle_command_error(test_func, "a", "b", kwarg1="c")
        assert result == "a-b-c"

    def test_handle_command_error_with_kwargs(self):
        """Test command error handling with keyword arguments."""
        def test_func(**kwargs):
            return kwargs

        result = _handle_command_error(test_func, key1="value1", key2="value2")
        assert result == {"key1": "value1", "key2": "value2"}
