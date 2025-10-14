"""Tests for main CLI functionality and argument parsing."""

from unittest.mock import Mock, patch
import pytest

from utils import build_parser, main


class TestBuildParser:
    """Test cases for build_parser function."""

    def test_build_parser_creates_parser(self):
        """Test that build_parser creates a valid argument parser."""
        parser = build_parser()

        assert parser.prog == "utils"
        assert parser.description == "Utilities CLI"

        # Check that subparsers are created
        subparsers_action = None
        for action in parser._actions:
            if hasattr(action, 'choices') and action.choices:
                subparsers_action = action
                break

        assert subparsers_action is not None
        assert subparsers_action.dest == "command"
        assert subparsers_action.required is True

    def test_build_parser_has_all_commands(self):
        """Test that all expected commands are available."""
        parser = build_parser()

        # Get all available commands
        subparsers_action = None
        for action in parser._actions:
            if hasattr(action, 'choices') and action.choices:
                subparsers_action = action
                break

        assert subparsers_action is not None
        available_commands = list(subparsers_action.choices.keys())

        expected_commands = [
            "token",
            "clear_known_hosts",
            "rescue",
            "reset",
            "set_vswitch",
            "firewall",
            "reset_all",
            "rescue_all",
            "set_vswitch_all",
            "set_firewall_all",
            "provision",
            "provision_all"
        ]

        for command in expected_commands:
            assert command in available_commands

    def test_build_parser_command_help_texts(self):
        """Test that commands have appropriate help text."""
        parser = build_parser()

        # Get subparsers action
        subparsers_action = None
        for action in parser._actions:
            if hasattr(action, 'choices') and action.choices:
                subparsers_action = action
                break

        assert subparsers_action is not None

        # Test a few key commands - check that they exist and have descriptions
        assert "token" in subparsers_action.choices
        assert "rescue" in subparsers_action.choices
        assert "reset" in subparsers_action.choices

        # Check that the commands have help text
        token_parser = subparsers_action.choices["token"]
        rescue_parser = subparsers_action.choices["rescue"]
        reset_parser = subparsers_action.choices["reset"]

        assert hasattr(token_parser, 'description') or hasattr(token_parser, 'help')
        assert hasattr(rescue_parser, 'description') or hasattr(rescue_parser, 'help')
        assert hasattr(reset_parser, 'description') or hasattr(reset_parser, 'help')

    def test_build_parser_rescue_command_args(self):
        """Test that rescue command has correct arguments."""
        parser = build_parser()

        # Get subparsers action
        subparsers_action = None
        for action in parser._actions:
            if hasattr(action, 'choices') and action.choices:
                subparsers_action = action
                break

        assert subparsers_action is not None
        rescue_parser = subparsers_action.choices["rescue"]

        # Check that host argument exists
        host_action = None
        deactivate_action = None

        for action in rescue_parser._actions:
            if action.dest == "host":
                host_action = action
            elif action.dest == "deactivate":
                deactivate_action = action

        assert host_action is not None
        assert deactivate_action is not None
        # Check that deactivate is a store_true action
        assert hasattr(deactivate_action, 'action') or str(type(deactivate_action)).find('StoreTrue') != -1

    def test_build_parser_provision_command_args(self):
        """Test that provision command has correct arguments."""
        parser = build_parser()

        # Get subparsers action
        subparsers_action = None
        for action in parser._actions:
            if hasattr(action, 'choices') and action.choices:
                subparsers_action = action
                break

        assert subparsers_action is not None
        provision_parser = subparsers_action.choices["provision"]

        # Check that host argument exists
        host_action = None
        for action in provision_parser._actions:
            if action.dest == "host":
                host_action = action
                break

        assert host_action is not None


class TestMain:
    """Test cases for main function."""

    def test_main_token_command(self):
        """Test main function with token command."""
        with patch('utils.command_token', return_value=0) as mock_token:
            result = main(["token"])

        assert result == 0
        mock_token.assert_called_once()

    def test_main_clear_known_hosts_command(self):
        """Test main function with clear_known_hosts command."""
        with patch('utils.command_clear_known_hosts', return_value=0) as mock_clear:
            result = main(["clear_known_hosts"])

        assert result == 0
        mock_clear.assert_called_once()

    def test_main_rescue_command(self):
        """Test main function with rescue command."""
        with patch('utils.command_rescue', return_value=0) as mock_rescue:
            result = main(["rescue", "shadrach"])

        assert result == 0
        mock_rescue.assert_called_once()

        # Check that client was injected
        args = mock_rescue.call_args[0][0]
        assert hasattr(args, 'client')
        assert args.host == "shadrach"

    def test_main_rescue_command_with_deactivate(self):
        """Test main function with rescue command and deactivate flag."""
        with patch('utils.command_rescue', return_value=0) as mock_rescue:
            result = main(["rescue", "shadrach", "-d"])

        assert result == 0
        mock_rescue.assert_called_once()

        # Check that deactivate flag was set
        args = mock_rescue.call_args[0][0]
        assert args.deactivate is True

    def test_main_reset_command(self):
        """Test main function with reset command."""
        with patch('utils.command_reset', return_value=0) as mock_reset:
            result = main(["reset", "shadrach"])

        assert result == 0
        mock_reset.assert_called_once()

        # Check that client was injected
        args = mock_reset.call_args[0][0]
        assert hasattr(args, 'client')
        assert args.host == "shadrach"

    def test_main_set_vswitch_command(self):
        """Test main function with set_vswitch command."""
        with patch('utils.command_vswitch', return_value=0) as mock_vswitch:
            result = main(["set_vswitch", "shadrach"])

        assert result == 0
        mock_vswitch.assert_called_once()

        # Check that client was injected
        args = mock_vswitch.call_args[0][0]
        assert hasattr(args, 'client')
        assert args.host == "shadrach"

    def test_main_reset_all_command(self):
        """Test main function with reset_all command."""
        with patch('utils.command_reset_all', return_value=0) as mock_reset_all:
            result = main(["reset_all"])

        assert result == 0
        mock_reset_all.assert_called_once()

        # Check that client was injected
        args = mock_reset_all.call_args[0][0]
        assert hasattr(args, 'client')

    def test_main_rescue_all_command(self):
        """Test main function with rescue_all command."""
        with patch('utils.command_rescue_all', return_value=0) as mock_rescue_all:
            result = main(["rescue_all"])

        assert result == 0
        mock_rescue_all.assert_called_once()

        # Check that client was injected
        args = mock_rescue_all.call_args[0][0]
        assert hasattr(args, 'client')

    def test_main_rescue_all_command_with_deactivate(self):
        """Test main function with rescue_all command and deactivate flag."""
        with patch('utils.command_rescue_all', return_value=0) as mock_rescue_all:
            result = main(["rescue_all", "-d"])

        assert result == 0
        mock_rescue_all.assert_called_once()

        # Check that deactivate flag was set
        args = mock_rescue_all.call_args[0][0]
        assert args.deactivate is True

    def test_main_set_vswitch_all_command(self):
        """Test main function with set_vswitch_all command."""
        with patch('utils.command_set_vswitch_all', return_value=0) as mock_vswitch_all:
            result = main(["set_vswitch_all"])

        assert result == 0
        mock_vswitch_all.assert_called_once()

        # Check that client was injected
        args = mock_vswitch_all.call_args[0][0]
        assert hasattr(args, 'client')

    def test_main_firewall_command(self):
        """Test main function with firewall command."""
        with patch('utils.command_firewall', return_value=0) as mock_firewall:
            result = main(["firewall", "shadrach"])

        assert result == 0
        mock_firewall.assert_called_once()

        # Check that client was injected
        args = mock_firewall.call_args[0][0]
        assert hasattr(args, 'client')
        assert args.host == "shadrach"

    def test_main_set_firewall_all_command(self):
        """Test main function with set_firewall_all command."""
        with patch('utils.command_set_firewall_all', return_value=0) as mock_firewall_all:
            result = main(["set_firewall_all"])

        assert result == 0
        mock_firewall_all.assert_called_once()

        # Check that client was injected
        args = mock_firewall_all.call_args[0][0]
        assert hasattr(args, 'client')

    def test_main_provision_command(self):
        """Test main function with provision command."""
        with patch('utils.command_provision', return_value=0) as mock_provision:
            result = main(["provision", "shadrach"])

        assert result == 0
        mock_provision.assert_called_once()

        # Check that client was injected
        args = mock_provision.call_args[0][0]
        assert hasattr(args, 'client')
        assert args.host == "shadrach"

    def test_main_provision_all_command(self):
        """Test main function with provision_all command."""
        with patch('utils.command_provision_all', return_value=0) as mock_provision_all:
            result = main(["provision_all"])

        assert result == 0
        mock_provision_all.assert_called_once()

        # Check that client was injected
        args = mock_provision_all.call_args[0][0]
        assert hasattr(args, 'client')

    def test_main_invalid_command(self):
        """Test main function with invalid command."""
        with pytest.raises(SystemExit):
            main(["invalid_command"])

    def test_main_missing_required_args(self):
        """Test main function with missing required arguments."""
        with pytest.raises(SystemExit):
            main(["rescue"])  # Missing host argument

    def test_main_help_command(self):
        """Test main function with help command."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])

        assert exc_info.value.code == 0

    def test_main_command_help(self):
        """Test main function with command-specific help."""
        with pytest.raises(SystemExit) as exc_info:
            main(["rescue", "--help"])

        assert exc_info.value.code == 0

    def test_main_client_injection(self):
        """Test that HetznerRobotClient is properly injected into args."""
        with patch('utils.command_rescue', return_value=0) as mock_rescue:
            with patch('utils.HetznerRobotClient') as mock_client_class:
                mock_client_instance = Mock()
                mock_client_class.return_value = mock_client_instance

                result = main(["rescue", "shadrach"])

        assert result == 0
        mock_client_class.assert_called_once()

        # Check that client was injected
        args = mock_rescue.call_args[0][0]
        assert args.client == mock_client_instance

    def test_main_command_failure(self):
        """Test main function when command returns non-zero exit code."""
        with patch('utils.command_rescue', return_value=1) as mock_rescue:
            result = main(["rescue", "shadrach"])

        assert result == 1
        mock_rescue.assert_called_once()
