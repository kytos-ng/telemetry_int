"""Test INTManager"""
import pytest

from unittest.mock import AsyncMock, MagicMock
from napps.kytos.telemetry_int.exceptions import ProxyPortSameSourceIntraEVC
from napps.kytos.telemetry_int.managers.int import INTManager


class TestINTManager:

    """TestINTManager."""

    async def test_disable_int_metadata(self, monkeypatch) -> None:
        """Test disable INT metadata args."""
        controller = MagicMock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        int_manager.remove_int_flows = AsyncMock()
        await int_manager.disable_int({}, False)

        assert api_mock.add_evcs_metadata.call_count == 1
        args = api_mock.add_evcs_metadata.call_args[0]
        assert args[0] == {}
        assert "telemetry" in args[1]
        telemetry_dict = args[1]["telemetry"]
        expected_keys = ["enabled", "status", "status_reason", "status_updated_at"]
        assert sorted(list(telemetry_dict.keys())) == sorted(expected_keys)

        assert not telemetry_dict["enabled"]
        assert telemetry_dict["status"] == "DOWN"
        assert telemetry_dict["status_reason"] == ["disabled"]

        assert args[2] is False

    async def test_enable_int_metadata(self, monkeypatch) -> None:
        """Test enable INT metadata args."""
        controller = MagicMock()
        api_mock = AsyncMock()
        stored_flows_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.utils.get_found_stored_flows", stored_flows_mock
        )

        int_manager = INTManager(controller)
        int_manager.remove_int_flows = AsyncMock()
        await int_manager.enable_int({}, False)

        assert stored_flows_mock.call_count == 1
        assert api_mock.add_evcs_metadata.call_count == 1
        args = api_mock.add_evcs_metadata.call_args[0]
        assert args[0] == {}
        assert "telemetry" in args[1]
        telemetry_dict = args[1]["telemetry"]
        expected_keys = ["enabled", "status", "status_reason", "status_updated_at"]
        assert sorted(list(telemetry_dict.keys())) == sorted(expected_keys)

        assert telemetry_dict["enabled"] is True
        assert telemetry_dict["status"] == "UP"
        assert telemetry_dict["status_reason"] == []

    def test_validate_intra_evc_different_proxy_ports(self) -> None:
        """Test _validate_intra_evc_different_proxy_ports."""
        pp_a, pp_z, controller = MagicMock(), MagicMock(), MagicMock()
        evc = {
            "id": "some_id",
            "uni_a": {"proxy_port": pp_a, "interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"proxy_port": pp_z, "interface_id": "00:00:00:00:00:00:00:01:2"},
        }

        int_manager = INTManager(controller)
        int_manager._validate_intra_evc_different_proxy_ports(evc)

        source = MagicMock()
        pp_a.source, pp_z.source = source, source
        with pytest.raises(ProxyPortSameSourceIntraEVC):
            int_manager._validate_intra_evc_different_proxy_ports(evc)
