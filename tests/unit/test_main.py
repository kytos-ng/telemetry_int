"""Test Main methods."""

from unittest.mock import AsyncMock, MagicMock, patch
from napps.kytos.telemetry_int.main import Main
from kytos.lib.helpers import get_controller_mock
from kytos.core.events import KytosEvent


class TestMain:
    """Tests for the Main class."""

    def setup_method(self):
        """Setup."""
        patch("kytos.core.helpers.run_on_thread", lambda x: x).start()
        # pylint: disable=import-outside-toplevel
        controller = get_controller_mock()
        self.napp = Main(controller)

    async def test_on_flow_mod_error(self, monkeypatch) -> None:
        """Test on_flow_mod_error."""
        api_mock, flow = AsyncMock(), MagicMock()
        flow.cookie = 1
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        api_mock.get_evc.return_value = {
            str(flow.cookie): {"metadata": {"telemetry": {"enabled": True}}}
        }
        self.napp.int_manager.remove_int_flows = AsyncMock()

        event = KytosEvent(content={"flow": flow, "error_command": "add"})
        await self.napp.on_flow_mod_error(event)

        assert api_mock.get_evc.call_count == 1
        assert api_mock.get_stored_flows.call_count == 1
        assert api_mock.add_evcs_metadata.call_count == 1
        assert self.napp.int_manager.remove_int_flows.call_count == 1
