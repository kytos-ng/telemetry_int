"""Test Main methods."""
import pytest

from unittest.mock import AsyncMock, MagicMock, patch
from napps.kytos.telemetry_int.main import Main
from napps.kytos.telemetry_int import utils
from kytos.lib.helpers import get_controller_mock, get_test_client
from kytos.core.events import KytosEvent


class TestMain:
    """Tests for the Main class."""

    def setup_method(self):
        """Setup."""
        patch("kytos.core.helpers.run_on_thread", lambda x: x).start()
        # pylint: disable=import-outside-toplevel
        controller = get_controller_mock()
        self.napp = Main(controller)
        self.api_client = get_test_client(controller, self.napp)
        self.base_endpoint = "kytos/telemetry_int/v1"

    async def test_enable_telemetry(self, monkeypatch) -> None:
        """Test enable telemetry."""
        api_mock, flow = AsyncMock(), MagicMock()
        flow.cookie = 0xA800000000000001
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )

        evc_id = utils.get_id_from_cookie(flow.cookie)
        api_mock.get_evcs.return_value = {
            evc_id: {"metadata": {"telemetry": {"enabled": False}}}
        }

        self.napp.int_manager = AsyncMock()

        endpoint = f"{self.base_endpoint}/evc/enable"
        response = await self.api_client.post(endpoint, json={"evc_ids": [evc_id]})
        assert self.napp.int_manager.enable_int.call_count == 1
        assert response.status_code == 201
        assert response.json() == [evc_id]

    @pytest.mark.parametrize("route", ["/evc/enable", "/evc/disable"])
    async def test_en_dis_openapi_validation(self, route: str) -> None:
        """Test OpenAPI enable/disable basic validation."""
        endpoint = f"{self.base_endpoint}{route}"
        # wrong evc_ids payload data type
        response = await self.api_client.post(endpoint, json={"evc_ids": 1})
        assert response.status_code == 400
        assert "evc_ids" in response.json()["description"]

    async def test_disable_telemetry(self, monkeypatch) -> None:
        """Test disable telemetry."""
        api_mock, flow = AsyncMock(), MagicMock()
        flow.cookie = 0xA800000000000001
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )

        evc_id = utils.get_id_from_cookie(flow.cookie)
        api_mock.get_evcs.return_value = {
            evc_id: {"metadata": {"telemetry": {"enabled": True}}}
        }

        self.napp.int_manager = AsyncMock()

        endpoint = f"{self.base_endpoint}/evc/disable"
        response = await self.api_client.post(endpoint, json={"evc_ids": [evc_id]})
        assert self.napp.int_manager.disable_int.call_count == 1
        assert response.status_code == 200
        assert response.json() == [evc_id]

    async def test_get_enabled_evcs(self, monkeypatch) -> None:
        """Test get enabled evcs."""
        api_mock, flow = AsyncMock(), MagicMock()
        flow.cookie = 0xA800000000000001
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )

        evc_id = utils.get_id_from_cookie(flow.cookie)
        api_mock.get_evcs.return_value = {
            evc_id: {"metadata": {"telemetry": {"enabled": True}}},
        }

        endpoint = f"{self.base_endpoint}/evc"
        response = await self.api_client.get(endpoint)
        assert api_mock.get_evcs.call_args[1] == {"metadata.telemetry.enabled": "true"}
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert evc_id in data

    async def test_on_table_enabled(self) -> None:
        """Test on_table_enabled."""
        assert self.napp.int_manager.flow_builder.table_group == {"evpl": 2, "epl": 3}
        await self.napp.on_table_enabled(
            KytosEvent(content={"telemetry_int": {"evpl": 22, "epl": 33}})
        )
        assert self.napp.int_manager.flow_builder.table_group == {"evpl": 22, "epl": 33}
        assert self.napp.controller.buffers.app.aput.call_count == 1

    async def test_on_table_enabled_error(self, monkeypatch) -> None:
        """Test on_table_enabled error case."""
        assert self.napp.int_manager.flow_builder.table_group == {"evpl": 2, "epl": 3}
        log_mock = MagicMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.log", log_mock)
        await self.napp.on_table_enabled(
            KytosEvent(content={"telemetry_int": {"invalid": 1}})
        )
        assert self.napp.int_manager.flow_builder.table_group == {"evpl": 2, "epl": 3}
        assert log_mock.error.call_count == 1
        assert not self.napp.controller.buffers.app.aput.call_count

    async def test_on_flow_mod_error(self, monkeypatch) -> None:
        """Test on_flow_mod_error."""
        api_mock_main, api_mock_int, flow = AsyncMock(), AsyncMock(), MagicMock()
        flow.cookie = 0xA800000000000001
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock_main,
        )
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.managers.int.api",
            api_mock_int,
        )
        cookie = utils.get_id_from_cookie(flow.cookie)
        api_mock_main.get_evc.return_value = {
            cookie: {"metadata": {"telemetry": {"enabled": True}}}
        }
        api_mock_int.get_stored_flows.return_value = {cookie: [MagicMock()]}
        self.napp.int_manager._remove_int_flows = AsyncMock()

        event = KytosEvent(content={"flow": flow, "error_command": "add"})
        await self.napp.on_flow_mod_error(event)

        assert api_mock_main.get_evc.call_count == 1
        assert api_mock_int.get_stored_flows.call_count == 1
        assert api_mock_int.add_evcs_metadata.call_count == 1
        assert self.napp.int_manager._remove_int_flows.call_count == 1
