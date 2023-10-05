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
        api_mock, flow1, flow2 = AsyncMock(), MagicMock(), MagicMock()
        flow1.cookie = 0xA800000000000001
        flow2.cookie = 0xA800000000000002
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )

        evc1_id = utils.get_id_from_cookie(flow1.cookie)
        evc2_id = utils.get_id_from_cookie(flow2.cookie)
        api_mock.get_evcs.return_value = {
            evc1_id: {"metadata": {"telemetry": {"enabled": False}}},
            evc2_id: {"metadata": {"telemetry": {"enabled": True}}}
        }

        endpoint = f"{self.base_endpoint}/evc"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert evc1_id not in data
        assert evc2_id in data

    async def test_on_flow_mod_error(self, monkeypatch) -> None:
        """Test on_flow_mod_error."""
        api_mock, flow = AsyncMock(), MagicMock()
        flow.cookie = 0xA800000000000001
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        api_mock.get_evc.return_value = {
            utils.get_id_from_cookie(flow.cookie): {
                "metadata": {"telemetry": {"enabled": True}}
            }
        }
        self.napp.int_manager.remove_int_flows = AsyncMock()

        event = KytosEvent(content={"flow": flow, "error_command": "add"})
        await self.napp.on_flow_mod_error(event)

        assert api_mock.get_evc.call_count == 1
        assert api_mock.get_stored_flows.call_count == 1
        assert api_mock.add_evcs_metadata.call_count == 1
        assert self.napp.int_manager.remove_int_flows.call_count == 1
