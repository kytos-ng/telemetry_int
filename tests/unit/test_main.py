# pylint: disable=too-many-lines
"""Test Main methods."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from napps.kytos.telemetry_int import utils
from napps.kytos.telemetry_int.exceptions import (
    EVCError,
    EVCNotFound,
    FlowsNotFound,
    ProxyPortShared,
)
from napps.kytos.telemetry_int.kytos_api_helper import UnrecoverableError
from napps.kytos.telemetry_int.main import Main
from tenacity import Future, RetryError

from kytos.core.common import EntityStatus
from kytos.core.events import KytosEvent
from kytos.lib.helpers import get_controller_mock, get_test_client


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

        enable_int_args = self.napp.int_manager.enable_int.call_args
        # evcs arg
        assert evc_id in enable_int_args[0][0]
        # assert the other args
        assert enable_int_args[1] == {
            "force": False,
            "proxy_port_enabled": None,
            "set_proxy_port_metadata": True,
        }

        assert response.status_code == 201
        assert response.json() == [evc_id]

    async def test_enable_telemetry_wrong_types(self, monkeypatch) -> None:
        """Test enable telemetry wrong types."""
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

        endpoint = f"{self.base_endpoint}/evc/enable"
        response = await self.api_client.post(
            endpoint, json={"evc_ids": [evc_id], "proxy_port_enabled": 1}
        )
        assert response.status_code == 400
        assert (
            "1 is not of type 'boolean' for field proxy_port_enabled"
            in response.json()["description"]
        )

        endpoint = f"{self.base_endpoint}/evc/enable"
        response = await self.api_client.post(
            endpoint, json={"evc_ids": [evc_id], "force": 2}
        )
        assert response.status_code == 400
        assert (
            "2 is not of type 'boolean' for field force"
            in response.json()["description"]
        )

    async def test_redeploy_telemetry_enabled(self, monkeypatch) -> None:
        """Test redeploy telemetry enabled."""
        api_mock, flow = AsyncMock(), MagicMock()
        flow.cookie = 0xA800000000000001
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )

        evc_id = utils.get_id_from_cookie(flow.cookie)
        api_mock.get_evc.return_value = {
            evc_id: {"metadata": {"telemetry": {"enabled": True}}}
        }

        self.napp.int_manager = AsyncMock()

        endpoint = f"{self.base_endpoint}/evc/redeploy"
        response = await self.api_client.patch(endpoint, json={"evc_ids": [evc_id]})
        assert self.napp.int_manager.redeploy_int.call_count == 1
        assert response.status_code == 201
        assert response.json() == [evc_id]

    async def test_redeploy_telemetry_not_enabled(self, monkeypatch) -> None:
        """Test redeploy telemetry not enabled."""
        api_mock, flow, api_mngr_mock = AsyncMock(), MagicMock(), AsyncMock()
        flow.cookie = 0xA800000000000001
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.managers.int.api",
            api_mngr_mock,
        )

        evc_id = utils.get_id_from_cookie(flow.cookie)
        api_mock.get_evc.return_value = {
            evc_id: {"metadata": {"telemetry": {"enabled": False}}}
        }

        self.napp.int_manager._validate_map_enable_evcs = MagicMock()
        self.napp.int_manager._remove_int_flows_by_cookies = AsyncMock()
        self.napp.int_manager.install_int_flows = AsyncMock()
        endpoint = f"{self.base_endpoint}/evc/redeploy"
        response = await self.api_client.patch(endpoint, json={"evc_ids": [evc_id]})
        assert response.status_code == 409
        assert "isn't enabled" in response.json()["description"]

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

    async def test_get_evc_compare(self, monkeypatch) -> None:
        """Test get evc compre ok case."""
        api_mock, flow = AsyncMock(), MagicMock()
        flow.cookie = 0xA800000000000001
        evc_id = "1"
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )

        evc_id = utils.get_id_from_cookie(flow.cookie)
        api_mock.get_evcs.return_value = {
            evc_id: {
                "id": evc_id,
                "name": "evc",
                "metadata": {"telemetry": {"enabled": True}},
            },
        }
        api_mock.get_stored_flows.side_effect = [
            {flow.cookie: [{"id": "some_1", "match": {"in_port": 1}}]},
            {flow.cookie: [{"id": "some_2", "match": {"in_port": 1}}]},
        ]

        endpoint = f"{self.base_endpoint}/evc/compare"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 0

    async def test_get_evc_compare_wrong_metadata(self, monkeypatch) -> None:
        """Test get evc compre wrong_metadata_has_int_flows case."""
        api_mock, flow = AsyncMock(), MagicMock()
        flow.cookie = 0xA800000000000001
        evc_id = "1"
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )

        evc_id = utils.get_id_from_cookie(flow.cookie)
        api_mock.get_evcs.return_value = {
            evc_id: {"id": evc_id, "name": "evc", "metadata": {}},
        }
        api_mock.get_stored_flows.side_effect = [
            {flow.cookie: [{"id": "some_1", "match": {"in_port": 1}}]},
            {flow.cookie: [{"id": "some_2", "match": {"in_port": 1}}]},
        ]

        endpoint = f"{self.base_endpoint}/evc/compare"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == evc_id
        assert data[0]["compare_reason"] == ["wrong_metadata_has_int_flows"]
        assert data[0]["name"] == "evc"

    async def test_get_evc_compare_missing_some_int_flows(self, monkeypatch) -> None:
        """Test get evc compre missing_some_int_flows case."""
        api_mock, flow = AsyncMock(), MagicMock()
        flow.cookie = 0xA800000000000001
        evc_id = "1"
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )

        evc_id = utils.get_id_from_cookie(flow.cookie)
        api_mock.get_evcs.return_value = {
            evc_id: {
                "id": evc_id,
                "name": "evc",
                "metadata": {"telemetry": {"enabled": True}},
            },
        }
        api_mock.get_stored_flows.side_effect = [
            {flow.cookie: [{"id": "some_1", "match": {"in_port": 1}}]},
            {
                flow.cookie: [
                    {"id": "some_2", "match": {"in_port": 1}},
                    {"id": "some_3", "match": {"in_port": 1}},
                ]
            },
        ]

        endpoint = f"{self.base_endpoint}/evc/compare"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == evc_id
        assert data[0]["compare_reason"] == ["missing_some_int_flows"]
        assert data[0]["name"] == "evc"

    async def test_delete_proxy_port_metadata(self, monkeypatch) -> None:
        """Test delete proxy_port metadata."""
        api_mock = AsyncMock()
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        intf_id, port_number = "00:00:00:00:00:00:00:01:1", 7
        endpoint = f"{self.base_endpoint}/uni/{intf_id}/proxy_port"
        self.napp.controller.get_interface_by_id = MagicMock()
        pp = MagicMock()
        pp.evc_ids = set()
        self.napp.int_manager.get_proxy_port_or_raise = MagicMock()
        self.napp.int_manager.get_proxy_port_or_raise.return_value = pp
        intf_mock = MagicMock()
        intf_mock.metadata = {"proxy_port": port_number}
        self.napp.controller.get_interface_by_id = MagicMock()
        self.napp.controller.get_interface_by_id.return_value = intf_mock
        response = await self.api_client.delete(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert data == "Operation successful"
        assert api_mock.delete_proxy_port_metadata.call_count == 1

    async def test_delete_proxy_port_metadata_force(self, monkeypatch) -> None:
        """Test delete proxy_port metadata force."""
        api_mock = AsyncMock()
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        intf_id, port_number = "00:00:00:00:00:00:00:01:1", 7
        src_id = "00:00:00:00:00:00:00:01:7"
        endpoint = f"{self.base_endpoint}/uni/{intf_id}/proxy_port"
        self.napp.controller.get_interface_by_id = MagicMock()
        pp = MagicMock()
        pp.evc_ids = set(["some_id"])
        self.napp.int_manager.unis_src[intf_id] = src_id
        self.napp.int_manager.srcs_pp[src_id] = pp
        intf_mock = MagicMock()
        intf_mock.metadata = {"proxy_port": port_number}
        self.napp.controller.get_interface_by_id = MagicMock()
        self.napp.controller.get_interface_by_id.return_value = intf_mock
        response = await self.api_client.delete(endpoint)
        assert response.status_code == 409
        data = response.json()["description"]
        assert "is in use on 1" in data
        assert not api_mock.delete_proxy_port_metadata.call_count

        endpoint = f"{self.base_endpoint}/uni/{intf_id}/proxy_port?force=true"
        response = await self.api_client.delete(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert "Operation successful" in data
        assert api_mock.delete_proxy_port_metadata.call_count == 1

    async def test_delete_proxy_port_metadata_early_ret(self, monkeypatch) -> None:
        """Test delete proxy_port metadata early ret."""
        api_mock = AsyncMock()
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        intf_id = "00:00:00:00:00:00:00:01:1"
        endpoint = f"{self.base_endpoint}/uni/{intf_id}/proxy_port"
        self.napp.controller.get_interface_by_id = MagicMock()
        pp = MagicMock()
        pp.evc_ids = set(["some_id"])
        self.napp.int_manager.get_proxy_port_or_raise = MagicMock()
        self.napp.int_manager.get_proxy_port_or_raise.return_value = pp
        intf_mock = MagicMock()
        intf_mock.metadata = {}
        self.napp.controller.get_interface_by_id = MagicMock()
        self.napp.controller.get_interface_by_id.return_value = intf_mock
        response = await self.api_client.delete(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert "Operation successful" in data
        assert not api_mock.delete_proxy_port_metadata.call_count

    async def test_add_proxy_port_metadata(self, monkeypatch) -> None:
        """Test add proxy_port metadata."""
        api_mock = AsyncMock()
        api_mock.get_evcs.return_value = {}
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        intf_id, port_number = "00:00:00:00:00:00:00:01:1", 7
        endpoint = f"{self.base_endpoint}/uni/{intf_id}/proxy_port/{port_number}"
        self.napp.controller.get_interface_by_id = MagicMock()
        pp = MagicMock()
        pp.status = EntityStatus.UP
        self.napp.int_manager.get_proxy_port_or_raise = MagicMock()
        self.napp.int_manager.get_proxy_port_or_raise.return_value = pp
        response = await self.api_client.post(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert data == "Operation successful"
        assert api_mock.add_proxy_port_metadata.call_count == 1

    async def test_add_proxy_port_metadata_early_ret(self, monkeypatch) -> None:
        """Test add proxy_port metadata early ret."""
        api_mock = AsyncMock()
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        intf_id, port_number = "00:00:00:00:00:00:00:01:1", 7
        endpoint = f"{self.base_endpoint}/uni/{intf_id}/proxy_port/{port_number}"
        intf_mock = MagicMock()
        intf_mock.metadata = {"proxy_port": port_number}
        self.napp.controller.get_interface_by_id = MagicMock()
        self.napp.controller.get_interface_by_id.return_value = intf_mock
        response = await self.api_client.post(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert data == "Operation successful"
        assert not api_mock.add_proxy_port_metadata.call_count

    async def test_add_proxy_port_metadata_conflict(self, monkeypatch) -> None:
        """Test add proxy_port metadata conflict."""
        api_mock = AsyncMock()
        api_mock.get_evcs.return_value = {}
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        intf_id, port_number = "00:00:00:00:00:00:00:01:1", 7
        endpoint = f"{self.base_endpoint}/uni/{intf_id}/proxy_port/{port_number}"
        self.napp.controller.get_interface_by_id = MagicMock()
        pp = MagicMock()
        pp.status = EntityStatus.UP
        self.napp.int_manager.get_proxy_port_or_raise = MagicMock()
        self.napp.int_manager.get_proxy_port_or_raise.side_effect = ProxyPortShared(
            "no_evc_id", "boom"
        )
        response = await self.api_client.post(endpoint)
        assert response.status_code == 409

    async def test_add_proxy_port_metadata_force(self, monkeypatch) -> None:
        """Test add proxy_port metadata force."""
        api_mock = AsyncMock()
        api_mock.get_evcs.return_value = {}
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        intf_id, port_number = "00:00:00:00:00:00:00:01:1", 7
        force = "true"
        endpoint = (
            f"{self.base_endpoint}/uni/{intf_id}/proxy_port/{port_number}?force={force}"
        )
        self.napp.controller.get_interface_by_id = MagicMock()
        pp = MagicMock()
        # despite proxy port down, with force true the request shoudl succeed
        pp.status = EntityStatus.DOWN
        self.napp.int_manager.get_proxy_port_or_raise = MagicMock()
        self.napp.int_manager.get_proxy_port_or_raise.return_value = pp
        response = await self.api_client.post(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert data == "Operation successful"
        assert api_mock.add_proxy_port_metadata.call_count == 1

        force = "false"
        endpoint = (
            f"{self.base_endpoint}/uni/{intf_id}/proxy_port/{port_number}?force={force}"
        )
        response = await self.api_client.post(endpoint)
        assert response.status_code == 409
        assert "isn't UP" in response.json()["description"]

    async def test_list_proxy_port(self) -> None:
        """Test list proxy port."""
        endpoint = f"{self.base_endpoint}/uni/proxy_port"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        data = response.json()
        assert not data

        sw1, intf_mock = MagicMock(), MagicMock()
        intf_mock.metadata = {"proxy_port": 1}
        intf_mock.status.value = "UP"
        intf_mock.id = "1"
        sw1.interfaces = {"intf1": intf_mock}
        self.napp.controller.switches = {"sw1": sw1}
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        data = response.json()
        expected = [
            {
                "proxy_port": {
                    "port_number": 1,
                    "status": "DOWN",
                    "status_reason": ["UNI interface 1 not found"],
                },
                "uni": {"id": "1", "status": "UP", "status_reason": []},
            }
        ]
        assert data == expected

        pp = MagicMock()
        self.napp.int_manager.get_proxy_port_or_raise = MagicMock()
        self.napp.int_manager.get_proxy_port_or_raise.return_value = pp
        pp.status.value = "UP"

        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        data = response.json()
        expected = [
            {
                "proxy_port": {
                    "port_number": 1,
                    "status": "UP",
                    "status_reason": [],
                },
                "uni": {"id": "1", "status": "UP", "status_reason": []},
            }
        ]
        assert data == expected

    async def test_on_table_enabled(self) -> None:
        """Test on_table_enabled."""
        assert self.napp.int_manager.flow_builder.table_group == {
            "evpl": 2,
            "epl": 3,
            "evpl_vlan_range": 3,
        }
        await self.napp.on_table_enabled(
            KytosEvent(content={"telemetry_int": {"evpl": 22, "epl": 33}})
        )
        assert self.napp.int_manager.flow_builder.table_group == {
            "evpl": 22,
            "epl": 33,
            "evpl_vlan_range": 3,
        }
        assert self.napp.controller.buffers.app.aput.call_count == 1

    async def test_on_table_enabled_no_group(self) -> None:
        """Test on_table_enabled no group."""
        await self.napp.on_table_enabled(
            KytosEvent(content={"mef_eline": {"evpl": 22, "epl": 33}})
        )
        assert not self.napp.controller.buffers.app.aput.call_count

    async def test_on_evc_deployed(self) -> None:
        """Test on_evc_deployed."""
        content = {"metadata": {"telemetry_request": {}}, "id": "some_id"}
        self.napp.int_manager.redeploy_int = AsyncMock()
        self.napp.int_manager.enable_int = AsyncMock()
        await self.napp.on_evc_deployed(KytosEvent(content=content))
        assert self.napp.int_manager.enable_int.call_count == 1
        assert self.napp.int_manager.redeploy_int.call_count == 0

        content = {"metadata": {"telemetry": {"enabled": True}}, "id": "some_id"}
        await self.napp.on_evc_deployed(KytosEvent(content=content))
        assert self.napp.int_manager.enable_int.call_count == 1
        assert self.napp.int_manager.redeploy_int.call_count == 1

    async def test_on_evc_deployed_error(self, monkeypatch) -> None:
        """Test on_evc_deployed error."""
        content = {"metadata": {"telemetry_request": {}}, "id": "some_id"}
        self.napp.int_manager.enable_int = AsyncMock()
        self.napp.int_manager.enable_int.side_effect = EVCError("no_id", "boom")
        log_mock = MagicMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.log", log_mock)
        api_mock = AsyncMock()
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        await self.napp.on_evc_deployed(KytosEvent(content=content))
        assert log_mock.error.call_count == 1
        assert api_mock.add_evcs_metadata.call_count == 1

    async def test_on_evc_deleted(self) -> None:
        """Test on_evc_deleted."""
        content = {"metadata": {"telemetry": {"enabled": True}}, "id": "some_id"}
        self.napp.int_manager.disable_int = AsyncMock()
        await self.napp.on_evc_deleted(KytosEvent(content=content))
        assert self.napp.int_manager.disable_int.call_count == 1

    async def test_on_uni_active_updated(self, monkeypatch) -> None:
        """Test on UNI active updated."""
        api_mock = AsyncMock()
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.main.api",
            api_mock,
        )
        content = {
            "metadata": {"telemetry": {"enabled": True}},
            "id": "some_id",
            "active": True,
        }
        await self.napp.on_uni_active_updated(KytosEvent(content=content))
        assert api_mock.add_evcs_metadata.call_count == 1
        args = api_mock.add_evcs_metadata.call_args[0][1]
        assert args["telemetry"]["status"] == "UP"

        content["active"] = False
        await self.napp.on_uni_active_updated(KytosEvent(content=content))
        assert api_mock.add_evcs_metadata.call_count == 2
        args = api_mock.add_evcs_metadata.call_args[0][1]
        assert args["telemetry"]["status"] == "DOWN"

    async def test_on_evc_undeployed(self) -> None:
        """Test on_evc_undeployed."""
        content = {
            "enabled": False,
            "metadata": {"telemetry": {"enabled": False}},
            "id": "some_id",
        }
        self.napp.int_manager.remove_int_flows = AsyncMock()
        await self.napp.on_evc_undeployed(KytosEvent(content=content))
        assert self.napp.int_manager.remove_int_flows.call_count == 0

        content["metadata"]["telemetry"]["enabled"] = True
        await self.napp.on_evc_undeployed(KytosEvent(content=content))
        assert self.napp.int_manager.remove_int_flows.call_count == 1

    async def test_on_evc_redeployed_link(self) -> None:
        """Test on redeployed_link_down|redeployed_link_up."""
        content = {
            "enabled": True,
            "metadata": {"telemetry": {"enabled": False}},
            "id": "some_id",
        }
        self.napp.int_manager.redeploy_int = AsyncMock()
        await self.napp.on_evc_redeployed_link(KytosEvent(content=content))
        assert self.napp.int_manager.redeploy_int.call_count == 0

        content["metadata"]["telemetry"]["enabled"] = True
        await self.napp.on_evc_redeployed_link(KytosEvent(content=content))
        assert self.napp.int_manager.redeploy_int.call_count == 1

    async def test_on_evc_redeployed_link_error(self, monkeypatch) -> None:
        """Test on redeployed_link_down|redeployed_link_up error."""
        content = {
            "enabled": True,
            "metadata": {"telemetry": {"enabled": True}},
            "id": "some_id",
        }
        log_mock = MagicMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.log", log_mock)
        self.napp.int_manager.redeploy_int = AsyncMock()
        self.napp.int_manager.redeploy_int.side_effect = EVCError("no_id", "boom")
        await self.napp.on_evc_redeployed_link(KytosEvent(content=content))
        assert log_mock.error.call_count == 1

    async def test_on_evc_error_redeployed_link_down(self) -> None:
        """Test error_redeployed_link_down."""
        content = {
            "enabled": True,
            "metadata": {"telemetry": {"enabled": False}},
            "id": "some_id",
        }
        self.napp.int_manager.remove_int_flows = AsyncMock()
        await self.napp.on_evc_error_redeployed_link_down(KytosEvent(content=content))
        assert self.napp.int_manager.remove_int_flows.call_count == 0

        content["metadata"]["telemetry"]["enabled"] = True
        await self.napp.on_evc_error_redeployed_link_down(KytosEvent(content=content))
        assert self.napp.int_manager.remove_int_flows.call_count == 1

    async def test_on_link_down(self) -> None:
        """Test on link_down."""
        self.napp.int_manager.handle_pp_link_down = AsyncMock()
        await self.napp.on_link_down(KytosEvent(content={"link": MagicMock()}))
        assert self.napp.int_manager.handle_pp_link_down.call_count == 1

    async def test_on_link_up(self) -> None:
        """Test on link_up."""
        self.napp.int_manager.handle_pp_link_up = AsyncMock()
        await self.napp.on_link_up(KytosEvent(content={"link": MagicMock()}))
        assert self.napp.int_manager.handle_pp_link_up.call_count == 1

    async def test_on_table_enabled_error(self, monkeypatch) -> None:
        """Test on_table_enabled error case."""
        assert self.napp.int_manager.flow_builder.table_group == {
            "evpl": 2,
            "epl": 3,
            "evpl_vlan_range": 3,
        }
        log_mock = MagicMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.log", log_mock)
        await self.napp.on_table_enabled(
            KytosEvent(content={"telemetry_int": {"invalid": 1}})
        )
        assert self.napp.int_manager.flow_builder.table_group == {
            "evpl": 2,
            "epl": 3,
            "evpl_vlan_range": 3,
        }
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
        evc_id = utils.get_id_from_cookie(flow.cookie)
        api_mock_main.get_evc.return_value = {
            evc_id: {"metadata": {"telemetry": {"enabled": True}}, "id": evc_id}
        }
        api_mock_int.get_stored_flows.return_value = {evc_id: [MagicMock()]}
        self.napp.int_manager._remove_int_flows_by_cookies = AsyncMock()

        event = KytosEvent(content={"flow": flow, "error_command": "add"})
        await self.napp.on_flow_mod_error(event)

        assert api_mock_main.get_evc.call_count == 1
        assert api_mock_int.get_stored_flows.call_count == 1
        assert api_mock_int.add_evcs_metadata.call_count == 1
        assert self.napp.int_manager._remove_int_flows_by_cookies.call_count == 1

    async def test_on_mef_eline_evcs_loaded(self):
        """Test on_mef_eline_evcs_loaded."""
        evcs = {"1": {}, "2": {}}
        event = KytosEvent(content=evcs)
        self.napp.int_manager = MagicMock()
        await self.napp.on_mef_eline_evcs_loaded(event)
        self.napp.int_manager.load_uni_src_proxy_ports.assert_called_with(evcs)

    async def test_on_intf_metadata_remove(self):
        """Test on_intf_metadata_removed."""
        intf = MagicMock()
        event = KytosEvent(content={"interface": intf})
        self.napp.int_manager = MagicMock()
        await self.napp.on_intf_metadata_removed(event)
        self.napp.int_manager.handle_pp_metadata_removed.assert_called_with(intf)

    async def test_on_intf_metadata_added(self):
        """Test on_intf_metadata_added."""
        intf = MagicMock()
        event = KytosEvent(content={"interface": intf})
        self.napp.int_manager = MagicMock()
        await self.napp.on_intf_metadata_added(event)
        self.napp.int_manager.handle_pp_metadata_added.assert_called_with(intf)

    @pytest.mark.parametrize(
        "event_name",
        [
            "kytos/mef_eline.failover_deployed",
            "kytos/mef_eline.failover_link_down",
            "kytos/mef_eline.failover_old_path",
            "kytos/mef_eline.static.standby_installed",
            "kytos/mef_eline.static.ingress_installed",
            "kytos/mef_eline.static.ingress_removed",
            "kytos/mef_eline.static.ingress_swapped",
        ],
    )
    async def test_on_partial_flows(self, event_name):
        """Every mef_eline event carrying a flow subset is handled, and the
        event name is passed through."""
        event = KytosEvent(name=event_name, content={})
        self.napp.int_manager = MagicMock()
        self.napp.int_manager.handle_partial_flows = AsyncMock(return_value=set())
        await self.napp.on_partial_flows(event)
        self.napp.int_manager.handle_partial_flows.assert_called_with(
            {}, event_name=event_name
        )

    @staticmethod
    def _int_evc(active: bool, status="UP", status_reason=None) -> dict:
        """An INT enabled EVC event content."""
        return {
            "active": active,
            "metadata": {
                "telemetry": {
                    "enabled": True,
                    "status": status,
                    "status_reason": status_reason or [],
                }
            },
        }

    async def _partial_flows(self, event_name: str, content: dict) -> None:
        """Handle a partial flows event with a mocked INT manager."""
        await self.napp.on_partial_flows(KytosEvent(name=event_name, content=content))

    @pytest.mark.parametrize(
        "event_name",
        [
            "kytos/mef_eline.static.ingress_removed",
            "kytos/mef_eline.failover_link_down",
            "kytos/mef_eline.failover_old_path",
        ],
    )
    async def test_partial_flows_status_down_then_up(
        self, monkeypatch, event_name
    ) -> None:
        """An EVC no longer forwarding goes DOWN, and UP again once a later
        event reports it forwarding, e.g. after a dynamic escape or a
        standby swap, which aren't undeploys or redeploys (mef_eline EP041)."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)
        self.napp.int_manager = MagicMock()
        self.napp.int_manager.handle_partial_flows = AsyncMock(return_value=set())

        await self._partial_flows(event_name, {"1": self._int_evc(False)})
        evcs, metadata = api_mock.add_evcs_metadata.call_args[0]
        assert list(evcs) == ["1"]
        assert metadata["telemetry"]["status"] == "DOWN"
        assert metadata["telemetry"]["status_reason"] == ["link_down_no_path"]

        # forwarding again, e.g. escaped: back UP, even if the content was
        # built before that DOWN was stored
        await self._partial_flows(
            "kytos/mef_eline.failover_link_down", {"1": self._int_evc(True)}
        )
        assert api_mock.add_evcs_metadata.call_count == 2
        metadata = api_mock.add_evcs_metadata.call_args[0][1]
        assert metadata["telemetry"]["status"] == "UP"
        assert metadata["telemetry"]["status_reason"] == []

        # already UP and forwarding: nothing to write
        await self._partial_flows(
            "kytos/mef_eline.static.ingress_swapped",
            {"1": self._int_evc(True)},
        )
        assert api_mock.add_evcs_metadata.call_count == 2

    async def test_partial_flows_status_keeps_other_down(self, monkeypatch) -> None:
        """A DOWN set for another reason is never overwritten, neither by a
        DOWN nor by an UP; one set here survives a restart through its
        reason; EVCs without INT or that just fell back are skipped."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)
        self.napp.int_manager = MagicMock()
        self.napp.int_manager.handle_partial_flows = AsyncMock(return_value={"3"})
        name = "kytos/mef_eline.static.ingress_installed"

        await self._partial_flows(
            name,
            {
                "1": self._int_evc(True, "DOWN", ["proxy_port_error"]),
                "2": self._int_evc(False, "DOWN", ["uni_down"]),
                "3": self._int_evc(True, "DOWN", ["link_down_no_path"]),
                "4": {"active": False, "metadata": {}},
            },
        )
        api_mock.add_evcs_metadata.assert_not_called()

        # its own DOWN after a restart (no memory of it)
        self.napp.int_manager.handle_partial_flows = AsyncMock(return_value=set())
        await self._partial_flows(
            name, {"1": self._int_evc(True, "DOWN", ["link_down_no_path"])}
        )
        metadata = api_mock.add_evcs_metadata.call_args[0][1]
        assert metadata["telemetry"]["status"] == "UP"

    async def test_evc_expected_flows_success(self, monkeypatch) -> None:
        """Test expected flows endpoint with specific evc_ids."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)

        evc_id = "3766c105686749"
        api_mock.get_evcs.return_value = {
            evc_id: {"metadata": {"telemetry": {"enabled": True}}}
        }

        expected_flows = {
            evc_id: {
                "count_total": 4,
                "count_table": {"0": 2, "1": 2},
                "flows": [
                    {
                        "switch": "00:00:00:00:00:00:00:01",
                        "flow": {"table_id": 0, "priority": 20000},
                        "flow_id": "aa84a60ca2965b52d71f",
                        "id": "965b52d71f",
                    }
                ],
            }
        }
        self.napp.int_manager.list_expected_flows = AsyncMock(
            return_value=expected_flows
        )

        endpoint = f"{self.base_endpoint}/evc/expected_flows"
        response = await self.api_client.post(endpoint, json={"evc_ids": [evc_id]})

        assert response.status_code == 200
        assert self.napp.int_manager.list_expected_flows.call_count == 1
        data = response.json()
        assert evc_id in data
        assert data[evc_id]["count_total"] == 4
        assert "flows" in data[evc_id]

    async def test_evc_expected_flows_empty_list(self, monkeypatch) -> None:
        """Test expected flows with empty evc_ids list."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)

        api_mock.get_evcs.return_value = {
            "evc1": {"metadata": {"telemetry": {"enabled": True}}},
            "evc2": {"metadata": {}},
        }

        expected_flows = {"evc1": {"count_total": 2, "count_table": {}, "flows": []}}
        self.napp.int_manager.list_expected_flows = AsyncMock(
            return_value=expected_flows
        )

        endpoint = f"{self.base_endpoint}/evc/expected_flows"
        response = await self.api_client.post(endpoint, json={"evc_ids": []})

        assert response.status_code == 200
        call_args = self.napp.int_manager.list_expected_flows.call_args[0][0]
        assert "evc1" in call_args
        assert "evc2" not in call_args

    async def test_evc_expected_flows_single_evc(self, monkeypatch) -> None:
        """Test expected flows with single evc_id uses get_evc."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)

        evc_id = "3766c105686749"
        api_mock.get_evc.return_value = {
            evc_id: {"metadata": {"telemetry": {"enabled": True}}}
        }

        expected_flows = {evc_id: {"count_total": 2, "count_table": {}, "flows": []}}
        self.napp.int_manager.list_expected_flows = AsyncMock(
            return_value=expected_flows
        )

        endpoint = f"{self.base_endpoint}/evc/expected_flows"
        response = await self.api_client.post(endpoint, json={"evc_ids": [evc_id]})

        assert response.status_code == 200
        assert api_mock.get_evc.call_count == 1
        assert api_mock.get_evc.call_args[0][0] == evc_id
        assert api_mock.get_evcs.call_count == 0

    async def test_evc_expected_flows_no_int_evcs(self, monkeypatch) -> None:
        """Test expected flows with no INT-enabled EVCs."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)

        api_mock.get_evcs.return_value = {
            "evc1": {"metadata": {}},
            "evc2": {"metadata": {"telemetry": {"enabled": False}}},
        }

        endpoint = f"{self.base_endpoint}/evc/expected_flows"
        response = await self.api_client.post(endpoint, json={"evc_ids": []})

        assert response.status_code == 200
        assert response.json() == {}

    async def test_evc_expected_flows_openapi_validation(self) -> None:
        """Test expected flows OpenAPI validation."""
        endpoint = f"{self.base_endpoint}/evc/expected_flows"

        response = await self.api_client.post(endpoint, json={"evc_ids": "wrong"})
        assert response.status_code == 400
        assert "evc_ids" in response.json()["description"]

    async def test_evc_expected_flows_invalid_payload(self) -> None:
        """Test expected flows with invalid payload."""
        endpoint = f"{self.base_endpoint}/evc/expected_flows"

        response = await self.api_client.post(endpoint, json={})
        assert response.status_code == 400
        assert "Invalid payload" in response.json()["description"]

    async def test_evc_expected_flows_evc_not_found(self, monkeypatch) -> None:
        """Test expected flows with EVCNotFound exception."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)

        evc_id = "3766c105686749"
        api_mock.get_evcs.return_value = {evc_id: {}}

        self.napp.int_manager.list_expected_flows = AsyncMock(
            side_effect=EVCNotFound(evc_id)
        )

        endpoint = f"{self.base_endpoint}/evc/expected_flows"
        response = await self.api_client.post(endpoint, json={"evc_ids": [evc_id]})

        assert response.status_code == 404
        assert "not found" in response.json()["description"]

    async def test_evc_expected_flows_flows_not_found(self, monkeypatch) -> None:
        """Test expected flows with FlowsNotFound exception."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)

        evc_id = "3766c105686749"
        api_mock.get_evcs.return_value = {evc_id: {}}

        self.napp.int_manager.list_expected_flows = AsyncMock(
            side_effect=FlowsNotFound(evc_id)
        )

        endpoint = f"{self.base_endpoint}/evc/expected_flows"
        response = await self.api_client.post(endpoint, json={"evc_ids": [evc_id]})

        assert response.status_code == 404
        assert "flows not found" in response.json()["description"]

    async def test_evc_expected_flows_retry_error_get_evcs(self, monkeypatch) -> None:
        """Test expected flows with RetryError from get_evcs."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)

        future = Future(1)
        future.set_exception(Exception("Service unavailable"))
        api_mock.get_evcs.side_effect = RetryError(future)

        endpoint = f"{self.base_endpoint}/evc/expected_flows"
        response = await self.api_client.post(endpoint, json={"evc_ids": []})

        assert response.status_code == 503

    async def test_evc_expected_flows_unrecoverable_error(self, monkeypatch) -> None:
        """Test expected flows with UnrecoverableError."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.main.api", api_mock)

        evc_id = "3766c105686749"
        api_mock.get_evcs.return_value = {evc_id: {}}

        self.napp.int_manager.list_expected_flows = AsyncMock(
            side_effect=UnrecoverableError("Unrecoverable error")
        )

        endpoint = f"{self.base_endpoint}/evc/expected_flows"
        response = await self.api_client.post(endpoint, json={"evc_ids": [evc_id]})

        assert response.status_code == 500
