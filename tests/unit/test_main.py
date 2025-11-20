"""Test Main methods."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from napps.kytos.telemetry_int import utils
from napps.kytos.telemetry_int.exceptions import EVCError, ProxyPortShared
from napps.kytos.telemetry_int.main import Main

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

    async def test_on_failover_deployed(self):
        """Test on_failover_deployed."""
        event = KytosEvent(content={})
        self.napp.int_manager = MagicMock()
        await self.napp.on_failover_deployed(event)
        self.napp.int_manager.handle_failover_flows.assert_called()

    async def test_on_failover_link_down(self):
        """Test on_failover_link_down."""
        event = KytosEvent(content={})
        self.napp.int_manager = MagicMock()
        await self.napp.on_failover_link_down(event)
        self.napp.int_manager.handle_failover_flows.assert_called()

    async def test_on_failover_old_path(self):
        """Test on_failover_old_path."""
        event = KytosEvent(content={})
        self.napp.int_manager = MagicMock()
        await self.napp.on_failover_old_path(event)
        self.napp.int_manager.handle_failover_flows.assert_called()
