"""Test INTManager"""

import pytest

from unittest.mock import AsyncMock, MagicMock
from napps.kytos.telemetry_int.exceptions import ProxyPortSameSourceIntraEVC
from napps.kytos.telemetry_int.managers.int import INTManager
from napps.kytos.telemetry_int import exceptions
from kytos.core.common import EntityStatus

from kytos.lib.helpers import (
    get_interface_mock,
    get_controller_mock,
    get_switch_mock,
)


class TestINTManager:
    """TestINTManager."""

    def test_get_proxy_port_or_raise(self) -> None:
        """Test proxy_port_or_raise."""
        dpid_a = "00:00:00:00:00:00:00:01"
        mock_switch_a = get_switch_mock(dpid_a, 0x04)
        mock_interface_a = get_interface_mock("s1-eth1", 1, mock_switch_a)
        mock_interface_a.metadata = {}
        intf_id = f"{dpid_a}:1"
        controller = get_controller_mock()
        evc_id = "3766c105686749"
        int_manager = INTManager(controller)

        # Initially the mocked interface and switch hasn't been associated in the ctrllr
        with pytest.raises(exceptions.ProxyPortNotFound) as exc:
            int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert f"interface {intf_id} not found" in str(exc)

        # Now, proxy_port still hasn't been set yet
        controller.get_interface_by_id = lambda x: mock_interface_a
        with pytest.raises(exceptions.ProxyPortNotFound) as exc:
            int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert f"proxy_port metadata not found in {intf_id}" in str(exc)

        # Now, destination interface hasn't been mocked yet
        mock_interface_a.metadata = {"proxy_port": 5}
        with pytest.raises(exceptions.ProxyPortDestNotFound) as exc:
            int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert "destination interface not found" in str(exc)

        mock_interface_b = get_interface_mock("s1-eth5", 5, mock_switch_a)
        mock_interface_b.metadata = {"looped": {"port_numbers": [5, 6]}}
        mock_interface_a.switch.get_interface_by_port_no = lambda x: mock_interface_b
        # Now all dependencies have been mocked and it should get the ProxyPort
        pp = int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert pp.source == mock_interface_b

    def test_load_uni_src_proxy_port(self) -> None:
        """Test test_load_uni_src_proxy_port."""
        dpid_a = "00:00:00:00:00:00:00:01"
        mock_switch_a = get_switch_mock(dpid_a, 0x04)
        mock_interface_a = get_interface_mock("s1-eth1", 1, mock_switch_a)
        mock_interface_a.metadata = {"proxy_port": 3}
        mock_interface_z = get_interface_mock("s1-eth2", 2, mock_switch_a)
        mock_interface_z.metadata = {"proxy_port": 5}
        intf_id_a = f"{dpid_a}:1"
        intf_id_z = f"{dpid_a}:2"
        intf_id_a_1 = f"{dpid_a}:3"
        intf_id_z_1 = f"{dpid_a}:5"

        mock_interface_a_1 = get_interface_mock("s1-eth3", 3, mock_switch_a)
        mock_interface_a_1.metadata = {"looped": {"port_numbers": [3, 4]}}
        mock_interface_a_2 = get_interface_mock("s1-eth4", 4, mock_switch_a)
        mock_interface_z_1 = get_interface_mock("s1-eth5", 5, mock_switch_a)
        mock_interface_z_1.metadata = {"looped": {"port_numbers": [5, 6]}}
        mock_interface_z_2 = get_interface_mock("s1-eth6", 6, mock_switch_a)

        def get_interface_by_port_no(port_no):
            data = {
                1: mock_interface_a,
                2: mock_interface_z,
                3: mock_interface_a_1,
                4: mock_interface_a_2,
                5: mock_interface_z_1,
                6: mock_interface_z_2,
            }
            return data[port_no]

        def get_interface_by_id(intf_id):
            data = {
                intf_id_a: mock_interface_a,
                intf_id_z: mock_interface_z,
            }
            return data[intf_id]

        controller = get_controller_mock()
        mock_switch_a.get_interface_by_port_no = get_interface_by_port_no
        controller.get_interface_by_id = get_interface_by_id

        evcs = {
            "3766c105686749": {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            },
            "3766c105686748": {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            },
            "3766c105686747": {
                "metadata": {"telemetry": {"enabled": False}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            },
        }
        int_manager = INTManager(controller)
        int_manager.load_uni_src_proxy_ports(evcs)
        assert len(int_manager.unis_src) == 2
        assert int_manager.unis_src[intf_id_a] == intf_id_a_1
        assert int_manager.unis_src[intf_id_z] == intf_id_z_1

        assert len(int_manager.srcs_pp) == 2
        assert int_manager.srcs_pp[intf_id_a_1].source == mock_interface_a_1
        assert int_manager.srcs_pp[intf_id_a_1].destination == mock_interface_a_2
        assert int_manager.srcs_pp[intf_id_z_1].source == mock_interface_z_1
        assert int_manager.srcs_pp[intf_id_z_1].destination == mock_interface_z_2

        assert int_manager.srcs_pp[intf_id_a_1].evc_ids == {
            "3766c105686749",
            "3766c105686748",
        }
        assert int_manager.srcs_pp[intf_id_z_1].evc_ids == {
            "3766c105686749",
            "3766c105686748",
        }

    async def test_handle_pp_link_down(self, monkeypatch):
        """Test test_handle_pp_link_down."""
        int_manager = INTManager(MagicMock())
        api_mock, link_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        link_mock.endpoint_a.id = "some_intf_id"
        evc_id = "3766c105686748"
        int_manager.srcs_pp[link_mock.endpoint_a.id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.remove_int_flows = AsyncMock()

        await int_manager.handle_pp_link_down(link_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
            "metadata.telemetry.status": "UP",
        }
        assert int_manager.remove_int_flows.call_count == 1
        args = int_manager.remove_int_flows.call_args[0]
        assert evc_id in args[0]
        assert "telemetry" in args[1]
        telemetry = args[1]["telemetry"]
        assert telemetry["enabled"]
        assert telemetry["status"] == "DOWN"
        assert telemetry["status_reason"] == ["proxy_port_down"]
        assert "status_updated_at" in telemetry

    async def test_handle_pp_link_up(self, monkeypatch):
        """Test handle_pp_link_up."""
        int_manager = INTManager(MagicMock())
        api_mock, link_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        link_mock.endpoint_a.id = "3"
        pp_mock.status = EntityStatus.UP
        link_mock.status = EntityStatus.UP
        link_mock.status_reason = []
        evc_id = "3766c105686748"
        uni_a_id, uni_z_id = "1", "2"
        src_a_id, src_z_id = "3", "5"
        int_manager.srcs_pp[src_a_id] = pp_mock
        int_manager.srcs_pp[src_z_id] = pp_mock
        int_manager.unis_src[uni_a_id] = src_a_id
        int_manager.unis_src[uni_z_id] = src_z_id
        pp_mock.evc_ids = {evc_id}

        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {
            evc_id: {
                "active": True,
                "archived": False,
                "uni_a": {"interface_id": uni_a_id},
                "uni_z": {"interface_id": uni_z_id},
            }
        }
        int_manager.install_int_flows = AsyncMock()
        int_manager._validate_map_enable_evcs = MagicMock()

        await int_manager.handle_pp_link_up(link_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
            "metadata.telemetry.status": "DOWN",
        }
        assert int_manager.install_int_flows.call_count == 1
        args = int_manager.install_int_flows.call_args[0]
        assert "telemetry" in args[1]
        telemetry_dict = args[1]["telemetry"]
        expected_keys = ["enabled", "status", "status_reason", "status_updated_at"]
        assert sorted(list(telemetry_dict.keys())) == sorted(expected_keys)
        assert telemetry_dict["enabled"]
        assert telemetry_dict["status"] == "UP"
        assert not telemetry_dict["status_reason"]

    async def test_handle_pp_metadata_removed(self, monkeypatch):
        """Test handle_pp_metadata_removed."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        source_id = "some_source_id"
        evc_id = "3766c105686748"
        int_manager.unis_src[intf_mock.id] = source_id
        int_manager.srcs_pp[source_id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        assert "proxy_port" not in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.remove_int_flows = AsyncMock()

        await int_manager.handle_pp_metadata_removed(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
            "metadata.telemetry.status": "UP",
        }
        assert int_manager.remove_int_flows.call_count == 1
        args = int_manager.remove_int_flows.call_args[0]
        assert evc_id in args[0]
        assert "telemetry" in args[1]
        telemetry = args[1]["telemetry"]
        assert telemetry["enabled"]
        assert telemetry["status"] == "DOWN"
        assert telemetry["status_reason"] == ["proxy_port_metadata_removed"]
        assert "status_updated_at" in telemetry

    async def test_handle_pp_metadata_added(self, monkeypatch):
        """Test handle_pp_metadata_added."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        source_id, source_port = "some_source_id", 2
        intf_mock.metadata = {"proxy_port": source_port}
        evc_id = "3766c105686748"
        int_manager.unis_src[intf_mock.id] = source_id
        int_manager.srcs_pp[source_id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()

        await int_manager.handle_pp_metadata_added(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {"metadata.telemetry.enabled": "true"}
        assert int_manager.disable_int.call_count == 1
        assert int_manager.enable_int.call_count == 1

    async def test_handle_pp_metadata_added_no_change(self, monkeypatch):
        """Test handle_pp_metadata_added no change."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        source_id, source_port = "some_source_id", 2
        source_intf = MagicMock()
        intf_mock.metadata = {"proxy_port": source_port}
        evc_id = "3766c105686748"
        int_manager.unis_src[intf_mock.id] = source_id
        int_manager.srcs_pp[source_id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        # Simulating that the current and new proxy_port source are the same
        pp_mock.source = source_intf
        intf_mock.switch.get_interface_by_port_no.return_value = source_intf

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()

        await int_manager.handle_pp_metadata_added(intf_mock)
        assert not api_mock.get_evcs.call_count
        assert not int_manager.disable_int.call_count
        assert not int_manager.enable_int.call_count

    async def test_handle_pp_metadata_added_no_affected(self, monkeypatch):
        """Test handle_pp_metadata_added no affected evcs."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        source_id, source_port = "some_source_id", 2
        intf_mock.metadata = {"proxy_port": source_port}
        evc_id = "3766c105686748"
        int_manager.unis_src[intf_mock.id] = source_id
        int_manager.srcs_pp[source_id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        # Simulating returning no EVCs that were enabled and UP
        api_mock.get_evcs.return_value = {}
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()

        await int_manager.handle_pp_metadata_added(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
        }
        assert not int_manager.disable_int.call_count
        assert not int_manager.enable_int.call_count

    async def test_disable_int_metadata(self, monkeypatch) -> None:
        """Test disable INT metadata args."""
        controller = MagicMock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        int_manager._remove_int_flows_by_cookies = AsyncMock()
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
        evcs = {
            "3766c105686749": {
                "active": True,
                "uni_a": MagicMock(),
                "uni_z": MagicMock(),
            }
        }
        int_manager._validate_map_enable_evcs = MagicMock()
        int_manager._validate_map_enable_evcs.return_value = evcs
        int_manager.flow_builder.build_int_flows = MagicMock()
        int_manager.flow_builder.build_int_flows.return_value = {
            0xAA3766C105686749: [MagicMock()]
        }
        int_manager._add_pps_evc_ids = MagicMock()
        int_manager._send_flows = AsyncMock()

        await int_manager.enable_int(evcs, False)

        assert stored_flows_mock.call_count == 1
        assert api_mock.add_evcs_metadata.call_count == 3
        args = api_mock.add_evcs_metadata.call_args[0]
        assert "telemetry" in args[1]
        telemetry_dict = args[1]["telemetry"]
        expected_keys = ["enabled", "status", "status_reason", "status_updated_at"]
        assert sorted(list(telemetry_dict.keys())) == sorted(expected_keys)
        assert int_manager._send_flows.call_count == 1

        assert telemetry_dict["enabled"] is True
        assert telemetry_dict["status"] == "UP"
        assert telemetry_dict["status_reason"] == []

    async def test_redeploy_int(self, monkeypatch) -> None:
        """Test redeploy int."""
        controller = MagicMock()
        api_mock = AsyncMock()
        stored_flows_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.utils.get_found_stored_flows", stored_flows_mock
        )

        int_manager = INTManager(controller)
        int_manager._remove_int_flows_by_cookies = AsyncMock()
        int_manager._install_int_flows = AsyncMock()

        dpid_a = "00:00:00:00:00:00:00:01"
        intf_id_a = f"{dpid_a}:1"
        intf_id_z = f"{dpid_a}:2"
        evc_id = "3766c105686749"
        evcs = {
            evc_id: {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            }
        }
        int_manager._validate_map_enable_evcs = MagicMock()
        await int_manager.redeploy_int(evcs)

        assert stored_flows_mock.call_count == 1
        assert int_manager._remove_int_flows_by_cookies.call_count == 1
        assert api_mock.get_stored_flows.call_count == 1
        assert int_manager._install_int_flows.call_count == 1

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

    async def test__remove_int_flows_by_cookies(
        self, inter_evc_evpl_flows_data
    ) -> None:
        """test _remove_int_flows_by_cookies."""
        controller = get_controller_mock()
        controller._buffers.app.aput = AsyncMock()
        int_manager = INTManager(controller)
        assert len(inter_evc_evpl_flows_data) == 3
        res = await int_manager._remove_int_flows_by_cookies(inter_evc_evpl_flows_data)
        assert len(res) == 3
        for flows in res.values():
            for flow in flows:
                assert "cookie_mask" in flow
                assert flow["cookie_mask"] == int(0xFFFFFFFFFFFFFFFF)
                assert flow["table_id"] == 0xFF
        assert controller._buffers.app.aput.call_count == 3

    async def test__remove_int_flows(self, inter_evc_evpl_flows_data) -> None:
        """test _remove_int_flows."""
        controller = get_controller_mock()
        controller._buffers.app.aput = AsyncMock()
        int_manager = INTManager(controller)
        assert len(inter_evc_evpl_flows_data) == 3
        res = await int_manager._remove_int_flows(inter_evc_evpl_flows_data)
        assert len(res) == 3
        assert controller._buffers.app.aput.call_count == 3

    async def test__install_int_flows(self, inter_evc_evpl_flows_data, monkeypatch):
        """test__install_int_flows."""
        sleep_mock = AsyncMock()
        monkeypatch.setattr("asyncio.sleep", sleep_mock)
        controller = get_controller_mock()
        controller._buffers.app.aput = AsyncMock()
        int_manager = INTManager(controller)
        assert len(inter_evc_evpl_flows_data) == 3
        res = await int_manager._install_int_flows(inter_evc_evpl_flows_data)
        assert len(res) == 3
        assert controller._buffers.app.aput.call_count == 3
        assert sleep_mock.call_count == 0

    def test__add_pps_evc_ids(self):
        """test_add_pps_evc_ids."""
        dpid_a = "00:00:00:00:00:00:00:01"
        intf_id_a = f"{dpid_a}:1"
        intf_id_z = f"{dpid_a}:2"
        evc_id = "3766c105686749"
        evcs = {
            evc_id: {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            }
        }
        controller = get_controller_mock()
        int_manager = INTManager(controller)
        pp = MagicMock()
        mock = MagicMock()
        int_manager.get_proxy_port_or_raise = mock
        mock.return_value = pp
        int_manager._add_pps_evc_ids(evcs)
        assert int_manager.get_proxy_port_or_raise.call_count == 2
        assert pp.evc_ids.add.call_count == 2
        pp.evc_ids.add.assert_called_with(evc_id)

    def test__discard_pps_evc_ids(self):
        """test_discard_pps_evc_ids."""
        dpid_a = "00:00:00:00:00:00:00:01"
        intf_id_a = f"{dpid_a}:1"
        intf_id_z = f"{dpid_a}:2"
        evc_id = "3766c105686749"
        evcs = {
            evc_id: {
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": intf_id_a},
                "uni_z": {"interface_id": intf_id_z},
            }
        }
        controller = get_controller_mock()
        int_manager = INTManager(controller)
        pp = MagicMock()
        mock = MagicMock()
        int_manager.get_proxy_port_or_raise = mock
        mock.return_value = pp
        int_manager._discard_pps_evc_ids(evcs)
        assert int_manager.get_proxy_port_or_raise.call_count == 2
        assert pp.evc_ids.discard.call_count == 2
        pp.evc_ids.discard.assert_called_with(evc_id)

    def test_validate_evc_stored_flows(self) -> None:
        """Test validate evc stored flows."""
        controller = MagicMock()
        int_manager = INTManager(controller)
        evcs = {
            "3766c105686749": {
                "active": True,
                "uni_a": MagicMock(),
                "uni_z": MagicMock(),
            }
        }
        stored_flows = {0xAA3766C105686749: [MagicMock()]}
        int_manager._validate_evcs_stored_flows(evcs, stored_flows)

        with pytest.raises(exceptions.FlowsNotFound):
            int_manager._validate_evcs_stored_flows(evcs, {0xAA3766C105686749: []})

        with pytest.raises(exceptions.FlowsNotFound):
            int_manager._validate_evcs_stored_flows(evcs, {})

        evcs["3766c105686749"]["active"] = False
        int_manager._validate_evcs_stored_flows(evcs, {})

    async def test__send_flows(self) -> None:
        """Test _send_flows."""
        controller = get_controller_mock()
        controller._buffers.app.aput = AsyncMock()
        int_manager = INTManager(controller)
        switch_flows = {"dpid": []}
        await int_manager._send_flows(switch_flows, "install")
        controller._buffers.app.aput.assert_not_called()

        switch_flows = {"dpid": [MagicMock()]}
        await int_manager._send_flows(switch_flows, "install")
        controller._buffers.app.aput.assert_called()
