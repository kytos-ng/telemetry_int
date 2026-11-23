"""Test INTManager"""

# pylint: disable=too-many-lines

import asyncio
import copy

import pytest

from unittest.mock import AsyncMock, MagicMock
from tenacity import RetryError
from napps.kytos.telemetry_int.exceptions import ProxyPortSameSourceIntraEVC
from napps.kytos.telemetry_int.exceptions import ProxyPortShared
from napps.kytos.telemetry_int.managers.int import INTManager
from napps.kytos.telemetry_int import exceptions, settings, utils
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
        with pytest.raises(exceptions.ProxyPortMetadataNotFound) as exc:
            int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert f"metadata not found in {intf_id}" in str(exc)

        # Now, destination interface hasn't been mocked yet
        mock_interface_a.metadata = {"proxy_port": 5}
        with pytest.raises(exceptions.ProxyPortDestNotFound) as exc:
            int_manager.get_proxy_port_or_raise(intf_id, evc_id)
        assert "isn't looped" in str(exc)

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

    async def test_update_int_status_down_then_up(self, monkeypatch) -> None:
        """An EVC no longer forwarding goes DOWN, and UP again once a later
        event reports it forwarding, e.g. after a resume on a configured path
        or a dynamic escape, which aren't redeploys (mef_eline EP041)."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())

        await int_manager._update_int_status("ev", {"1": self._int_evc(False)})
        evcs, metadata = api_mock.add_evcs_metadata.call_args[0]
        assert list(evcs) == ["1"]
        assert metadata["telemetry"]["status"] == "DOWN"
        assert metadata["telemetry"]["status_reason"] == ["link_down_no_path"]

        await int_manager._update_int_status("ev", {"1": self._int_evc(True)})
        metadata = api_mock.add_evcs_metadata.call_args[0][1]
        assert metadata["telemetry"]["status"] == "UP"
        assert metadata["telemetry"]["status_reason"] == []

        await int_manager._update_int_status("ev", {"1": self._int_evc(True)})
        assert api_mock.add_evcs_metadata.call_count == 3

    async def test_update_int_status_keeps_foreign_down(self, monkeypatch) -> None:
        """A DOWN set for another reason is never overwritten, neither by a
        DOWN nor by an UP; one set here survives a restart through its
        reason."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        foreign = {"status": "DOWN", "status_reason": ["proxy_port_error"]}

        for active in (True, False):
            await int_manager._update_int_status(
                "ev", {"1": self._int_evc(active, **foreign)}
            )
            api_mock.add_evcs_metadata.assert_not_called()

        await int_manager._update_int_status(
            "ev",
            {"1": self._int_evc(True, "DOWN", ["link_down_no_path"])},
        )
        metadata = api_mock.add_evcs_metadata.call_args[0][1]
        assert metadata["telemetry"]["status"] == "UP"

    async def test_update_int_status_batched_per_status(self, monkeypatch) -> None:
        """EVCs are written one call per status, not one per EVC."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())

        await int_manager._update_int_status(
            "ev",
            {
                "1": self._int_evc(False),
                "2": self._int_evc(False),
                "3": self._int_evc(True, "DOWN", ["link_down_no_path"]),
            },
        )

        assert api_mock.add_evcs_metadata.call_count == 2
        by_status = {
            call[0][1]["telemetry"]["status"]: sorted(call[0][0])
            for call in api_mock.add_evcs_metadata.call_args_list
        }
        assert by_status == {"DOWN": ["1", "2"], "UP": ["3"]}

    async def test_handle_partial_flows_status_after_bootstrap(
        self, monkeypatch
    ) -> None:
        """An EVC enabled fully event-based, whose telemetry metadata is
        bootstrapped while its flows are handled, still gets its status
        mirrored, even with no flows in the event."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        int_manager.get_proxy_port_or_raise = MagicMock(
            return_value=MagicMock(status=EntityStatus.UP)
        )
        evc = {
            "active": False,
            "metadata": {"telemetry_request": {}},
            "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"interface_id": "00:00:00:00:00:00:00:03:1"},
        }

        await int_manager.handle_partial_flows(
            {"1": evc}, "kytos/mef_eline.static.ingress_removed"
        )

        metadata = api_mock.add_evcs_metadata.call_args[0][1]
        assert metadata["telemetry"]["status"] == "DOWN"
        assert metadata["telemetry"]["status_reason"] == ["link_down_no_path"]

    async def test_handle_partial_flows_status_by_event(self, monkeypatch) -> None:
        """Only an ingress install or removal mirrors the EVC status."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        int_manager.get_proxy_port_or_raise = MagicMock(
            return_value=MagicMock(status=EntityStatus.UP)
        )

        def resumed() -> dict:
            return {
                "active": True,
                "metadata": {
                    "telemetry": {
                        "enabled": True,
                        "status": "DOWN",
                        "status_reason": ["link_down_no_path"],
                    }
                },
                "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
                "uni_z": {"interface_id": "00:00:00:00:00:00:00:03:1"},
            }

        await int_manager.handle_partial_flows(
            {"1": resumed()}, "kytos/mef_eline.static.ingress_swapped"
        )
        api_mock.add_evcs_metadata.assert_not_called()

        await int_manager.handle_partial_flows(
            {"1": resumed()}, "kytos/mef_eline.static.ingress_installed"
        )
        metadata = api_mock.add_evcs_metadata.call_args[0][1]
        assert metadata["telemetry"]["status"] == "UP"

    async def test_handle_partial_flows_source_flows_by_event(self) -> None:
        """INT source flows are installed again only on an ingress resume,
        as an ingress removal took them out; a swap leaves them in place."""
        int_manager = INTManager(MagicMock())
        int_manager.get_proxy_port_or_raise = MagicMock(
            return_value=MagicMock(status=EntityStatus.UP)
        )
        int_manager._install_int_flows = AsyncMock()
        int_manager._update_int_status = AsyncMock()
        source, table_x = (
            {
                "flow": {
                    "instructions": [
                        {
                            "instruction_type": "apply_actions",
                            "actions": [{"action_type": action_type}],
                        }
                    ]
                }
            }
            for action_type in ("push_int", "add_int_metadata")
        )
        int_manager.flow_builder.build_int_flows = MagicMock(
            return_value={1: [source, table_x]}
        )

        def evc() -> dict:
            return {
                "active": True,
                "metadata": {"telemetry": {"enabled": True}},
                "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
                "uni_z": {"interface_id": "00:00:00:00:00:00:00:03:1"},
                "flows": {"00:00:00:00:00:00:00:01": [{"cookie": 1}]},
            }

        await int_manager.handle_partial_flows(
            {"1": evc()}, "kytos/mef_eline.static.ingress_swapped"
        )
        assert int_manager._install_int_flows.call_args[0][0] == {1: [table_x]}

        await int_manager.handle_partial_flows(
            {"1": evc()}, "kytos/mef_eline.static.ingress_installed"
        )
        assert int_manager._install_int_flows.call_args[0][0] == {1: [source, table_x]}

    async def test_handle_partial_flows_returns_fell_back(self):
        """EVCs whose proxy port is in an unexpected state fall back to
        mef_eline flows and are returned, so their status isn't changed
        again afterwards."""
        int_manager = INTManager(MagicMock())
        int_manager.remove_int_flows = AsyncMock()
        int_manager.get_proxy_port_or_raise = MagicMock(
            side_effect=exceptions.ProxyPortError("1", "bad")
        )
        evc = {
            "active": True,
            "metadata": {"telemetry": {"enabled": True}},
            "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"interface_id": "00:00:00:00:00:00:00:03:1"},
            "service_level": 0,
            "creation_time": "2024-01-01T00:00:00",
        }
        fell_back = await int_manager.handle_partial_flows(
            {"1": evc}, "kytos/mef_eline.static.ingress_installed"
        )
        assert fell_back == {"1"}
        assert int_manager.remove_int_flows.call_count == 1

    @staticmethod
    def _pp_int_manager(monkeypatch, pp_status, pp_metadata=True) -> tuple:
        """An INTManager whose UNIs resolve to proxy ports with ``pp_status``,
        or have no proxy port metadata at all, and its api mock."""
        api_mock = AsyncMock()
        api_mock.get_stored_flows.return_value = {}
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        if pp_metadata:
            pp = MagicMock(status=pp_status)
            int_manager.get_proxy_port_or_raise = MagicMock(return_value=pp)
        else:
            int_manager.get_proxy_port_or_raise = MagicMock(
                side_effect=exceptions.ProxyPortMetadataNotFound("1", "no pp")
            )
        int_manager._install_int_flows = AsyncMock()
        int_manager._remove_int_flows = AsyncMock()
        int_manager._remove_int_flows_by_cookies = AsyncMock()
        int_manager.install_int_flows = AsyncMock()
        int_manager.flow_builder.build_int_flows = MagicMock(
            return_value={1: [{"flow": {"instructions": []}}]}
        )
        int_manager.flow_builder.build_failover_old_flows = MagicMock(
            return_value={1: [{"flow": {}}]}
        )
        return int_manager, api_mock

    @staticmethod
    def _pp_evc(status="UP", status_reason=None, proxy_port_enabled=None) -> dict:
        """An active INT EVC event content carrying installed and removed
        flows."""
        metadata = {
            "telemetry": {
                "enabled": True,
                "status": status,
                "status_reason": status_reason or [],
            }
        }
        if proxy_port_enabled is not None:
            metadata["proxy_port_enabled"] = proxy_port_enabled
        return {
            "active": True,
            "metadata": metadata,
            "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"interface_id": "00:00:00:00:00:00:00:03:1"},
            "service_level": 0,
            "creation_time": "2024-01-01T00:00:00",
            "flows": {"00:00:00:00:00:00:00:01": [{"cookie": 1, "match": {}}]},
            "removed_flows": {"00:00:00:00:00:00:00:02": [{"cookie": 1, "match": {}}]},
        }

    @pytest.mark.parametrize(
        "event_name",
        [
            "kytos/mef_eline.static.ingress_swapped",
            "kytos/mef_eline.static.ingress_installed",
            "kytos/mef_eline.static.ingress_removed",
            "kytos/mef_eline.static.standby_installed",
            "kytos/mef_eline.failover_link_down",
        ],
    )
    @pytest.mark.parametrize(
        "content",
        [("DOWN", ["proxy_port_down"]), ("UP", None), ("DOWN", ["uni_down"])],
    )
    async def test_handle_partial_flows_proxy_port_down_falls_back(
        self, monkeypatch, event_name, content
    ) -> None:
        """An EVC whose proxy port is down falls back to mef_eline whatever
        its content status says, which can predate a proxy port link down or
        have been overwritten: the event installs no INT flows, every INT
        flow is removed and it's set DOWN proxy_port_down. The removals in
        the event are still applied, and no EVC is fetched."""
        int_manager, api_mock = self._pp_int_manager(monkeypatch, EntityStatus.DOWN)

        await int_manager.handle_partial_flows(
            {"1": self._pp_evc(*content)}, event_name
        )

        int_manager._install_int_flows.assert_not_called()
        int_manager.install_int_flows.assert_not_called()
        assert int_manager._remove_int_flows.call_count == 1
        api_mock.get_evcs.assert_not_called()
        assert api_mock.get_stored_flows.call_args[0][0] == [
            utils.get_cookie("1", settings.INT_COOKIE_PREFIX)
        ]
        assert int_manager._remove_int_flows_by_cookies.call_count == 1
        assert api_mock.add_evcs_metadata.call_count == 1
        evcs, metadata = api_mock.add_evcs_metadata.call_args[0][:2]
        assert list(evcs) == ["1"]
        assert metadata["telemetry"]["enabled"] is True
        assert metadata["telemetry"]["status"] == "DOWN"
        assert metadata["telemetry"]["status_reason"] == ["proxy_port_down"]

    async def test_handle_partial_flows_proxy_port_down_no_fallback(
        self, monkeypatch
    ) -> None:
        """Without FALLBACK_TO_MEF_LOOP_DOWN INT stays on a proxy port that's
        down, so its flows are handled as usual."""
        monkeypatch.setattr(settings, "FALLBACK_TO_MEF_LOOP_DOWN", False)
        int_manager, api_mock = self._pp_int_manager(monkeypatch, EntityStatus.DOWN)

        await int_manager.handle_partial_flows(
            {"1": self._pp_evc()}, "kytos/mef_eline.static.ingress_swapped"
        )

        assert int_manager._install_int_flows.call_count == 1
        assert int_manager._remove_int_flows.call_count == 1
        int_manager._remove_int_flows_by_cookies.assert_not_called()
        api_mock.add_evcs_metadata.assert_not_called()

    async def test_handle_partial_flows_steps_run_after_errors(
        self, monkeypatch
    ) -> None:
        """A failing step doesn't skip the next ones, which can concern other
        EVCs of the event. EVCs with flows in a failed remove or install are
        set DOWN flows_remove_failed or flows_install_failed, and their status
        isn't updated from the event afterwards."""
        failed_id, ok_id = "3766c105686748", "3766c105686749"
        cookie = utils.get_cookie(failed_id, settings.INT_COOKIE_PREFIX)
        int_manager, api_mock = self._pp_int_manager(monkeypatch, EntityStatus.UP)
        int_manager.flow_builder.build_failover_old_flows = MagicMock(
            return_value={cookie: [{"flow": {}}]}
        )
        int_manager._built_install_flows = MagicMock(
            return_value={cookie: [{"flow": {}}]}
        )
        int_manager._remove_int_flows.side_effect = exceptions.FlowsSendError(
            "1", {failed_id}
        )
        int_manager._install_int_flows.side_effect = exceptions.FlowsSendError(
            "2", {failed_id}
        )
        int_manager._update_int_status = AsyncMock()
        int_manager._pop_pp_evcs = MagicMock(
            return_value=({"2": self._pp_evc()}, {"3": self._pp_evc()})
        )
        int_manager._fall_back_pp_down = AsyncMock(
            side_effect=exceptions.UnrecoverableError("3")
        )
        int_manager._reinstall_pp_recovered = AsyncMock()

        await int_manager.handle_partial_flows(
            {failed_id: self._pp_evc(), ok_id: self._pp_evc()},
            "kytos/mef_eline.static.ingress_removed",
        )

        int_manager._remove_int_flows.assert_awaited_once()
        int_manager._install_int_flows.assert_awaited_once()
        int_manager._fall_back_pp_down.assert_awaited_once()
        int_manager._reinstall_pp_recovered.assert_awaited_once()
        reasons = [
            (list(args[0]), args[1]["telemetry"])
            for args, _ in api_mock.add_evcs_metadata.call_args_list
        ]
        assert [(ids, t["status_reason"]) for ids, t in reasons] == [
            ([failed_id], ["flows_remove_failed"]),
            ([failed_id], ["flows_install_failed"]),
        ]
        assert all(t["enabled"] and t["status"] == "DOWN" for _, t in reasons)
        assert list(int_manager._update_int_status.call_args[0][1]) == [ok_id]

    @pytest.mark.parametrize(
        "status_reason", [["proxy_port_down"], ["proxy_port_error"]]
    )
    async def test_handle_partial_flows_proxy_port_up_while_inactive(
        self, monkeypatch, status_reason
    ) -> None:
        """A proxy port that came back UP while the EVC wasn't forwarding is
        skipped by handle_pp_link_up (not active), so resuming the ingress
        (static.ingress_installed) is what must reinstall every INT flow and
        set it UP, the event only carries the ingress flows."""
        int_manager, api_mock = self._pp_int_manager(monkeypatch, EntityStatus.UP)

        await int_manager.handle_partial_flows(
            {"1": self._pp_evc("DOWN", status_reason)},
            "kytos/mef_eline.static.ingress_installed",
        )

        int_manager._install_int_flows.assert_not_called()
        assert int_manager._remove_int_flows.call_count == 1
        assert int_manager.install_int_flows.call_count == 1
        evcs, metadata = int_manager.install_int_flows.call_args[0][:2]
        assert list(evcs) == ["1"]
        assert metadata["telemetry"]["status"] == "UP"
        assert metadata["telemetry"]["status_reason"] == []
        api_mock.add_evcs_metadata.assert_not_called()
        api_mock.get_evcs.assert_not_called()

    @pytest.mark.parametrize(
        "event_name",
        [
            "kytos/mef_eline.static.ingress_swapped",
            "kytos/mef_eline.failover_link_down",
        ],
    )
    async def test_handle_partial_flows_proxy_port_up_other_event(
        self, monkeypatch, event_name
    ) -> None:
        """With its proxy ports UP again an active EVC is reinstalled by
        handle_pp_link_up, so other events are handled as usual."""
        int_manager, _ = self._pp_int_manager(monkeypatch, EntityStatus.UP)

        await int_manager.handle_partial_flows(
            {"1": self._pp_evc("DOWN", ["proxy_port_down"])}, event_name
        )

        assert int_manager._install_int_flows.call_count == 1
        int_manager.install_int_flows.assert_not_called()

    @pytest.mark.parametrize("fallback", [True, False])
    async def test_install_int_flows_proxy_port_down(
        self, monkeypatch, fallback
    ) -> None:
        """An EVC whose proxy port is down is set DOWN proxy_port_down, and
        with FALLBACK_TO_MEF_LOOP_DOWN it falls back to mef_eline, active or
        not: its INT flows aren't installed. An EVC with proxy_port_enabled
        false doesn't use the proxy port, so it's installed and UP."""
        monkeypatch.setattr(settings, "FALLBACK_TO_MEF_LOOP_DOWN", fallback)
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr(utils, "get_found_stored_flows", AsyncMock())
        int_manager = INTManager(MagicMock())
        int_manager._install_int_flows = AsyncMock()
        pp_down = MagicMock(status=EntityStatus.DOWN)
        evcs = {}
        for evc_id, proxy_port_enabled in (
            ("a1", None),
            ("a2", False),
            ("a3", None),
            ("a4", None),
        ):
            evc = self._pp_evc(proxy_port_enabled=proxy_port_enabled)
            evc["active"] = evc_id != "a4"
            evc["uni_a"], evc["uni_z"] = utils.get_evc_unis(evc)
            if evc_id != "a3":
                evc["uni_a"]["proxy_port"] = evc["uni_z"]["proxy_port"] = pp_down
            evcs[evc_id] = evc
        cookies = {
            evc_id: utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
            for evc_id in evcs
        }
        int_manager.flow_builder.build_int_flows = MagicMock(
            return_value={cookie: [{"flow": {}}] for cookie in cookies.values()}
        )
        metadata = {"telemetry": {"enabled": True, "status": "UP", "status_reason": []}}

        await int_manager.install_int_flows(evcs, metadata)

        installed = int_manager._install_int_flows.call_args[0][0]
        by_status = {
            (
                call[0][1]["telemetry"]["status"],
                tuple(call[0][1]["telemetry"]["status_reason"]),
            ): sorted(call[0][0])
            for call in api_mock.add_evcs_metadata.call_args_list
            if call[0][0]
        }
        if fallback:
            assert set(installed) == {cookies["a2"], cookies["a3"]}
            assert by_status == {
                ("DOWN", ("proxy_port_down",)): ["a1", "a4"],
                ("UP", ()): ["a2", "a3"],
            }
        else:
            assert set(installed) == set(cookies.values())
            assert by_status == {
                ("DOWN", ("proxy_port_down",)): ["a1"],
                ("DOWN", ("no_flows",)): ["a4"],
                ("UP", ()): ["a2", "a3"],
            }

    @pytest.mark.parametrize(
        "pp_metadata,proxy_port_enabled",
        [(False, None), (True, False)],
    )
    async def test_handle_partial_flows_without_proxy_port_installs_int(
        self, monkeypatch, pp_metadata, proxy_port_enabled
    ) -> None:
        """Proxy ports are optional: an EVC not using one, either no proxy
        port metadata on its UNIs or proxy_port_enabled false, gets its INT
        flows on a partial flows event whatever a loop's status."""
        int_manager, api_mock = self._pp_int_manager(
            monkeypatch, EntityStatus.DOWN, pp_metadata=pp_metadata
        )

        await int_manager.handle_partial_flows(
            {"1": self._pp_evc(proxy_port_enabled=proxy_port_enabled)},
            "kytos/mef_eline.static.ingress_swapped",
        )

        assert int_manager._install_int_flows.call_count == 1
        int_manager._remove_int_flows_by_cookies.assert_not_called()
        api_mock.add_evcs_metadata.assert_not_called()

    async def test_handle_pp_link_down(self, monkeypatch):
        """Test test_handle_pp_link_down."""
        int_manager = INTManager(MagicMock())
        api_mock, link_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        link_mock.endpoint_a.id = "some_intf_id"
        evc_id = "3766c105686748"
        int_manager.srcs_pp[link_mock.endpoint_a.id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        down_id, failed_id = "3766c105686749", "3766c10568674a"
        pp_mock.evc_ids = {evc_id, down_id, failed_id}
        api_mock.get_evcs.return_value = {
            evc_id: {"metadata": {"telemetry": {"status": "UP"}}},
            down_id: {
                "metadata": {
                    "telemetry": {"status": "DOWN", "status_reason": ["uni_down"]}
                }
            },
            failed_id: {
                "metadata": {
                    "telemetry": {
                        "enabled": True,
                        "status": "DOWN",
                        "status_reason": ["flows_install_failed"],
                    }
                }
            },
        }
        int_manager.remove_int_flows = AsyncMock()

        await int_manager.handle_pp_link_down(link_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
        }
        assert int_manager.remove_int_flows.call_count == 1
        args = int_manager.remove_int_flows.call_args[0]
        assert sorted(args[0]) == sorted([evc_id, failed_id])
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

    @staticmethod
    def _pp_link_up_int_manager(monkeypatch) -> tuple:
        """An INTManager with one DOWN INT EVC on an UP proxy port, and the
        link that came back UP."""
        int_manager = INTManager(MagicMock())
        api_mock, link_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        link_mock.endpoint_a.id = "3"
        link_mock.status = EntityStatus.UP
        link_mock.status_reason = []
        pp_mock.status = EntityStatus.UP
        evc_id = "3766c105686748"
        pp_mock.evc_ids = {evc_id}
        int_manager.srcs_pp["3"] = pp_mock
        int_manager.srcs_pp["5"] = pp_mock
        int_manager.unis_src["1"] = "3"
        int_manager.unis_src["2"] = "5"
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {
            evc_id: {
                "active": True,
                "archived": False,
                "uni_a": {"interface_id": "1"},
                "uni_z": {"interface_id": "2"},
            }
        }
        int_manager.install_int_flows = AsyncMock()
        int_manager._validate_map_enable_evcs = MagicMock(side_effect=lambda e, **_: e)
        return int_manager, link_mock, evc_id

    async def test_handle_pp_link_up_waits_evc_lock(self, monkeypatch):
        """Reinstalling INT on a proxy port link up waits for the EVC lock,
        else it can interleave with handle_partial_flows (a static swap) and
        put back INT flows built from the EVC's previous flows."""
        int_manager, link_mock, evc_id = self._pp_link_up_int_manager(monkeypatch)

        async with int_manager._evcs_lock[evc_id]:
            task = asyncio.create_task(int_manager.handle_pp_link_up(link_mock))
            for _ in range(5):
                await asyncio.sleep(0)
            int_manager.install_int_flows.assert_not_called()
        await task
        assert int_manager.install_int_flows.call_count == 1

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
        int_manager.disable_int = AsyncMock()

        await int_manager.handle_pp_metadata_removed(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {
            "metadata.telemetry.enabled": "true",
        }
        assert int_manager.disable_int.call_count == 1
        args = int_manager.disable_int.call_args[0]
        assert evc_id in args[0]

    async def test_handle_pp_metadata_removed_pp_down(self, monkeypatch):
        """Test handle_pp_metadata_removed on an EVC DOWN due to proxy_port_down."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        intf_mock.metadata = {}
        source_id = "some_source_id"
        evc_id, other_evc_id = "3766c105686748", "3766c105686749"
        int_manager.unis_src[intf_mock.id] = source_id
        int_manager.srcs_pp[source_id] = pp_mock
        pp_mock.evc_ids = {evc_id}

        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        telemetry_down = {
            "enabled": True,
            "status": "DOWN",
            "status_reason": ["proxy_port_down"],
        }
        evcs = {
            _id: {"id": _id, "metadata": {"telemetry": telemetry_down}}
            for _id in (evc_id, other_evc_id)
        }
        api_mock.get_evcs.return_value = evcs
        int_manager.disable_int = AsyncMock()

        await int_manager.handle_pp_metadata_removed(intf_mock)
        assert api_mock.get_evcs.call_args[1] == {"metadata.telemetry.enabled": "true"}
        assert int_manager.disable_int.call_count == 1
        args, kwargs = int_manager.disable_int.call_args
        assert list(args[0]) == [evc_id]
        assert kwargs == {"force": True, "reason": "proxy_port_metadata_removed"}

    async def test_handle_pp_metadata_added(self, monkeypatch):
        """Test handle_pp_metadata_added."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        intf_mock.metadata = {"proxy_port": 2}
        evc_id = "3766c105686748"
        pp_mock.evc_ids = {evc_id}
        int_manager.get_proxy_port_or_raise = MagicMock()
        int_manager.get_proxy_port_or_raise.return_value = pp_mock

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

    async def test_handle_pp_metadata_added_evcs_with_no_pp(self, monkeypatch):
        """Test handle_pp_metadata_added with existing evcs with no pp."""
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        intf_mock.metadata = {"proxy_port": 2}
        evc_id = "3766c105686748"
        pp_mock.evc_ids = {}
        int_manager.get_proxy_port_or_raise = MagicMock()
        int_manager.get_proxy_port_or_raise.return_value = pp_mock

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {
            evc_id: {
                "uni_a": {"interface_id": "some_intf_id"},
                "uni_z": {"interface_id": "another_intf_id"},
            }
        }
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
        int_manager.get_proxy_port_or_raise = MagicMock()
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

    async def test_handle_pp_metadata_added_exc_port_shared(self, monkeypatch):
        """Test handle_pp_metadata_added exception port shared."""
        log_mock = MagicMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.log", log_mock)
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        intf_mock.metadata = {"proxy_port": 2}
        evc_id = "3766c105686748"
        int_manager.get_proxy_port_or_raise = MagicMock()
        pp_mock.evc_ids = {evc_id}
        int_manager.get_proxy_port_or_raise.return_value = pp_mock

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {evc_id: {}}
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()
        int_manager.enable_int.side_effect = ProxyPortShared(evc_id, "shared")

        await int_manager.handle_pp_metadata_added(intf_mock)
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_count == 1
        assert api_mock.get_evcs.call_args[1] == {"metadata.telemetry.enabled": "true"}
        assert int_manager.disable_int.call_count == 1
        assert int_manager.enable_int.call_count == 1

        assert api_mock.add_evcs_metadata.call_count == 1
        assert log_mock.error.call_count == 1

    async def test_handle_pp_metadata_added_enable_exc_only_affected_evcs(
        self, monkeypatch
    ):
        """Test that only affected_evcs are passed to add_evcs_metadata."""
        log_mock = MagicMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.log", log_mock)
        int_manager = INTManager(MagicMock())
        api_mock, intf_mock, pp_mock = AsyncMock(), MagicMock(), MagicMock()
        intf_mock.id = "some_intf_id"
        intf_mock.metadata = {"proxy_port": 2}

        evc_a_id = "3766c105686748"
        evc_b_id = "aabbcc112233dd"
        evc_a_data = {
            "uni_a": {"interface_id": "some_intf_id"},
            "uni_z": {"interface_id": "other_intf_id"},
        }
        evc_b_data = {
            "uni_a": {"interface_id": "unrelated_a"},
            "uni_z": {"interface_id": "unrelated_z"},
        }

        int_manager.get_proxy_port_or_raise = MagicMock()
        pp_mock.evc_ids = {evc_a_id}
        int_manager.get_proxy_port_or_raise.return_value = pp_mock

        assert "proxy_port" in intf_mock.metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        api_mock.get_evcs.return_value = {
            evc_a_id: evc_a_data,
            evc_b_id: evc_b_data,
        }
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock()
        int_manager.enable_int.side_effect = ProxyPortShared(evc_a_id, "shared")

        await int_manager.handle_pp_metadata_added(intf_mock)

        assert int_manager.disable_int.call_count == 1
        assert int_manager.disable_int.call_args[0][0] == {evc_a_id: evc_a_data}
        assert int_manager.enable_int.call_count == 1
        assert int_manager.enable_int.call_args[0][0] == {evc_a_id: evc_a_data}

        assert api_mock.add_evcs_metadata.call_count == 1
        evcs_arg = api_mock.add_evcs_metadata.call_args[0][0]
        assert evcs_arg == {evc_a_id: evc_a_data}
        metadata_arg = api_mock.add_evcs_metadata.call_args[0][1]
        assert metadata_arg["telemetry"]["enabled"] is False
        assert metadata_arg["telemetry"]["status"] == "DOWN"

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
        evc_id = "3766c105686749"
        int_manager._remove_int_flows_by_cookies = AsyncMock()
        evcs = {
            evc_id: {
                "active": True,
                "uni_a": MagicMock(),
                "uni_z": MagicMock(),
                "id": evc_id,
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
        assert int_manager._remove_int_flows_by_cookies.call_count == 1
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

    def test_validate_dedicated_proxy_port_evcs(self) -> None:
        """Test _validate_intra_evc_different_proxy_ports."""
        pp_a, pp_z, controller = MagicMock(), MagicMock(), MagicMock()
        evc = {
            "id": "some_id",
            "uni_a": {"proxy_port": pp_a, "interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"proxy_port": pp_z, "interface_id": "00:00:00:00:00:00:00:01:2"},
        }

        int_manager = INTManager(controller)
        int_manager._validate_dedicated_proxy_port_evcs({evc["id"]: evc})

        source = MagicMock()
        pp_a.source, pp_z.source = source, source
        with pytest.raises(ProxyPortShared):
            int_manager._validate_dedicated_proxy_port_evcs({evc["id"]: evc})

    def test_validate_proxy_ports_symmetry_inter_evc(self) -> None:
        """Test _validate_proxy_ports_symmetry for inter evc."""
        evc = {
            "id": "some_id",
            "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"interface_id": "00:00:00:00:00:00:00:03:1"},
        }

        controller = MagicMock()
        int_manager = INTManager(controller)

        # no proxy ports case
        int_manager._validate_proxy_ports_symmetry(evc)

        # one proxy port, asymmetric case
        pp_a = MagicMock()
        evc["uni_a"]["proxy_port"] = pp_a
        with pytest.raises(exceptions.ProxyPortAsymmetric):
            int_manager._validate_proxy_ports_symmetry(evc)

        # one proxy port, still asymmetric case
        pp_z = MagicMock()
        evc["uni_a"].pop("proxy_port")
        evc["uni_z"]["proxy_port"] = pp_z
        with pytest.raises(exceptions.ProxyPortAsymmetric):
            int_manager._validate_proxy_ports_symmetry(evc)

        # symmetric case
        evc["uni_a"]["proxy_port"] = pp_a
        int_manager._validate_proxy_ports_symmetry(evc)

        # cover ProxyPortRequired for inter EVC with metadata
        evc["uni_a"].pop("proxy_port")
        evc["uni_z"].pop("proxy_port")
        evc["metadata"] = {"proxy_port_enabled": True}
        with pytest.raises(exceptions.ProxyPortRequired) as exc:
            int_manager._validate_proxy_ports_symmetry(evc)
        assert "proxy_port_enabled" in str(exc)

    def test_validate_proxy_ports_symmetry_intra_evc(self) -> None:
        """Test _validate_proxy_ports_symmetry intra evc."""
        evc = {
            "id": "some_id",
            "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"interface_id": "00:00:00:00:00:00:00:01:2"},
        }

        controller = MagicMock()
        int_manager = INTManager(controller)

        # no proxy ports case
        with pytest.raises(exceptions.ProxyPortRequired) as exc:
            int_manager._validate_proxy_ports_symmetry(evc)
        assert "intra-EVC must use proxy ports" in str(exc)

        # one proxy port, asymmetric case
        pp_a = MagicMock()
        evc["uni_a"]["proxy_port"] = pp_a
        with pytest.raises(exceptions.ProxyPortAsymmetric):
            int_manager._validate_proxy_ports_symmetry(evc)

        # one proxy port, still asymmetric case
        pp_z = MagicMock()
        evc["uni_a"].pop("proxy_port")
        evc["uni_z"]["proxy_port"] = pp_z
        with pytest.raises(exceptions.ProxyPortAsymmetric):
            int_manager._validate_proxy_ports_symmetry(evc)

        # symmetric case
        evc["uni_a"]["proxy_port"] = pp_a
        int_manager._validate_proxy_ports_symmetry(evc)

    def test_validate_dedicated_proxy_port_evcs_existing(self) -> None:
        """Test _validate_intra_evc_different_proxy_ports existing."""
        pp_a, pp_z, controller = MagicMock(), MagicMock(), MagicMock()
        evc = {
            "id": "some_id",
            "uni_a": {"proxy_port": pp_a, "interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"proxy_port": pp_z, "interface_id": "00:00:00:00:00:00:00:01:2"},
        }

        int_manager = INTManager(controller)
        int_manager.unis_src["00:00:00:00:00:00:00:01:3"] = pp_a.source.id
        with pytest.raises(ProxyPortShared):
            int_manager._validate_dedicated_proxy_port_evcs({evc["id"]: evc})

    async def test__remove_int_flows_by_cookies(
        self, inter_evc_evpl_flows_data, monkeypatch
    ) -> None:
        """test _remove_int_flows_by_cookies."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(get_controller_mock())
        assert len(inter_evc_evpl_flows_data) == 3
        res = await int_manager._remove_int_flows_by_cookies(inter_evc_evpl_flows_data)
        assert len(res) == 3
        for flows in res.values():
            for flow in flows:
                assert "cookie_mask" in flow
                assert flow["cookie_mask"] == int(0xFFFFFFFFFFFFFFFF)
                assert flow["table_id"] == 0xFF
                assert flow["owner"] == "telemetry_int"
        api_mock.send_flows.assert_awaited_once_with(res, "delete")

    async def test__remove_int_flows(
        self, inter_evc_evpl_flows_data, monkeypatch
    ) -> None:
        """test _remove_int_flows."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(get_controller_mock())
        assert len(inter_evc_evpl_flows_data) == 3
        res = await int_manager._remove_int_flows(inter_evc_evpl_flows_data)
        assert len(res) == 3
        api_mock.send_flows.assert_awaited_once_with(res, "delete")

    async def test__install_int_flows(self, inter_evc_evpl_flows_data, monkeypatch):
        """test__install_int_flows."""
        sleep_mock = AsyncMock()
        monkeypatch.setattr("asyncio.sleep", sleep_mock)
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(get_controller_mock())
        assert len(inter_evc_evpl_flows_data) == 3
        res = await int_manager._install_int_flows(inter_evc_evpl_flows_data)
        assert len(res) == 3
        api_mock.send_flows.assert_awaited_once_with(res, "install")
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
        int_manager.unis_src[intf_id_a] = "a"
        int_manager.unis_src[intf_id_z] = "z"
        int_manager.srcs_pp[int_manager.unis_src[intf_id_a]] = pp
        int_manager.srcs_pp[int_manager.unis_src[intf_id_z]] = pp
        int_manager._discard_pps_evc_ids(evcs)
        assert pp.evc_ids.discard.call_count == 2
        pp.evc_ids.discard.assert_called_with(evc_id)

    def test__discard_pps_evc_ids_evc_not_found(self):
        """test_discard_pps_evc_ids with an EVC not found."""
        evc_id = "3766c105686749"
        controller = get_controller_mock()
        int_manager = INTManager(controller)
        pp = MagicMock()
        int_manager.srcs_pp["a"] = pp
        int_manager._discard_pps_evc_ids({evc_id: {}})
        assert not pp.evc_ids.discard.call_count

    async def test_disable_int_force_evc_not_found(self, monkeypatch) -> None:
        """Test force disable INT on an EVC not found."""
        controller = MagicMock()
        api_mock = AsyncMock()
        api_mock.get_stored_flows.return_value = {}
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        evc_id = "aaaaaaaaaaaaaa"
        int_manager = INTManager(controller)
        int_manager._remove_int_flows_by_cookies = AsyncMock()
        await int_manager.disable_int({evc_id: {}}, force=True)

        api_mock.get_stored_flows.assert_awaited_with(
            [utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX)]
        )
        assert int_manager._remove_int_flows_by_cookies.call_count == 1
        assert api_mock.add_evcs_metadata.call_count == 1
        assert api_mock.add_evcs_metadata.call_args[0][0] == {evc_id: {}}
        assert api_mock.add_evcs_metadata.call_args[0][2] is True

    async def test_disable_int_evc_not_found(self) -> None:
        """Test disable INT on an EVC not found without force."""
        int_manager = INTManager(MagicMock())
        with pytest.raises(exceptions.EVCNotFound):
            await int_manager.disable_int({"aaaaaaaaaaaaaa": {}}, force=False)

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

    async def test__send_flows(self, monkeypatch) -> None:
        """Test _send_flows."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(get_controller_mock())
        switch_flows = {"dpid": [MagicMock()]}
        await int_manager._send_flows(switch_flows, "install")
        api_mock.send_flows.assert_awaited_once_with(switch_flows, "install")

    @pytest.mark.parametrize(
        "exc",
        [
            exceptions.UnrecoverableError("404 dpid not found"),
            RetryError(MagicMock()),
        ],
    )
    async def test__send_flows_error_logged_and_raised(self, monkeypatch, exc):
        """A failed send logs the EVC ids of its flows and is raised."""
        api_mock, log_mock = AsyncMock(), MagicMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.log", log_mock)
        api_mock.send_flows.side_effect = exc
        int_manager = INTManager(get_controller_mock())
        switch_flows = {
            "dpid_a": [{"cookie": 0xA83766C105686749}, {"cookie": 0xA83766C105686748}],
            "dpid_b": [{"cookie": 0xA83766C105686749}],
        }
        with pytest.raises(exceptions.FlowsSendError) as raised:
            await int_manager._send_flows(switch_flows, "delete")
        assert raised.value.__cause__ is exc
        assert raised.value.evc_ids == {"3766c105686748", "3766c105686749"}
        assert "['3766c105686748', '3766c105686749']" in str(raised.value)
        assert log_mock.error.call_count == 1
        msg = log_mock.error.call_args[0][0]
        assert "Failed to delete INT flows" in msg
        assert "['3766c105686748', '3766c105686749']" in msg

    async def test_disable_int_waits_enable_flows_stored(self, monkeypatch) -> None:
        """A disable_int waiting on the EVC lock while enable_int installs only
        reads the stored flows once flow_manager has stored the installed ones,
        so it removes them all (kytos-ng/telemetry_int#189).

        flow_manager is modeled storing the flows only when the gate opens."""
        api_mock, stored_flows_mock = AsyncMock(), AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr(
            "napps.kytos.telemetry_int.utils.get_found_stored_flows", stored_flows_mock
        )
        int_manager = INTManager(MagicMock())
        evc_id, dpid = "3766c105686749", "00:00:00:00:00:00:00:01"
        int_cookie = utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX)
        mef_cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
        int_flow = {"cookie": int_cookie, "table_id": 0, "priority": 20100}
        evc = {
            "id": evc_id,
            "active": True,
            "uni_a": MagicMock(),
            "uni_z": MagicMock(),
        }
        int_manager._validate_map_enable_evcs = MagicMock(return_value={evc_id: evc})
        int_manager._add_pps_evc_ids = MagicMock()
        int_manager._discard_pps_evc_ids = MagicMock()
        int_manager.flow_builder.build_int_flows = MagicMock(
            return_value={mef_cookie: [{"switch": dpid, "flow": int_flow}]}
        )

        stored, sent, gate = {}, [], asyncio.Event()

        async def send_flows(switch_flows, cmd):
            if not any(switch_flows.values()):
                return
            assert int_manager._evcs_lock[evc_id].locked()
            await gate.wait()
            sent.append((cmd, copy.deepcopy(dict(switch_flows))))
            if cmd == "install":
                stored[int_cookie] = [
                    {"switch": sw, "flow": flow}
                    for sw, flows in switch_flows.items()
                    for flow in flows
                ]
            else:
                stored.clear()

        async def get_stored_flows(cookies):
            return {k: list(v) for k, v in stored.items() if k in cookies}

        api_mock.send_flows.side_effect = send_flows
        api_mock.get_stored_flows.side_effect = get_stored_flows

        enable = asyncio.create_task(int_manager.enable_int({evc_id: evc}))
        for _ in range(5):
            await asyncio.sleep(0)
        disable = asyncio.create_task(
            int_manager.disable_int({evc_id: evc}, force=True)
        )
        for _ in range(5):
            await asyncio.sleep(0)
        assert api_mock.get_stored_flows.call_count == 1
        assert not sent

        gate.set()
        await asyncio.gather(enable, disable)

        assert api_mock.get_stored_flows.call_count == 2
        assert [cmd for cmd, _ in sent] == ["install", "delete"]
        assert sent[0][1] == {dpid: [int_flow]}
        assert [flow["cookie"] for flow in sent[1][1][dpid]] == [int_cookie]
        assert not stored

    async def test_list_expected_flows_intra_evc(
        self, monkeypatch, evcs_data, intra_evc_evpl_flows_data
    ) -> None:
        """Test list expected flows for intra-switch EVC."""
        controller = get_controller_mock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        evc_id = "3766c105686749"
        evcs = {evc_id: evcs_data[evc_id]}

        int_manager._validate_map_enable_evcs = MagicMock(return_value=evcs)

        cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
        stored_flows = {cookie: intra_evc_evpl_flows_data}
        api_mock.get_stored_flows.return_value = stored_flows

        dpid = "00:00:00:00:00:00:00:01"
        mock_switch = get_switch_mock(dpid, 0x04)
        mock_switch.id = dpid
        controller.get_switch_by_dpid = MagicMock(return_value=mock_switch)

        mock_flows = {
            cookie: [
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 1,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
            ]
        }
        int_manager.flow_builder.build_int_flows = MagicMock(return_value=mock_flows)

        result = await int_manager.list_expected_flows(evcs)

        assert evc_id in result
        assert "count_total" in result[evc_id]
        assert "count_table" in result[evc_id]
        assert "flows" in result[evc_id]
        assert isinstance(result[evc_id]["count_total"], int)
        assert isinstance(result[evc_id]["count_table"], dict)
        assert isinstance(result[evc_id]["flows"], list)

        for flow in result[evc_id]["flows"]:
            assert "switch" in flow
            assert "flow" in flow
            assert "flow_id" in flow
            assert "id" in flow
            assert "inserted_at" not in flow
            assert "updated_at" not in flow
            assert "state" not in flow

    async def test_list_expected_flows_inter_evc(
        self, monkeypatch, evcs_data, inter_evc_evpl_flows_data
    ) -> None:
        """Test list expected flows for inter-switch EVC."""
        controller = get_controller_mock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        evc_id = "16a76ae61b2f46"
        evcs = {evc_id: evcs_data[evc_id]}

        int_manager._validate_map_enable_evcs = MagicMock(return_value=evcs)

        cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
        stored_flows = {cookie: inter_evc_evpl_flows_data}
        api_mock.get_stored_flows.return_value = stored_flows

        dpid1 = "00:00:00:00:00:00:00:01"
        dpid2 = "00:00:00:00:00:00:00:02"
        mock_switch1 = get_switch_mock(dpid1, 0x04)
        mock_switch1.id = dpid1
        mock_switch2 = get_switch_mock(dpid2, 0x04)
        mock_switch2.id = dpid2

        def get_switch_by_dpid(dpid):
            return mock_switch1 if dpid == dpid1 else mock_switch2

        controller.get_switch_by_dpid = MagicMock(side_effect=get_switch_by_dpid)

        mock_flows = {
            cookie: [
                {
                    "switch": dpid1,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
                {
                    "switch": dpid2,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
            ]
        }
        int_manager.flow_builder.build_int_flows = MagicMock(return_value=mock_flows)

        result = await int_manager.list_expected_flows(evcs)

        assert evc_id in result
        assert "count_total" in result[evc_id]
        assert "count_table" in result[evc_id]
        assert "flows" in result[evc_id]
        assert len(result[evc_id]["flows"]) == 2

        for flow in result[evc_id]["flows"]:
            assert "switch" in flow
            assert "flow" in flow
            assert "flow_id" in flow
            assert "id" in flow
            assert "inserted_at" not in flow
            assert "updated_at" not in flow
            assert "state" not in flow

    async def test_list_expected_flows_multiple_evcs(
        self, monkeypatch, evcs_data, intra_evc_evpl_flows_data
    ) -> None:
        """Test list expected flows for multiple EVCs."""
        controller = get_controller_mock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        evc_id_intra = "3766c105686749"
        evc_id_inter = "16a76ae61b2f46"
        evcs = {
            evc_id_intra: evcs_data[evc_id_intra],
            evc_id_inter: evcs_data[evc_id_inter],
        }

        int_manager._validate_map_enable_evcs = MagicMock(return_value=evcs)

        cookie_intra = utils.get_cookie(evc_id_intra, settings.MEF_COOKIE_PREFIX)
        cookie_inter = utils.get_cookie(evc_id_inter, settings.MEF_COOKIE_PREFIX)
        stored_flows = {
            cookie_intra: intra_evc_evpl_flows_data,
            cookie_inter: intra_evc_evpl_flows_data,
        }
        api_mock.get_stored_flows.return_value = stored_flows

        dpid = "00:00:00:00:00:00:00:01"
        mock_switch = get_switch_mock(dpid, 0x04)
        mock_switch.id = dpid
        controller.get_switch_by_dpid = MagicMock(return_value=mock_switch)

        mock_flows = {
            cookie_intra: [
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie_intra,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                }
            ],
            cookie_inter: [
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie_inter,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                }
            ],
        }
        int_manager.flow_builder.build_int_flows = MagicMock(return_value=mock_flows)

        result = await int_manager.list_expected_flows(evcs)

        assert evc_id_intra in result
        assert evc_id_inter in result
        assert len(result) == 2

    async def test_list_expected_flows_count_tables(
        self, monkeypatch, evcs_data, intra_evc_evpl_flows_data
    ) -> None:
        """Test list expected flows counts flows per table correctly."""
        controller = get_controller_mock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        evc_id = "3766c105686749"
        evcs = {evc_id: evcs_data[evc_id]}

        int_manager._validate_map_enable_evcs = MagicMock(return_value=evcs)

        cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
        stored_flows = {cookie: intra_evc_evpl_flows_data}
        api_mock.get_stored_flows.return_value = stored_flows

        dpid = "00:00:00:00:00:00:00:01"
        mock_switch = get_switch_mock(dpid, 0x04)
        mock_switch.id = dpid
        controller.get_switch_by_dpid = MagicMock(return_value=mock_switch)

        mock_flows = {
            cookie: [
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 0,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
                {
                    "switch": dpid,
                    "flow": {
                        "table_id": 1,
                        "cookie": cookie,
                        "priority": 20000,
                        "match": {},
                        "actions": [],
                    },
                    "inserted_at": "2023-09-15T13:11:53.162000",
                    "updated_at": "2023-09-15T13:11:53.184000",
                    "state": "installed",
                },
            ]
        }
        int_manager.flow_builder.build_int_flows = MagicMock(return_value=mock_flows)

        result = await int_manager.list_expected_flows(evcs)

        count_table = result[evc_id]["count_table"]
        flows = result[evc_id]["flows"]

        table_count = {}
        for flow in flows:
            table_id = flow["flow"]["table_id"]
            table_count[table_id] = table_count.get(table_id, 0) + 1

        for table_id, count in count_table.items():
            assert table_count[table_id] == count

        assert result[evc_id]["count_total"] == len(flows)

    async def test_check_consistency_disable_only_inconsistent(
        self, monkeypatch
    ) -> None:
        """Test check_consistency with inconsistent_action='disable' only
        disables the inconsistent EVCs, not all EVCs.

        Regression test for the fix where disable_int was called with all
        evcs instead of only to_disable.
        """
        controller = MagicMock()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)

        int_manager = INTManager(controller)
        int_manager._validate_map_enable_evcs = MagicMock(side_effect=lambda e, **kw: e)
        int_manager.disable_int = AsyncMock()

        consistent_evc_id = "3766c105686749"
        inconsistent_evc_id = "16a76ae61b2f46"
        evcs = {
            consistent_evc_id: {
                "id": consistent_evc_id,
                "service_level": 6,
            },
            inconsistent_evc_id: {
                "id": inconsistent_evc_id,
                "service_level": 6,
            },
        }

        consistent_cookie = utils.get_cookie(
            consistent_evc_id, settings.INT_COOKIE_PREFIX
        )
        inconsistent_cookie = utils.get_cookie(
            inconsistent_evc_id, settings.INT_COOKIE_PREFIX
        )

        flow_id_a = "aaaa1111"
        flow_id_b = "bbbb2222"
        flow_id_alien = "cccc3333"

        # _list_expected_flows returns expected flows per evc_id
        async def mock_list_expected_flows(_evcs):
            return {
                consistent_evc_id: {
                    "flows": [{"flow_id": flow_id_a, "flow": {}, "switch": "dpid1"}],
                },
                inconsistent_evc_id: {
                    "flows": [{"flow_id": flow_id_b, "flow": {}, "switch": "dpid1"}],
                },
            }

        int_manager._list_expected_flows = mock_list_expected_flows

        # get_stored_flows returns stored flows per cookie
        # consistent EVC: stored matches expected
        # inconsistent EVC: stored has alien flow, missing expected flow
        api_mock.get_stored_flows.return_value = {
            consistent_cookie: [
                {"flow_id": flow_id_a, "flow": {}, "switch": "dpid1"},
            ],
            inconsistent_cookie: [
                {"flow_id": flow_id_alien, "flow": {}, "switch": "dpid1"},
            ],
        }

        result = await int_manager.check_consistency(
            evcs, inconsistent_action="disable"
        )

        # Both EVCs should be in results
        assert consistent_evc_id in result
        assert inconsistent_evc_id in result
        assert result[consistent_evc_id]["outcome"] == "consistent"
        assert result[inconsistent_evc_id]["outcome"] == "inconsistent"

        # The inconsistent EVC has missing and alien flows
        assert len(result[inconsistent_evc_id]["missing_flows"]) == 1
        assert result[inconsistent_evc_id]["missing_flows"][0]["flow_id"] == flow_id_b
        assert len(result[inconsistent_evc_id]["alien_flows"]) == 1
        assert result[inconsistent_evc_id]["alien_flows"][0]["flow_id"] == flow_id_alien

        # The consistent EVC has no missing or alien flows
        assert len(result[consistent_evc_id]["missing_flows"]) == 0
        assert len(result[consistent_evc_id]["alien_flows"]) == 0

        # disable_int must only be called with the inconsistent EVC
        assert int_manager.disable_int.call_count == 1
        args = int_manager.disable_int.call_args
        disabled_evcs = args[0][0]
        assert inconsistent_evc_id in disabled_evcs
        assert consistent_evc_id not in disabled_evcs
        assert args[1] == {"force": True, "reason": "consistency_check"}

    @staticmethod
    def _wait_gate(gate: asyncio.Event):
        """An async side effect waiting for gate."""

        async def wait(*_) -> None:
            await gate.wait()

        return wait

    @staticmethod
    def _metadata_calls(api_mock) -> list[tuple[list[str], dict]]:
        """add_evcs_metadata calls with EVCs, as (EVC ids, telemetry)."""
        return [
            (sorted(args[0]), args[1]["telemetry"])
            for args, _ in api_mock.add_evcs_metadata.call_args_list
            if args[0]
        ]

    async def test__remove_evcs_int_flows_metadata_after_flows(
        self, monkeypatch
    ) -> None:
        """Metadata is only set once the INT flows are removed."""
        gate = asyncio.Event()
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        int_manager._remove_int_flows_by_cookies = AsyncMock(
            side_effect=self._wait_gate(gate)
        )
        evcs = {"3766c105686748": self._pp_evc()}
        metadata = {"telemetry": {"enabled": False, "status": "DOWN"}}

        task = asyncio.create_task(int_manager._remove_evcs_int_flows(evcs, metadata))
        for _ in range(5):
            await asyncio.sleep(0)
        api_mock.add_evcs_metadata.assert_not_called()
        gate.set()
        await task

        assert self._metadata_calls(api_mock) == [
            (["3766c105686748"], metadata["telemetry"])
        ]

    async def test__remove_evcs_int_flows_failed(self, monkeypatch) -> None:
        """If removing fails, the EVCs with INT flows stored are set INT
        enabled DOWN flows_remove_failed instead of their metadata, the
        others still get it, and the error is raised."""
        failed_id, ok_id = "3766c105686748", "3766c105686749"
        api_mock = AsyncMock()
        api_mock.get_stored_flows.return_value = {
            utils.get_cookie(failed_id, settings.INT_COOKIE_PREFIX): [{"flow": {}}],
        }
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        int_manager._remove_int_flows_by_cookies = AsyncMock(
            side_effect=exceptions.FlowsSendError("boom", {failed_id})
        )
        evcs = {failed_id: self._pp_evc(), ok_id: self._pp_evc()}
        metadata = {"telemetry": {"enabled": False, "status": "DOWN"}}

        with pytest.raises(exceptions.FlowsSendError):
            await int_manager._remove_evcs_int_flows(evcs, metadata)

        calls = self._metadata_calls(api_mock)
        assert [ids for ids, _ in calls] == [[failed_id], [ok_id]]
        assert calls[0][1]["enabled"] is True
        assert calls[0][1]["status"] == "DOWN"
        assert calls[0][1]["status_reason"] == ["flows_remove_failed"]
        assert calls[1][1] == metadata["telemetry"]

    async def test_install_int_flows_metadata_after_flows(self, monkeypatch) -> None:
        """Metadata is only set once the INT flows are installed."""
        gate = asyncio.Event()
        evc_id = "3766c105686748"
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr(utils, "get_found_stored_flows", AsyncMock())
        int_manager = INTManager(MagicMock())
        int_manager._install_int_flows = AsyncMock(side_effect=self._wait_gate(gate))
        int_manager.flow_builder.build_int_flows = MagicMock(
            return_value={
                utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX): [{"flow": {}}]
            }
        )
        metadata = {"telemetry": {"enabled": True, "status": "UP", "status_reason": []}}

        task = asyncio.create_task(
            int_manager.install_int_flows({evc_id: self._pp_evc()}, metadata)
        )
        for _ in range(5):
            await asyncio.sleep(0)
        api_mock.add_evcs_metadata.assert_not_called()
        gate.set()
        await task

        assert self._metadata_calls(api_mock) == [([evc_id], metadata["telemetry"])]

    async def test_install_int_flows_failed(self, monkeypatch) -> None:
        """If installing fails, the EVCs with INT flows in it are set INT
        enabled DOWN flows_install_failed instead of their metadata, the
        others still get theirs, and the error is raised."""
        failed_id, inactive_id = "3766c105686748", "3766c105686749"
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr(utils, "get_found_stored_flows", AsyncMock())
        int_manager = INTManager(MagicMock())
        int_manager._install_int_flows = AsyncMock(
            side_effect=exceptions.FlowsSendError("boom", {failed_id})
        )
        int_manager.flow_builder.build_int_flows = MagicMock(
            return_value={
                utils.get_cookie(failed_id, settings.MEF_COOKIE_PREFIX): [{"flow": {}}]
            }
        )
        inactive = self._pp_evc()
        inactive["active"] = False
        evcs = {failed_id: self._pp_evc(), inactive_id: inactive}
        metadata = {"telemetry": {"enabled": True, "status": "UP", "status_reason": []}}

        with pytest.raises(exceptions.FlowsSendError):
            await int_manager.install_int_flows(evcs, metadata)

        calls = self._metadata_calls(api_mock)
        assert [(ids, t["status"], t["status_reason"]) for ids, t in calls] == [
            ([failed_id], "DOWN", ["flows_install_failed"]),
            ([inactive_id], "DOWN", ["no_flows"]),
        ]
        assert all(t["enabled"] for _, t in calls)

    async def test__set_flows_failed_metadata_error_logged(self, monkeypatch) -> None:
        """Failing to set the failed status is logged, not raised."""
        evc_id = "3766c105686748"
        api_mock, log_mock = AsyncMock(), MagicMock()
        api_mock.add_evcs_metadata.side_effect = exceptions.UnrecoverableError("x")
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr("napps.kytos.telemetry_int.utils.log", log_mock)
        int_manager = INTManager(MagicMock())

        failed = await int_manager._set_flows_failed(
            {evc_id: self._pp_evc(), "3766c105686749": self._pp_evc()},
            {evc_id},
            "flows_remove_failed",
        )

        assert list(failed) == [evc_id]
        assert log_mock.error.call_count == 1
        assert "flows_remove_failed" in log_mock.error.call_args[0][0]

    @pytest.mark.parametrize("method", ["enable_int", "redeploy_int"])
    async def test_remove_before_install_failed(self, monkeypatch, method) -> None:
        """If removing the INT flows before installing them fails, the EVCs
        are set INT enabled DOWN flows_remove_failed, nothing is installed,
        and the error is raised. An enabled EVC still gets its proxy ports
        tracked, so a proxy port link down still falls it back."""
        evc_id = "3766c105686748"
        api_mock = AsyncMock()
        api_mock.get_stored_flows.return_value = {
            utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX): [{"flow": {}}],
        }
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        int_manager._validate_map_enable_evcs = MagicMock(
            side_effect=lambda e, *_, **__: e
        )
        int_manager._validate_has_int = MagicMock()
        int_manager._add_pps_evc_ids = MagicMock()
        int_manager._remove_int_flows_by_cookies = AsyncMock(
            side_effect=exceptions.FlowsSendError("boom", {evc_id})
        )
        int_manager.install_int_flows = AsyncMock()
        evc, other = self._pp_evc(), self._pp_evc()

        with pytest.raises(exceptions.FlowsSendError):
            await getattr(int_manager, method)({evc_id: evc, "3766c105686749": other})

        int_manager.install_int_flows.assert_not_called()
        calls = self._metadata_calls(api_mock)
        assert [(ids, t["status_reason"]) for ids, t in calls] == [
            ([evc_id], ["flows_remove_failed"])
        ]
        if method == "enable_int":
            int_manager._add_pps_evc_ids.assert_called_once_with({evc_id: evc})

    async def test_enable_int_evc_error_pps_not_tracked(self, monkeypatch) -> None:
        """An EVC that fails validation while installing, e.g. FlowsNotFound,
        has nothing to fall back, so its proxy ports aren't tracked."""
        api_mock = AsyncMock()
        api_mock.get_stored_flows.return_value = {}
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        int_manager._validate_map_enable_evcs = MagicMock(
            side_effect=lambda e, *_, **__: e
        )
        int_manager._add_pps_evc_ids = MagicMock()
        int_manager._remove_int_flows_by_cookies = AsyncMock()
        int_manager.install_int_flows = AsyncMock(
            side_effect=exceptions.FlowsNotFound("3766c105686748")
        )

        with pytest.raises(exceptions.FlowsNotFound):
            await int_manager.enable_int({"3766c105686748": self._pp_evc()})

        int_manager._add_pps_evc_ids.assert_not_called()

    @staticmethod
    def _consistency_int_manager(monkeypatch, evc_id, status_reason, stored=True):
        """An INTManager whose EVC expects one INT flow, stored or not, with
        an INT status_reason, and its api mock."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        int_manager._validate_map_enable_evcs = MagicMock(side_effect=lambda e, **_: e)
        int_manager.redeploy_int = AsyncMock()
        int_manager._install_int_flows = AsyncMock()
        int_manager._remove_int_flows = AsyncMock()
        flow = {"flow_id": "aaaa1111", "flow": {}, "switch": "dpid1"}
        int_manager._list_expected_flows = AsyncMock(
            return_value={evc_id: {"flows": [flow]}}
        )
        cookie = utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX)
        api_mock.get_stored_flows.return_value = {cookie: [flow] if stored else []}
        evc = {
            "id": evc_id,
            "service_level": 6,
            "active": True,
            "uni_a": {"interface_id": "00:00:00:00:00:00:00:01:1"},
            "uni_z": {"interface_id": "00:00:00:00:00:00:00:03:1"},
            "metadata": {
                "telemetry": {
                    "enabled": True,
                    "status": "DOWN" if status_reason else "UP",
                    "status_reason": status_reason,
                }
            },
        }
        return int_manager, api_mock, {evc_id: evc}

    @pytest.mark.parametrize("active", [True, False])
    @pytest.mark.parametrize("action", [None, "fix", "redeploy", "disable"])
    @pytest.mark.parametrize(
        "status_reason", [["flows_install_failed"], ["flows_remove_failed"]]
    )
    async def test_check_consistency_flows_failed_flows_match(
        self, monkeypatch, action, status_reason, active
    ) -> None:
        """An EVC whose INT flows failed to be sent but match is consistent,
        it's still returned, filtering for inconsistent ones, since its status
        is wrong. With inconsistent_action fix or redeploy only its status is
        set, the one installing its INT flows sets, no flow is sent."""
        evc_id = "3766c105686748"
        int_manager, api_mock, evcs = self._consistency_int_manager(
            monkeypatch, evc_id, status_reason
        )
        evcs[evc_id]["active"] = active
        int_manager.disable_int = AsyncMock()

        result = await int_manager.check_consistency(
            evcs, outcome="inconsistent", inconsistent_action=action
        )

        assert result[evc_id]["outcome"] == "consistent"
        assert result[evc_id]["status_reason"] == status_reason
        int_manager._install_int_flows.assert_not_called()
        int_manager._remove_int_flows.assert_not_called()
        int_manager.redeploy_int.assert_not_called()
        int_manager.disable_int.assert_not_called()
        calls = self._metadata_calls(api_mock)
        if action in ("fix", "redeploy"):
            status = ("UP", []) if active else ("DOWN", ["no_flows"])
            assert [(ids, t["status"], t["status_reason"]) for ids, t in calls] == [
                ([evc_id], *status)
            ]
            assert calls[0][1]["enabled"] is True
        else:
            assert not calls

    @pytest.mark.parametrize("fallback", [True, False])
    @pytest.mark.parametrize("action", ["fix", "redeploy"])
    async def test_check_consistency_flows_failed_flows_match_pp_down(
        self, monkeypatch, action, fallback
    ) -> None:
        """An EVC whose INT flows failed to be sent but match, with a proxy
        port down, is redeployed with FALLBACK_TO_MEF_LOOP_DOWN, so it falls
        back to mef_eline removing its INT flows, else only its status is set
        DOWN proxy_port_down."""
        evc_id = "3766c105686748"
        int_manager, api_mock, evcs = self._consistency_int_manager(
            monkeypatch, evc_id, ["flows_install_failed"]
        )
        monkeypatch.setattr(settings, "FALLBACK_TO_MEF_LOOP_DOWN", fallback)
        pp = MagicMock(status=EntityStatus.DOWN)
        evcs[evc_id]["uni_a"]["proxy_port"] = pp
        evcs[evc_id]["uni_z"]["proxy_port"] = pp

        result = await int_manager.check_consistency(
            evcs, outcome="inconsistent", inconsistent_action=action
        )

        assert result[evc_id]["outcome"] == "consistent"
        int_manager._install_int_flows.assert_not_called()
        int_manager._remove_int_flows.assert_not_called()
        calls = self._metadata_calls(api_mock)
        if fallback:
            int_manager.redeploy_int.assert_awaited_once_with(evcs)
            assert not calls
        else:
            int_manager.redeploy_int.assert_not_called()
            assert [(ids, t["status"], t["status_reason"]) for ids, t in calls] == [
                ([evc_id], "DOWN", ["proxy_port_down"])
            ]

    @pytest.mark.parametrize("action", [None, "fix", "redeploy"])
    async def test_check_consistency_flows_failed_flows_mismatch(
        self, monkeypatch, action
    ) -> None:
        """An EVC whose INT flows failed to be sent and don't match is
        inconsistent, and it's redeployed with inconsistent_action fix or
        redeploy, which also sets its status, instead of fixing its flows."""
        evc_id = "3766c105686748"
        int_manager, api_mock, evcs = self._consistency_int_manager(
            monkeypatch, evc_id, ["flows_install_failed"], stored=False
        )

        result = await int_manager.check_consistency(
            evcs, outcome="inconsistent", inconsistent_action=action
        )

        assert result[evc_id]["outcome"] == "inconsistent"
        assert result[evc_id]["status_reason"] == ["flows_install_failed"]
        int_manager._install_int_flows.assert_not_called()
        api_mock.add_evcs_metadata.assert_not_called()
        if action:
            int_manager.redeploy_int.assert_awaited_once_with(evcs)
        else:
            int_manager.redeploy_int.assert_not_called()

    async def test_check_consistency_consistent_status_reason(
        self, monkeypatch
    ) -> None:
        """An EVC with its flows and no failed status is consistent."""
        evc_id = "3766c105686748"
        int_manager, _, evcs = self._consistency_int_manager(monkeypatch, evc_id, [])

        result = await int_manager.check_consistency(
            evcs, outcome="consistent", inconsistent_action="fix"
        )

        assert result[evc_id]["outcome"] == "consistent"
        assert result[evc_id]["status_reason"] == []
        int_manager.redeploy_int.assert_not_called()

    async def test_check_consistency_fix_failed(self, monkeypatch) -> None:
        """If installing the missing flows fails, the EVC is set INT enabled
        DOWN flows_install_failed, so the next fix redeploys it, and the error
        is raised."""
        evc_id = "3766c105686748"
        int_manager, api_mock, evcs = self._consistency_int_manager(
            monkeypatch, evc_id, [], stored=False
        )
        int_manager._install_int_flows.side_effect = exceptions.FlowsSendError(
            "x", {evc_id}
        )

        with pytest.raises(exceptions.FlowsSendError):
            await int_manager.check_consistency(evcs, inconsistent_action="fix")

        calls = self._metadata_calls(api_mock)
        assert [(ids, t["status_reason"]) for ids, t in calls] == [
            ([evc_id], ["flows_install_failed"])
        ]

    @pytest.mark.parametrize(
        "exc", [exceptions.UnrecoverableError("boom"), RetryError(MagicMock())]
    )
    async def test__send_flows_or_set_failed_other_errors(
        self, monkeypatch, exc
    ) -> None:
        """Only a failure to send the flows sets the EVCs failed, other errors
        are raised as they are."""
        api_mock = AsyncMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        evc_id = "3766c105686748"

        with pytest.raises(type(exc)):
            await int_manager._send_flows_or_set_failed(
                AsyncMock(side_effect=exc)(),
                {evc_id: self._pp_evc()},
                "flows_install_failed",
            )

        api_mock.add_evcs_metadata.assert_not_called()

    async def test_handle_pp_metadata_added_enable_flows_failed(
        self, monkeypatch
    ) -> None:
        """If re-enabling fails sending the flows, INT is kept enabled DOWN
        with the failed status, it isn't disabled."""
        api_mock, log_mock = AsyncMock(), MagicMock()
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.log", log_mock)
        int_manager = INTManager(MagicMock())
        intf = MagicMock(id="00:00:00:00:00:00:00:01:1", metadata={"proxy_port": 2})
        pp = MagicMock(evc_ids={"3766c105686748"})
        int_manager.get_proxy_port_or_raise = MagicMock(return_value=pp)
        api_mock.get_evcs.return_value = {"3766c105686748": self._pp_evc()}
        int_manager.disable_int = AsyncMock()
        int_manager.enable_int = AsyncMock(
            side_effect=exceptions.FlowsSendError("boom")
        )

        await int_manager.handle_pp_metadata_added(intf)

        int_manager.enable_int.assert_awaited_once()
        api_mock.add_evcs_metadata.assert_not_called()
        assert "flows_install_failed" in log_mock.error.call_args[0][0]

    @pytest.mark.parametrize(
        "failing,tracked",
        [
            ("install", ["3766c105686748", "3766c105686749"]),
            ("stored_flows", None),
        ],
    )
    async def test_enable_int_failed_pps_tracked(
        self, monkeypatch, failing, tracked
    ) -> None:
        """A failed install still sets every EVC INT enabled, the failed ones
        DOWN, so all get their proxy ports tracked, a failure before anything
        was sent tracks none."""
        api_mock = AsyncMock()
        api_mock.get_stored_flows.return_value = {}
        if failing == "stored_flows":
            api_mock.get_stored_flows.side_effect = RetryError(MagicMock())
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        int_manager._validate_map_enable_evcs = MagicMock(
            side_effect=lambda e, *_, **__: e
        )
        int_manager._add_pps_evc_ids = MagicMock()
        int_manager._remove_int_flows_by_cookies = AsyncMock()
        int_manager.install_int_flows = AsyncMock(
            side_effect=exceptions.FlowsSendError("boom", {"3766c105686748"})
        )
        evcs = {"3766c105686748": self._pp_evc(), "3766c105686749": self._pp_evc()}

        with pytest.raises((exceptions.FlowsSendError, RetryError)):
            await int_manager.enable_int(evcs)

        if tracked is None:
            int_manager._add_pps_evc_ids.assert_not_called()
        else:
            assert sorted(int_manager._add_pps_evc_ids.call_args[0][0]) == tracked

    async def test_disable_int_failed_pps_discarded(self, monkeypatch) -> None:
        """If removing fails, only the EVCs that weren't in the failed send,
        which got disabled, have their proxy ports discarded."""
        int_manager = INTManager(MagicMock())
        int_manager.remove_int_flows = AsyncMock(
            side_effect=exceptions.FlowsSendError("boom", {"3766c105686748"})
        )
        int_manager._discard_pps_evc_ids = MagicMock()
        evcs = {"3766c105686748": self._pp_evc(), "3766c105686749": self._pp_evc()}

        with pytest.raises(exceptions.FlowsSendError):
            await int_manager.disable_int(evcs, force=True)

        assert list(int_manager._discard_pps_evc_ids.call_args[0][0]) == [
            "3766c105686749"
        ]

    async def test__remove_evcs_int_flows_failed_kept_disabled(
        self, monkeypatch
    ) -> None:
        """An unrecoverable removal, such as on an OFPT_ERROR, that fails sets
        the EVC DOWN flows_remove_failed with INT disabled, so a consistency
        check doesn't redeploy it."""
        evc_id = "3766c105686748"
        api_mock = AsyncMock()
        api_mock.get_stored_flows.return_value = {
            utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX): [{"flow": {}}],
        }
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        int_manager = INTManager(MagicMock())
        int_manager._remove_int_flows_by_cookies = AsyncMock(
            side_effect=exceptions.FlowsSendError("boom", {evc_id})
        )
        metadata = {"telemetry": {"enabled": False, "status": "DOWN"}}

        with pytest.raises(exceptions.FlowsSendError):
            await int_manager.remove_int_flows(
                {evc_id: self._pp_evc()}, metadata, force=True, failed_enabled=False
            )

        calls = self._metadata_calls(api_mock)
        assert [(ids, t["enabled"], t["status_reason"]) for ids, t in calls] == [
            ([evc_id], False, ["flows_remove_failed"])
        ]

    @pytest.mark.parametrize("active", [True, False])
    async def test_handle_partial_flows_flows_failed_redeployed(
        self, monkeypatch, active
    ) -> None:
        """An EVC whose INT flows failed to be sent isn't installed only the
        event's INT flows, which could leave an INT source without its sink.
        It's redeployed if active, else it keeps its status, and its status
        isn't updated from the event."""
        failed_id, ok_id = "3766c105686748", "3766c105686749"
        int_manager, api_mock = self._pp_int_manager(monkeypatch, EntityStatus.UP)
        int_manager._redeploy_evcs_int_flows = AsyncMock()
        int_manager._built_install_flows = MagicMock(return_value={})
        failed = self._pp_evc("DOWN", ["flows_install_failed"])
        failed["active"] = active

        await int_manager.handle_partial_flows(
            {failed_id: failed, ok_id: self._pp_evc()},
            "kytos/mef_eline.static.ingress_installed",
        )

        assert list(int_manager._built_install_flows.call_args[0][0]) == [ok_id]
        if active:
            redeployed = int_manager._redeploy_evcs_int_flows.call_args[0][0]
            assert list(redeployed) == [failed_id]
        else:
            int_manager._redeploy_evcs_int_flows.assert_not_called()
        written = [
            evc_id
            for args, _ in api_mock.add_evcs_metadata.call_args_list
            for evc_id in args[0]
        ]
        assert written == [ok_id]

    async def test_install_int_flows_metadata_groups_concurrent(
        self, monkeypatch
    ) -> None:
        """The metadata groups, a bulk request each, are sent concurrently, and
        installing only returns once all are done, so none outlives the EVC
        locks. An error is raised once all are done."""
        gate, started = asyncio.Event(), []
        active_id, inactive_id = "3766c105686748", "3766c105686749"

        async def add_evcs_metadata(evcs, *_):
            if not evcs:
                return {}
            started.append(sorted(evcs))
            await gate.wait()
            if inactive_id in evcs:
                raise exceptions.UnrecoverableError("boom")
            return {}

        api_mock = AsyncMock()
        api_mock.add_evcs_metadata.side_effect = add_evcs_metadata
        monkeypatch.setattr("napps.kytos.telemetry_int.managers.int.api", api_mock)
        monkeypatch.setattr(utils, "get_found_stored_flows", AsyncMock())
        int_manager = INTManager(MagicMock())
        int_manager._install_int_flows = AsyncMock()
        int_manager.flow_builder.build_int_flows = MagicMock(
            return_value={
                utils.get_cookie(active_id, settings.MEF_COOKIE_PREFIX): [{"flow": {}}]
            }
        )
        inactive = self._pp_evc()
        inactive["active"] = False
        evcs = {active_id: self._pp_evc(), inactive_id: inactive}
        metadata = {"telemetry": {"enabled": True, "status": "UP", "status_reason": []}}

        task = asyncio.create_task(int_manager.install_int_flows(evcs, metadata))
        for _ in range(5):
            await asyncio.sleep(0)
        assert sorted(started) == [[active_id], [inactive_id]]
        assert not task.done()
        gate.set()
        with pytest.raises(exceptions.UnrecoverableError):
            await task
