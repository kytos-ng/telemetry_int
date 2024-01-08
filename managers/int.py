"""INTManager module."""
import asyncio
from collections import defaultdict
from datetime import datetime

from pyof.v0x04.controller2switch.table_mod import Table

from kytos.core.controller import Controller
from kytos.core.events import KytosEvent
from kytos.core.interface import Interface
from napps.kytos.telemetry_int import utils
from napps.kytos.telemetry_int import settings
from kytos.core import log
from kytos.core.link import Link
import napps.kytos.telemetry_int.kytos_api_helper as api
from napps.kytos.telemetry_int.managers.flow_builder import FlowBuilder
from kytos.core.common import EntityStatus
from napps.kytos.telemetry_int.proxy_port import ProxyPort

from napps.kytos.telemetry_int.exceptions import (
    EVCError,
    EVCNotFound,
    EVCHasINT,
    EVCHasNoINT,
    FlowsNotFound,
    ProxyPortError,
    ProxyPortStatusNotUP,
    ProxyPortDestNotFound,
    ProxyPortNotFound,
    ProxyPortSameSourceIntraEVC,
)


class INTManager:

    """INTManager encapsulates and aggregates telemetry-related functionalities."""

    def __init__(self, controller: Controller) -> None:
        """INTManager."""
        self.controller = controller
        self.flow_builder = FlowBuilder()
        self._topo_link_lock = asyncio.Lock()
        self._intf_meta_lock = asyncio.Lock()

        # Keep track between each uni intf id and its src intf id port
        self.unis_src: dict[str, str] = {}
        # Keep track between src intf id and its ProxyPort instance
        self.srcs_pp: dict[str, ProxyPort] = {}

    def load_uni_src_proxy_ports(self, evcs: dict[str, dict]) -> None:
        """Load UNI ids src ids and their ProxyPort instances."""
        for evc_id, evc in evcs.items():
            if not utils.has_int_enabled(evc):
                continue

            uni_a_id = evc["uni_a"]["interface_id"]
            uni_z_id = evc["uni_z"]["interface_id"]
            uni_a = self.controller.get_interface_by_id(uni_a_id)
            uni_z = self.controller.get_interface_by_id(uni_z_id)
            if uni_a and "proxy_port" in uni_a.metadata:
                src_a = uni_a.switch.get_interface_by_port_no(
                    uni_a.metadata["proxy_port"]
                )
                self.unis_src[uni_a.id] = src_a.id
                try:
                    pp = self.get_proxy_port_or_raise(uni_a.id, evc_id)
                except ProxyPortDestNotFound:
                    pp = self.srcs_pp[src_a.id]
                pp.evc_ids.add(evc_id)

            if uni_z and "proxy_port" in uni_z.metadata:
                src_z = uni_z.switch.get_interface_by_port_no(
                    uni_z.metadata["proxy_port"]
                )
                self.unis_src[uni_z.id] = src_z.id
                try:
                    pp = self.get_proxy_port_or_raise(uni_z.id, evc_id)
                except ProxyPortDestNotFound:
                    pp = self.srcs_pp[src_z.id]
                pp.evc_ids.add(evc_id)

    async def handle_pp_link_down(self, link: Link) -> None:
        """Handle proxy_port link_down."""
        if not settings.FALLBACK_TO_MEF_LOOP_DOWN:
            return
        pp = self.srcs_pp.get(link.endpoint_a.id)
        if not pp:
            pp = self.srcs_pp.get(link.endpoint_b.id)
        if not pp or not pp.evc_ids:
            return

        async with self._topo_link_lock:
            evcs = await api.get_evcs(
                **{
                    "metadata.telemetry.enabled": "true",
                    "metadata.telemetry.status": "UP",
                }
            )
            to_deactivate = {
                evc_id: evc for evc_id, evc in evcs.items() if evc_id in pp.evc_ids
            }
            if not to_deactivate:
                return

            log.info(
                f"Handling link_down {link}, removing INT flows falling back to "
                f"mef_eline, EVC ids: {list(to_deactivate)}"
            )
            metadata = {
                "telemetry": {
                    "enabled": True,
                    "status": "DOWN",
                    "status_reason": ["proxy_port_down"],
                    "status_updated_at": datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                }
            }
            await self.remove_int_flows(to_deactivate, metadata)

    async def handle_pp_link_up(self, link: Link) -> None:
        """Handle proxy_port link_up."""
        if not settings.FALLBACK_TO_MEF_LOOP_DOWN:
            return
        pp = self.srcs_pp.get(link.endpoint_a.id)
        if not pp:
            pp = self.srcs_pp.get(link.endpoint_b.id)
        if not pp or not pp.evc_ids:
            return

        async with self._topo_link_lock:
            if link.status != EntityStatus.UP or link.status_reason:
                return
            evcs = await api.get_evcs(
                **{
                    "metadata.telemetry.enabled": "true",
                    "metadata.telemetry.status": "DOWN",
                }
            )

            to_install = {}
            for evc_id, evc in evcs.items():
                if any(
                    (
                        not evc["active"],
                        evc["archived"],
                        evc_id not in pp.evc_ids,
                        evc["uni_a"]["interface_id"] not in self.unis_src,
                        evc["uni_z"]["interface_id"] not in self.unis_src,
                    )
                ):
                    continue

                src_a_id = self.unis_src[evc["uni_a"]["interface_id"]]
                src_z_id = self.unis_src[evc["uni_z"]["interface_id"]]
                if (
                    src_a_id in self.srcs_pp
                    and src_z_id in self.srcs_pp
                    and self.srcs_pp[src_a_id].status == EntityStatus.UP
                    and self.srcs_pp[src_z_id].status == EntityStatus.UP
                ):
                    to_install[evc_id] = evc

            if not to_install:
                return

            try:
                to_install = self._validate_map_enable_evcs(to_install, force=True)
            except EVCError as exc:
                log.exception(exc)
                return

            log.info(
                f"Handling link_up {link}, deploying INT flows, "
                f"EVC ids: {list(to_install)}"
            )
            metadata = {
                "telemetry": {
                    "enabled": True,
                    "status": "UP",
                    "status_reason": [],
                    "status_updated_at": datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                }
            }
            try:
                await self.install_int_flows(to_install, metadata)
            except FlowsNotFound as exc:
                log.exception(f"FlowsNotFound {str(exc)}")
                return

    async def handle_pp_metadata_removed(self, intf: Interface) -> None:
        """Handle proxy port metadata removed."""
        if "proxy_port" in intf.metadata:
            return
        try:
            pp = self.srcs_pp[self.unis_src[intf.id]]
            if not pp.evc_ids:
                return
        except KeyError:
            return

        async with self._intf_meta_lock:
            evcs = await api.get_evcs(
                **{
                    "metadata.telemetry.enabled": "true",
                    "metadata.telemetry.status": "UP",
                }
            )
            to_deactivate = {
                evc_id: evc for evc_id, evc in evcs.items() if evc_id in pp.evc_ids
            }
            if not to_deactivate:
                return

            log.info(
                f"Handling interface metadata removed on {intf}, removing INT flows "
                f"falling back to mef_eline, EVC ids: {list(to_deactivate)}"
            )
            metadata = {
                "telemetry": {
                    "enabled": True,
                    "status": "DOWN",
                    "status_reason": ["proxy_port_metadata_removed"],
                    "status_updated_at": datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                }
            }
            await self.remove_int_flows(to_deactivate, metadata)

    async def handle_pp_metadata_added(self, intf: Interface) -> None:
        """Handle proxy port metadata added.

        If an existing ProxyPort gets its proxy_port meadata updated
        and has associated EVCs then it'll remove and install the flows accordingly.

        """
        if "proxy_port" not in intf.metadata:
            return
        try:
            pp = self.srcs_pp[self.unis_src[intf.id]]
            if not pp.evc_ids:
                return
        except KeyError:
            return

        cur_source_intf = intf.switch.get_interface_by_port_no(
            intf.metadata.get("proxy_port")
        )
        if cur_source_intf == pp.source:
            return

        async with self._intf_meta_lock:
            pp.source = cur_source_intf

            evcs = await api.get_evcs(
                **{
                    "metadata.telemetry.enabled": "true",
                }
            )
            affected_evcs = {
                evc_id: evc for evc_id, evc in evcs.items() if evc_id in pp.evc_ids
            }
            if not affected_evcs:
                return

            log.info(
                f"Handling interface metadata updated on {intf}. It'll disable the "
                "EVCs to be safe, and then try to enable again with the updated "
                f" proxy port {pp}, EVC ids: {list(affected_evcs)}"
            )
            await self.disable_int(affected_evcs, force=True)
            try:
                await self.enable_int(affected_evcs, force=True)
            except ProxyPortSameSourceIntraEVC as exc:
                msg = (
                    f"Validation error when updating interface {intf} proxy port {pp}"
                    f" EVC ids: {list(affected_evcs)}, exception {str(exc)}"
                )
                log.error(msg)

    async def disable_int(self, evcs: dict[str, dict], force=False) -> None:
        """Disable INT on EVCs.

        evcs is a dict of prefetched EVCs from mef_eline based on evc_ids.

        The force bool option, if True, will bypass the following:

        1 - EVC not found
        2 - EVC doesn't have INT
        3 - ProxyPortNotFound or ProxyPortDestNotFound

        """
        self._validate_disable_evcs(evcs, force)
        log.info(f"Disabling INT on EVC ids: {list(evcs.keys())}, force: {force}")

        metadata = {
            "telemetry": {
                "enabled": False,
                "status": "DOWN",
                "status_reason": ["disabled"],
                "status_updated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            }
        }
        await self.remove_int_flows(evcs, metadata, force=force)
        try:
            self._discard_pps_evc_ids(evcs)
        except ProxyPortError:
            if not force:
                raise

    async def remove_int_flows(
        self, evcs: dict[str, dict], metadata: dict, force=False
    ) -> None:
        """Remove INT flows and set metadata on EVCs."""
        stored_flows = await api.get_stored_flows(
            [utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX) for evc_id in evcs]
        )
        await asyncio.gather(
            self._remove_int_flows(stored_flows),
            api.add_evcs_metadata(evcs, metadata, force),
        )

    async def enable_int(self, evcs: dict[str, dict], force=False) -> None:
        """Enable INT on EVCs.

        evcs is a dict of prefetched EVCs from mef_eline based on evc_ids.

        The force bool option, if True, will bypass the following:

        1 - EVC already has INT
        2 - ProxyPort isn't UP
        Other cases won't be bypassed since at the point it won't have the data needed.

        """
        evcs = self._validate_map_enable_evcs(evcs, force)
        log.info(f"Enabling INT on EVC ids: {list(evcs.keys())}, force: {force}")

        metadata = {
            "telemetry": {
                "enabled": True,
                "status": "UP",
                "status_reason": [],
                "status_updated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            }
        }
        await self.install_int_flows(evcs, metadata)
        self._add_pps_evc_ids(evcs)

    async def redeploy_int(self, evcs: dict[str, dict]) -> None:
        """Redeploy INT on EVCs. It'll only delete and install the flows again.

        evcs is a dict of prefetched EVCs from mef_eline based on evc_ids.
        """
        evcs = self._validate_map_enable_evcs(evcs, force=True)
        log.info(f"Redeploying INT on EVC ids: {list(evcs.keys())}, force: True")

        stored_flows = await api.get_stored_flows(
            [utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX) for evc_id in evcs]
        )
        await self._remove_int_flows(stored_flows)

        found_stored_flows = self.flow_builder.build_int_flows(
            evcs,
            await utils.get_found_stored_flows(
                [
                    utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
                    for evc_id in evcs
                ]
            ),
        )
        await self._install_int_flows(found_stored_flows)

    async def install_int_flows(self, evcs: dict[str, dict], metadata: dict) -> None:
        """Install INT flows and set metadata on EVCs."""
        stored_flows = self.flow_builder.build_int_flows(
            evcs,
            await utils.get_found_stored_flows(
                [
                    utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
                    for evc_id in evcs
                ]
            ),
        )
        await asyncio.gather(
            self._install_int_flows(stored_flows),
            api.add_evcs_metadata(evcs, metadata),
        )

    def get_proxy_port_or_raise(self, intf_id: str, evc_id: str) -> ProxyPort:
        """Return a ProxyPort assigned to a UNI or raise."""

        interface = self.controller.get_interface_by_id(intf_id)
        if not interface:
            raise ProxyPortNotFound(evc_id, f"UNI interface {intf_id} not found")

        if "proxy_port" not in interface.metadata:
            raise ProxyPortNotFound(
                evc_id, f"proxy_port metadata not found in {intf_id}"
            )

        source_intf = interface.switch.get_interface_by_port_no(
            interface.metadata.get("proxy_port")
        )
        if not source_intf:
            raise ProxyPortNotFound(
                evc_id,
                f"proxy_port of {intf_id} source interface not found",
            )

        pp = self.srcs_pp.get(source_intf.id)
        if not pp:
            pp = ProxyPort(self.controller, source_intf)
            self.srcs_pp[source_intf.id] = pp

        if not pp.destination:
            raise ProxyPortDestNotFound(
                evc_id,
                f"proxy_port of {intf_id} isn't looped or destination interface "
                "not found",
            )

        return pp

    def _validate_disable_evcs(
        self,
        evcs: dict[str, dict],
        force=False,
    ) -> None:
        """Validate disable EVCs."""
        for evc_id, evc in evcs.items():
            if not evc and not force:
                raise EVCNotFound(evc_id)
            if not utils.has_int_enabled(evc) and not force:
                raise EVCHasNoINT(evc_id)

    def _validate_intra_evc_different_proxy_ports(self, evc: dict) -> None:
        """Validate that an intra EVC is using different proxy ports.

        If the same proxy port is used on both UNIs, of one the sink/pop related matches
        would ended up being overwritten since they'd be the same. Currently, an
        external loop will have unidirectional flows matching in the lower (source)
        port number.
        """
        pp_a = evc["uni_a"].get("proxy_port")
        pp_z = evc["uni_z"].get("proxy_port")
        if any(
            (
                not utils.is_intra_switch_evc(evc),
                pp_a is None,
                pp_z is None,
            )
        ):
            return
        if pp_a.source != pp_z.source:
            return

        raise ProxyPortSameSourceIntraEVC(
            evc["id"], "intra EVC UNIs must use different proxy ports"
        )

    def _validate_map_enable_evcs(
        self,
        evcs: dict[str, dict],
        force=False,
    ) -> dict[str, dict]:
        """Validate map enabling EVCs.

        This function also maps both uni_a and uni_z dicts with their ProxyPorts, just
        so it can be reused later during provisioning.

        """
        for evc_id, evc in evcs.items():
            if not evc:
                raise EVCNotFound(evc_id)
            if utils.has_int_enabled(evc) and not force:
                raise EVCHasINT(evc_id)

            uni_a, uni_z = utils.get_evc_unis(evc)
            pp_a = self.get_proxy_port_or_raise(uni_a["interface_id"], evc_id)
            pp_z = self.get_proxy_port_or_raise(uni_z["interface_id"], evc_id)

            uni_a["proxy_port"], uni_z["proxy_port"] = pp_a, pp_z
            evc["uni_a"], evc["uni_z"] = uni_a, uni_z

            if pp_a.status != EntityStatus.UP and not force:
                dest_id = pp_a.destination.id if pp_a.destination else None
                dest_status = pp_a.status if pp_a.destination else None
                raise ProxyPortStatusNotUP(
                    evc_id,
                    f"proxy_port of {uni_a['interface_id']} isn't UP. "
                    f"source {pp_a.source.id} status {pp_a.source.status}, "
                    f"destination {dest_id} status {dest_status}",
                )
            if pp_z.status != EntityStatus.UP and not force:
                dest_id = pp_z.destination.id if pp_z.destination else None
                dest_status = pp_z.status if pp_z.destination else None
                raise ProxyPortStatusNotUP(
                    evc_id,
                    f"proxy_port of {uni_z['interface_id']} isn't UP."
                    f"source {pp_z.source.id} status {pp_z.source.status}, "
                    f"destination {dest_id} status {dest_status}",
                )

            self._validate_intra_evc_different_proxy_ports(evc)
        return evcs

    def _add_pps_evc_ids(self, evcs: dict[str, dict]):
        """Add proxy ports evc_ids.

        This is meant to be called after an EVC is enabled.
        """
        for evc_id, evc in evcs.items():
            uni_a, uni_z = utils.get_evc_unis(evc)
            pp_a = self.get_proxy_port_or_raise(uni_a["interface_id"], evc_id)
            pp_z = self.get_proxy_port_or_raise(uni_z["interface_id"], evc_id)
            pp_a.evc_ids.add(evc_id)
            pp_z.evc_ids.add(evc_id)
            self.unis_src[evc["uni_a"]["interface_id"]] = pp_a.source.id
            self.unis_src[evc["uni_z"]["interface_id"]] = pp_z.source.id

    def _discard_pps_evc_ids(self, evcs: dict[str, dict]) -> None:
        """Discard proxy port evc_ids.

        This is meant to be called when an EVC is disabled.
        """
        for evc_id, evc in evcs.items():
            uni_a, uni_z = utils.get_evc_unis(evc)
            pp_a = self.get_proxy_port_or_raise(uni_a["interface_id"], evc_id)
            pp_z = self.get_proxy_port_or_raise(uni_z["interface_id"], evc_id)
            pp_a.evc_ids.discard(evc_id)
            pp_z.evc_ids.discard(evc_id)

    def evc_compare(
        self, stored_int_flows: dict, stored_mef_flows: dict, evcs: dict
    ) -> dict[str, list]:
        """EVC compare.

        Cases:
        - No INT enabled but has INT flows -> wrong_metadata_has_int_flows
        - INT enabled but has less flows than mef flows -> missing_some_int_flows

        """
        int_flows = {
            utils.get_id_from_cookie(k): v for k, v in stored_int_flows.items()
        }
        mef_flows = {
            utils.get_id_from_cookie(k): v for k, v in stored_mef_flows.items()
        }

        results = defaultdict(list)
        for evc in evcs.values():
            evc_id = evc["id"]

            if (
                not utils.has_int_enabled(evc)
                and evc_id in int_flows
                and int_flows[evc_id]
            ):
                results[evc_id].append("wrong_metadata_has_int_flows")

            if (
                utils.has_int_enabled(evc)
                and evc_id in mef_flows
                and mef_flows[evc_id]
                and (
                    evc_id not in int_flows
                    or (
                        evc_id in int_flows
                        and len(int_flows[evc_id]) < len(mef_flows[evc_id])
                    )
                )
            ):
                results[evc_id].append("missing_some_int_flows")
        return results

    async def _remove_int_flows(self, stored_flows: dict[int, list[dict]]) -> None:
        """Delete int flows given a prefiltered stored_flows.

        Removal is driven by the stored flows instead of EVC ids and dpids to also
        be able to handle the force mode when an EVC no longer exists. It also follows
        the same pattern that mef_eline currently uses.

        The flows will be batched per dpid based on settings.BATCH_SIZE and will wait
        for settings.BATCH_INTERVAL per batch iteration.

        """
        switch_flows = defaultdict(set)
        for flows in stored_flows.values():
            for flow in flows:
                switch_flows[flow["switch"]].add(flow["flow"]["cookie"])

        for dpid, cookies in switch_flows.items():
            cookie_vals = list(cookies)
            batch_size = settings.BATCH_SIZE
            if batch_size <= 0:
                batch_size = len(cookie_vals)

            for i in range(0, len(cookie_vals), batch_size):
                if i > 0:
                    await asyncio.sleep(settings.BATCH_INTERVAL)
                flows = [
                    {
                        "cookie": cookie,
                        "cookie_mask": int(0xFFFFFFFFFFFFFFFF),
                        "table_id": Table.OFPTT_ALL.value,
                    }
                    for cookie in cookie_vals[i : i + batch_size]
                ]
                event = KytosEvent(
                    "kytos.flow_manager.flows.delete",
                    content={
                        "dpid": dpid,
                        "force": True,
                        "flow_dict": {"flows": flows},
                    },
                )
                await self.controller.buffers.app.aput(event)

    async def _install_int_flows(self, stored_flows: dict[int, list[dict]]) -> None:
        """Install INT flow mods.

        The flows will be batched per dpid based on settings.BATCH_SIZE and will wait
        for settings.BATCH_INTERVAL per batch iteration.
        """

        switch_flows = defaultdict(list)
        for flows in stored_flows.values():
            for flow in flows:
                switch_flows[flow["switch"]].append(flow["flow"])

        for dpid, flows in switch_flows.items():
            flow_vals = list(flows)
            batch_size = settings.BATCH_SIZE
            if batch_size <= 0:
                batch_size = len(flow_vals)

            for i in range(0, len(flow_vals), batch_size):
                if i > 0:
                    await asyncio.sleep(settings.BATCH_INTERVAL)
                flows = flow_vals[i : i + batch_size]
                event = KytosEvent(
                    "kytos.flow_manager.flows.install",
                    content={
                        "dpid": dpid,
                        "force": True,
                        "flow_dict": {"flows": flows},
                    },
                )
                await self.controller.buffers.app.aput(event)
