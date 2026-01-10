"""INTManager module."""

import asyncio
import copy
from collections import defaultdict
from datetime import datetime
from typing import Literal, Optional
from contextlib import AsyncExitStack

from pyof.v0x04.controller2switch.table_mod import Table

from kytos.core.controller import Controller
from kytos.core.events import KytosEvent
from kytos.core.interface import Interface
from napps.kytos.telemetry_int import utils
from napps.kytos.telemetry_int import settings
from kytos.core import log
from kytos.core.link import Link
import napps.kytos.telemetry_int.kytos_api_helper as api
from napps.kytos.of_core.flow import FlowFactory
from napps.kytos.of_core.v0x04.flow import Flow as Flow04
from napps.kytos.telemetry_int.managers.flow_builder import FlowBuilder
from kytos.core.common import EntityStatus
from napps.kytos.telemetry_int.proxy_port import ProxyPort

from tenacity import RetryError

from napps.kytos.telemetry_int.exceptions import (
    EVCError,
    EVCNotFound,
    EVCHasINT,
    EVCHasNoINT,
    FlowsNotFound,
    ProxyPortAsymmetric,
    ProxyPortMetadataNotFound,
    ProxyPortError,
    ProxyPortStatusNotUP,
    ProxyPortDestNotFound,
    ProxyPortNotFound,
    ProxyPortRequired,
    ProxyPortSameSourceIntraEVC,
    ProxyPortShared,
    UnrecoverableError,
)


class INTManager:
    """INTManager encapsulates and aggregates telemetry-related functionalities."""

    def __init__(self, controller: Controller) -> None:
        """INTManager."""
        self.controller = controller
        self.flow_builder = FlowBuilder()
        self._topo_link_lock = asyncio.Lock()
        self._intf_meta_lock = asyncio.Lock()
        self._evcs_lock: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._consistency_lock = asyncio.Lock()

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
                if src_a := uni_a.switch.get_interface_by_port_no(
                    uni_a.metadata["proxy_port"]
                ):
                    self.unis_src[uni_a.id] = src_a.id
                    try:
                        pp = self.get_proxy_port_or_raise(uni_a.id, evc_id)
                    except ProxyPortDestNotFound:
                        pp = self.srcs_pp[src_a.id]
                    pp.evc_ids.add(evc_id)
                else:
                    log.error(
                        f"Failed to load proxy_port {uni_a.metadata['proxy_port']} "
                        f"of UNI {uni_a_id}. You need to set a correct proxy_port value"
                    )

            if uni_z and "proxy_port" in uni_z.metadata:
                if src_z := uni_z.switch.get_interface_by_port_no(
                    uni_z.metadata["proxy_port"]
                ):
                    self.unis_src[uni_z.id] = src_z.id
                    try:
                        pp = self.get_proxy_port_or_raise(uni_z.id, evc_id)
                    except ProxyPortDestNotFound:
                        pp = self.srcs_pp[src_z.id]
                    pp.evc_ids.add(evc_id)
                else:
                    log.error(
                        f"Failed to load proxy_port {uni_z.metadata['proxy_port']} "
                        f"of UNI {uni_z_id}. You need to set a correct proxy_port value"
                    )

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
            affected_evcs = {
                evc_id: evc for evc_id, evc in evcs.items() if evc_id in pp.evc_ids
            }
            if not affected_evcs:
                return

            affected_evcs_list = list(affected_evcs)
            log.info(
                f"Handling topology.interfaces.metadata.removed on {intf}, it'll "
                f"disable INT falling back to mef_eline, EVC ids: {affected_evcs_list}"
            )
            try:
                await self.disable_int(
                    affected_evcs, force=True, reason="proxy_port_metadata_removed"
                )
            except (EVCError, RetryError, UnrecoverableError) as exc:
                excs = str(exc)
                if isinstance(exc, RetryError):
                    excs = str(exc.last_attempt.exception())
                log.error(
                    f"Failed to disable INT, Exception: {excs}, when handling "
                    f"topology.interfaces.metadata.removed on {intf}, {pp}. "
                    "You need to force disable INT on these EVC ids: "
                    f"{affected_evcs_list}"
                )

    async def handle_pp_metadata_added(self, intf: Interface) -> None:
        """Handle proxy port metadata added.

        If an existing ProxyPort gets its proxy_port meadata updated
        and has associated EVCs then it'll remove and install the flows accordingly.

        """
        if "proxy_port" not in intf.metadata:
            return
        pp = None
        try:
            pp = self.get_proxy_port_or_raise(intf.id, "proxy_port")
        except ProxyPortNotFound as exc:
            log.error(f"Error {str(exc)} when getting interface {intf} proxy port")
            return

        async with self._intf_meta_lock:
            evcs = await api.get_evcs(
                **{
                    "metadata.telemetry.enabled": "true",
                }
            )
            affected_evcs = {
                evc_id: evc
                for evc_id, evc in evcs.items()
                if pp
                and evc_id in pp.evc_ids
                or evc["uni_a"]["interface_id"] == intf.id
                or evc["uni_z"]["interface_id"] == intf.id
            }
            if not affected_evcs:
                return

            affected_evcs_list = list(affected_evcs)
            log.info(
                f"Handling topology.interfaces.metadata.added on {intf}. It'll disable "
                "the EVCs to be safe, and then try to enable again with the updated "
                f" proxy port {pp}, EVC ids: {affected_evcs_list}"
            )
            try:
                await self.disable_int(
                    affected_evcs, force=True, reason="proxy_port_metadata_added"
                )
            except (EVCError, RetryError, UnrecoverableError) as exc:
                excs = str(exc)
                if isinstance(exc, RetryError):
                    excs = str(exc.last_attempt.exception())
                log.error(
                    f"Failed to disable INT, Exception: {excs}, "
                    f"when handling topology.interfaces.metadata.added on {intf}, {pp}."
                    " You need to force disable and then enable INT on these EVC ids: "
                    f"{affected_evcs_list}"
                )
                return

            try:
                await self.enable_int(affected_evcs, force=True)
            except (EVCError, RetryError, UnrecoverableError) as exc:
                excs = str(exc)
                if isinstance(exc, RetryError):
                    excs = str(exc.last_attempt.exception())
                log.error(
                    f"Failed to re-enable INT, Exception: {excs} when handling "
                    f"topology.interfaces.metadata.added on {intf}, {pp}. You need to "
                    "analyze the error, and force enable INT later on "
                    f"EVC ids: {affected_evcs_list}"
                )
                metadata = {
                    "telemetry": {
                        "enabled": False,
                        "status": "DOWN",
                        "status_reason": [type(exc).__name__],
                        "status_updated_at": datetime.utcnow().strftime(
                            "%Y-%m-%dT%H:%M:%S"
                        ),
                    }
                }
                try:
                    await api.add_evcs_metadata(evcs, metadata)
                except (RetryError, UnrecoverableError) as exc:
                    excs = str(exc)
                    if isinstance(exc, RetryError):
                        excs = str(exc.last_attempt.exception())
                    log.error(
                        f"Failed to set INT metadata, Exception: {excs}, when handling"
                        f"topology.interfaces.metadata.added on intf {intf}, {pp}. "
                        "You need to solve the error and then force enable INT "
                        f"on EVC ids: {affected_evcs_list} "
                    )

    async def disable_int(
        self, evcs: dict[str, dict], force=False, reason="disabled"
    ) -> None:
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
                "status_reason": [reason],
                "status_updated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            }
        }
        await self.remove_int_flows(evcs, metadata, force=force)
        self._discard_pps_evc_ids(evcs)

    async def remove_int_flows(
        self, evcs: dict[str, dict], metadata: dict, force=False
    ) -> None:
        """Remove INT flows and set metadata on EVCs."""
        evcs = utils.sorted_evcs_by_svc_lvl(evcs)
        async with AsyncExitStack() as stack:
            _ = [
                await stack.enter_async_context(self._evcs_lock[evc_id])
                for evc_id in evcs
            ]
            stored_flows = await api.get_stored_flows(
                [
                    utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX)
                    for evc_id in evcs
                ]
            )
            await asyncio.gather(
                self._remove_int_flows_by_cookies(stored_flows),
                api.add_evcs_metadata(evcs, metadata, force),
            )

    async def enable_int(
        self,
        evcs: dict[str, dict],
        force=False,
        proxy_port_enabled: Optional[bool] = None,
        set_proxy_port_metadata=False,
    ) -> None:
        """Enable INT on EVCs.

        evcs is a dict of prefetched EVCs from mef_eline based on evc_ids.

        The force bool option, if True, will bypass the following:
        The proxy_port_enabled option, is to overwrite at the EVC level whether
        or not proxy_port should be enabled for the EVC regardless of interface
        proxy_port configuration

        1 - EVC already has INT
        2 - ProxyPort isn't UP
        Other cases won't be bypassed since at the point it won't have the data needed.

        A proxy port is only used for an inter-EVC if it's been pre-configured,
        otherwise by default it's not expected to be in place.

        Before enabling INT, like mef_eline, it'll remove the INT flows first.
        """
        evcs = self._validate_map_enable_evcs(evcs, force, proxy_port_enabled)
        log.info(
            f"Enabling INT on EVC ids: {list(evcs.keys())}, force: {force}, "
            f"proxy_port_enabled: {proxy_port_enabled}"
        )

        evcs = utils.sorted_evcs_by_svc_lvl(evcs)
        async with AsyncExitStack() as stack:
            _ = [
                await stack.enter_async_context(self._evcs_lock[evc_id])
                for evc_id in evcs
            ]
            stored_flows = await api.get_stored_flows(
                [
                    utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX)
                    for evc_id in evcs
                ]
            )
            await self._remove_int_flows_by_cookies(stored_flows)
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
            if set_proxy_port_metadata:
                metadata["proxy_port_enabled"] = proxy_port_enabled
            await self.install_int_flows(evcs, metadata)
        self._add_pps_evc_ids(evcs)

    async def redeploy_int(self, evcs: dict[str, dict]) -> None:
        """Redeploy INT on EVCs. It'll remove, install and update metadata.

        evcs is a dict of prefetched EVCs from mef_eline based on evc_ids.
        """
        self._validate_has_int(evcs)
        evcs = self._validate_map_enable_evcs(evcs, force=True)
        log.info(f"Redeploying INT on EVC ids: {list(evcs.keys())}, force: True")

        evcs = utils.sorted_evcs_by_svc_lvl(evcs)
        async with AsyncExitStack() as stack:
            _ = [
                await stack.enter_async_context(self._evcs_lock[evc_id])
                for evc_id in evcs
            ]
            stored_flows = await api.get_stored_flows(
                [
                    utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX)
                    for evc_id in evcs
                ]
            )
            await self._remove_int_flows_by_cookies(stored_flows)
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
            await self.install_int_flows(evcs, metadata, force=True)

    async def install_int_flows(
        self, evcs: dict[str, dict], metadata: dict, force=False
    ) -> None:
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
        self._validate_evcs_stored_flows(evcs, stored_flows)

        active_evcs, inactive_evcs, pp_down_evcs = {}, {}, {}
        for evc_id, evc in evcs.items():
            if not evc["active"]:
                inactive_evcs[evc_id] = evc
                continue
            if any(
                (
                    "proxy_port" in evc["uni_a"]
                    and evc["uni_a"]["proxy_port"].status != EntityStatus.UP,
                    "proxy_port" in evc["uni_z"]
                    and evc["uni_z"]["proxy_port"].status != EntityStatus.UP,
                )
            ):
                pp_down_evcs[evc_id] = evc
                continue
            active_evcs[evc_id] = evc

        inactive_metadata = copy.deepcopy(metadata)
        inactive_metadata["telemetry"]["status"] = "DOWN"
        pp_down_metadata = copy.deepcopy(inactive_metadata)
        inactive_metadata["telemetry"]["status_reason"] = ["no_flows"]
        pp_down_metadata["telemetry"]["status_reason"] = ["proxy_port_down"]

        await asyncio.gather(
            self._install_int_flows(stored_flows),
            api.add_evcs_metadata(inactive_evcs, inactive_metadata, force),
            api.add_evcs_metadata(pp_down_evcs, pp_down_metadata, force),
            api.add_evcs_metadata(active_evcs, metadata, force),
        )

    def get_proxy_port_or_raise(
        self, intf_id: str, evc_id: str, new_port_number: Optional[int] = None
    ) -> ProxyPort:
        """Return a ProxyPort assigned to a UNI or raise.

        new_port_number can be set and used to validate a new port_number.
        """

        interface = self.controller.get_interface_by_id(intf_id)
        if not interface:
            raise ProxyPortNotFound(evc_id, f"UNI interface {intf_id} not found")

        if new_port_number is None and "proxy_port" not in interface.metadata:
            raise ProxyPortMetadataNotFound(evc_id, f"metadata not found in {intf_id}")

        port_no = new_port_number or interface.metadata.get("proxy_port")
        source_intf = interface.switch.get_interface_by_port_no(port_no)
        if not source_intf:
            raise ProxyPortNotFound(
                evc_id,
                f"proxy_port {port_no} of {intf_id} source interface not found",
            )

        pp = self.srcs_pp.get(source_intf.id)
        if not pp:
            pp = ProxyPort(source_intf)
            self.srcs_pp[source_intf.id] = pp

        if not pp.destination:
            raise ProxyPortDestNotFound(
                evc_id, f"proxy_port {port_no} of UNI {intf_id} isn't looped"
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

    def _validate_evcs_stored_flows(
        self, evcs: dict[str, dict], stored_flows: dict[int, list[dict]]
    ) -> None:
        """Validate that each active EVC has corresponding flows."""
        for evc_id, evc in evcs.items():
            if evc["active"] and not stored_flows.get(
                utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
            ):
                raise FlowsNotFound(evc_id)

    def _validate_existing_evcs_proxy_port_symmetry(
        self, intf_adding_pp: Interface, evcs: dict[str, dict]
    ) -> None:
        """Validate existing EVCs proxy port symmetry before adding proxy port metadata.
        This is needed to validate since when optional proxy ports were introduced.
        """
        for evc_id, evc in evcs.items():
            uni_a = self.controller.get_interface_by_id(evc["uni_a"]["interface_id"])
            uni_z = self.controller.get_interface_by_id(evc["uni_z"]["interface_id"])
            if uni_a == intf_adding_pp and "proxy_port" not in uni_z.metadata:
                raise ProxyPortAsymmetric(
                    evc_id,
                    f"proxy port asymmetry. uni_z {uni_z.id} doesn't have "
                    f"a proxy port but uni_a {intf_adding_pp.id} would have ",
                )
            if uni_z == intf_adding_pp and "proxy_port" not in uni_a.metadata:
                raise ProxyPortAsymmetric(
                    evc_id,
                    f"proxy port asymmetry. uni_a {uni_a.id} doesn't have "
                    f"a proxy port but uni_z {intf_adding_pp.id} would have ",
                )

    def _validate_proxy_ports_symmetry(self, evc: dict) -> None:
        """Validate proxy ports symmetry for a given EVC."""

        pp_a = evc["uni_a"].get("proxy_port")
        pp_z = evc["uni_z"].get("proxy_port")
        if any(
            (
                pp_a and not pp_z,
                not pp_a and pp_z,
            )
        ):
            raise ProxyPortAsymmetric(
                evc["id"], f"proxy ports asymmetry. pp_a: {pp_a}, pp_z: {pp_z}"
            )

        if (
            not utils.is_intra_switch_evc(evc)
            and utils.get_evc_proxy_port_value(evc)
            and (not pp_a or not pp_z)
        ):
            raise ProxyPortRequired(
                evc["id"],
                "with proxy_port_enabled must have both proxy ports set, "
                f"pp_a: {pp_a}, pp_z: {pp_z}",
            )

        if utils.is_intra_switch_evc(evc) and not pp_a and not pp_z:
            raise ProxyPortRequired(evc["id"], "intra-EVC must use proxy ports")

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

    def _validate_new_dedicated_proxy_port(
        self, uni: Interface, new_port_no: int
    ) -> None:
        """This is for validating a future proxy port.
        Only a dedicated proxy port per UNI is supported at the moment.

        https://github.com/kytos-ng/telemetry_int/issues/110
        """
        for intf in uni.switch.interfaces.copy().values():
            if (
                intf != uni
                and "proxy_port" in intf.metadata
                and intf.metadata["proxy_port"] == new_port_no
            ):
                msg = (
                    f"UNI {uni.id} must use another dedicated proxy_port. "
                    f"UNI {intf.id} is already using proxy_port {new_port_no}"
                )
                raise ProxyPortShared("no_evc_id", msg)

    def _validate_dedicated_proxy_port_evcs(self, evcs: dict[str, dict]):
        """Validate that a proxy port is dedicated for the given EVCs.
        Only a dedicated proxy port per UNI is supported at the moment.

        https://github.com/kytos-ng/telemetry_int/issues/110
        """
        seen_src_unis: dict[str, str] = {}
        for evc in evcs.values():
            try:
                pp_a, pp_z = evc["uni_a"]["proxy_port"], evc["uni_z"]["proxy_port"]
            except KeyError:
                continue
            unia_id, uniz_id = (
                evc["uni_a"]["interface_id"],
                evc["uni_z"]["interface_id"],
            )
            for cur_uni_id, cur_src_id in self.unis_src.items():
                for uni_id, pp in zip((unia_id, uniz_id), (pp_a, pp_z)):
                    if uni_id != cur_uni_id and cur_src_id == pp.source.id:
                        msg = (
                            f"UNI {uni_id} must use another dedicated proxy port. "
                            f"UNI {cur_uni_id} is using {pp}"
                        )
                        raise ProxyPortShared(evc["id"], msg)

            # This is needed to validate the EVCs of the current request
            # since self.uni_src only gets updated when a EVC gets enabled
            for uni_id, pp in zip((unia_id, uniz_id), (pp_a, pp_z)):
                if (found := seen_src_unis.get(pp.source.id)) and found != uni_id:
                    msg = (
                        f"UNI {uni_id} must use another dedicated proxy port. "
                        f"UNI {found} would use {pp}"
                    )
                    raise ProxyPortShared(evc["id"], msg)
                seen_src_unis[pp.source.id] = uni_id

    async def handle_failover_flows(
        self, evcs_content: dict[str, dict], event_name: str
    ) -> None:
        """Handle failover flows. This method will generate the subset
        of INT flows. EVCs with 'flows' key will be installed, and
        'old_flows' will be removed.

        If a given proxy port has an unexpected state INT will be
        removed falling back to mef_eline flows.
        """
        to_install, to_remove, to_remove_with_err = {}, {}, {}
        new_flows: dict[int, list[dict]] = defaultdict(list)
        old_flows: dict[int, list[dict]] = defaultdict(list)

        old_flows_key = "removed_flows"
        new_flows_key = "flows"

        for evc_id, evc in evcs_content.items():
            if (
                "telemetry" not in evc["metadata"]
                and "telemetry_request" in evc["metadata"]
            ):
                # Bootstrap state when it was enabled fully event-based
                evc["metadata"]["telemetry"] = {"enabled": True}

            if not utils.has_int_enabled(evc):
                continue
            try:
                uni_a, uni_z = utils.get_evc_unis(evc)
                evc["id"] = evc_id
                evc["uni_a"], evc["uni_z"] = uni_a, uni_z
                pp_a = self.get_proxy_port_or_raise(uni_a["interface_id"], evc_id)
                pp_z = self.get_proxy_port_or_raise(uni_z["interface_id"], evc_id)
                uni_a["proxy_port"], uni_z["proxy_port"] = pp_a, pp_z
            except ProxyPortMetadataNotFound as e:
                if utils.is_intra_switch_evc(evc):
                    log.error(
                        f"Unexpected proxy port state on intra EVC: {str(e)}."
                        f"INT will be removed on evc id {evc_id}"
                    )
                    to_remove_with_err[evc_id] = evc
                    continue
            except ProxyPortError as e:
                log.error(
                    f"Unexpected proxy port state: {str(e)}."
                    f"INT will be removed on evc id {evc_id}"
                )
                to_remove_with_err[evc_id] = evc
                continue

            for dpid, flows in evc.get(new_flows_key, {}).items():
                for flow in flows:
                    new_flows[flow["cookie"]].append({"flow": flow, "switch": dpid})

            for dpid, flows in evc.get(old_flows_key, {}).items():
                for flow in flows:
                    # set priority and table_group just so INT flows can be built
                    # the priority doesn't matter for deletion
                    flow["priority"] = 21000
                    flow["table_group"] = (
                        "evpl" if "dl_vlan" in flow.get("match", {}) else "epl"
                    )
                    old_flows[flow["cookie"]].append({"flow": flow, "switch": dpid})

            if evc.get(new_flows_key):
                to_install[evc_id] = evc
                evc.pop(new_flows_key)
            if evc.get(old_flows_key):
                to_remove[evc_id] = evc
                evc.pop(old_flows_key, None)

        if to_remove:
            log.info(
                f"Handling {event_name} flows remove on EVC ids: {to_remove.keys()}"
            )
            to_remove = utils.sorted_evcs_by_svc_lvl(to_remove)
            async with AsyncExitStack() as stack:
                _ = [
                    await stack.enter_async_context(self._evcs_lock[evc_id])
                    for evc_id in to_remove
                ]
                await self._remove_int_flows(
                    self.flow_builder.build_failover_old_flows(to_remove, old_flows)
                )
        if to_remove_with_err:
            log.error(
                f"Handling {event_name} proxy_port_error falling back "
                f"to mef_eline, EVC ids: {list(to_remove_with_err.keys())}"
            )
            metadata = {
                "telemetry": {
                    "enabled": True,
                    "status": "DOWN",
                    "status_reason": ["proxy_port_error"],
                    "status_updated_at": datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                }
            }
            to_remove_with_err = utils.sorted_evcs_by_svc_lvl(to_remove_with_err)
            await self.remove_int_flows(to_remove_with_err, metadata, force=True)
        if to_install:
            log.info(
                f"Handling {event_name} flows install on EVC ids: {to_install.keys()}"
            )
            built_flows = self.flow_builder.build_int_flows(to_install, new_flows)
            built_flows = {
                cookie: [
                    flow
                    for flow in flows
                    if not utils.has_instruction_and_action_type(
                        flow.get("flow", {}).get("instructions", []),
                        "apply_actions",
                        "push_int",
                    )
                ]
                for cookie, flows in built_flows.items()
            }
            to_install = utils.sorted_evcs_by_svc_lvl(to_install)
            async with AsyncExitStack() as stack:
                _ = [
                    await stack.enter_async_context(self._evcs_lock[evc_id])
                    for evc_id in to_install
                ]
                await self._install_int_flows(built_flows)

    def _validate_map_enable_evcs(
        self,
        evcs: dict[str, dict],
        force=False,
        proxy_port_enabled: Optional[bool] = None,
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
            evc["uni_a"], evc["uni_z"] = uni_a, uni_z

            pp_a = None
            try:
                pp_a = self.get_proxy_port_or_raise(uni_a["interface_id"], evc_id)
                uni_a["proxy_port"] = pp_a
            except ProxyPortMetadataNotFound:
                pass
            except ProxyPortError:
                raise

            pp_z = None
            try:
                pp_z = self.get_proxy_port_or_raise(uni_z["interface_id"], evc_id)
                uni_z["proxy_port"] = pp_z
            except ProxyPortMetadataNotFound:
                pass
            except ProxyPortError:
                raise

            if (
                not utils.is_intra_switch_evc(evc)
                and not proxy_port_enabled
                or utils.get_evc_proxy_port_value(evc) is False
            ):
                continue
            self._validate_proxy_ports_symmetry(evc)
            if not pp_a and not pp_z:
                continue

            if pp_a.status != EntityStatus.UP and not force:
                dest_id = pp_a.destination.id if pp_a.destination else None
                dest_status = pp_a.status if pp_a.destination else None
                raise ProxyPortStatusNotUP(
                    evc_id,
                    f"proxy_port of UNI {uni_a['interface_id']} isn't UP. "
                    f"source {pp_a.source.id} status {pp_a.source.status}, "
                    f"destination {dest_id} status {dest_status}",
                )
            if pp_z.status != EntityStatus.UP and not force:
                dest_id = pp_z.destination.id if pp_z.destination else None
                dest_status = pp_z.status if pp_z.destination else None
                raise ProxyPortStatusNotUP(
                    evc_id,
                    f"proxy_port of UNI {uni_z['interface_id']} isn't UP."
                    f"source {pp_z.source.id} status {pp_z.source.status}, "
                    f"destination {dest_id} status {dest_status}",
                )

            self._validate_intra_evc_different_proxy_ports(evc)
        self._validate_dedicated_proxy_port_evcs(evcs)
        return evcs

    def _validate_has_int(self, evcs: dict[str, dict]):
        for evc_id, evc in evcs.items():
            if not utils.has_int_enabled(evc):
                raise EVCHasNoINT(evc_id)

    def _add_pps_evc_ids(self, evcs: dict[str, dict]):
        """Add proxy ports evc_ids.

        This is meant to be called after an EVC is enabled.
        """
        for evc_id, evc in evcs.items():
            uni_a, uni_z = utils.get_evc_unis(evc)
            try:
                pp_a = self.get_proxy_port_or_raise(uni_a["interface_id"], evc_id)
                pp_z = self.get_proxy_port_or_raise(uni_z["interface_id"], evc_id)
                pp_a.evc_ids.add(evc_id)
                pp_z.evc_ids.add(evc_id)
                self.unis_src[evc["uni_a"]["interface_id"]] = pp_a.source.id
                self.unis_src[evc["uni_z"]["interface_id"]] = pp_z.source.id
            except ProxyPortMetadataNotFound:
                if utils.is_intra_switch_evc(evc):
                    raise

    def _discard_pps_evc_ids(self, evcs: dict[str, dict]) -> None:
        """Discard proxy port evc_ids.

        This is meant to be called when an EVC is disabled.
        """
        for evc_id, evc in evcs.items():
            uni_a, uni_z = utils.get_evc_unis(evc)
            try:
                pp_a = self.srcs_pp[self.unis_src[uni_a["interface_id"]]]
                pp_a.evc_ids.discard(evc_id)
                if not pp_a.evc_ids:
                    self.unis_src.pop(evc["uni_a"]["interface_id"], None)
            except KeyError:
                pass
            try:
                pp_z = self.srcs_pp[self.unis_src[uni_z["interface_id"]]]
                pp_z.evc_ids.discard(evc_id)
                if not pp_z.evc_ids:
                    self.unis_src.pop(evc["uni_z"]["interface_id"], None)
            except KeyError:
                pass

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

    async def _remove_int_flows_by_cookies(
        self, stored_flows: dict[int, list[dict]]
    ) -> dict[str, list[dict]]:
        """Delete int flows given a prefiltered stored_flows by cookies.
        You should use this type of removal when you need to remove all
        flows associated with a cookie, if you need to include all keys in the match
        to remove only a subset use `_remove_int_flows(stored_flows)` method instead.

        Removal is driven by the stored flows instead of EVC ids and dpids to also
        be able to handle the force mode when an EVC no longer exists. It also follows
        the same pattern that mef_eline currently uses.
        """
        switch_flows_cookies = defaultdict(set)
        for flows in stored_flows.values():
            for flow in flows:
                switch_flows_cookies[flow["switch"]].add(flow["flow"]["cookie"])

        switch_flows = defaultdict(list)
        for dpid, cookies in switch_flows_cookies.items():
            for cookie in cookies:
                switch_flows[dpid].append(
                    {
                        "cookie": cookie,
                        "cookie_mask": int(0xFFFFFFFFFFFFFFFF),
                        "table_id": Table.OFPTT_ALL.value,
                        "owner": "telemetry_int",
                    }
                )
        await self._send_flows(switch_flows, "delete")
        return switch_flows

    async def _remove_int_flows(
        self, stored_flows: dict[int, list[dict]]
    ) -> dict[str, list[dict]]:
        """Delete int flows given a prefiltered stored_flows. This method is meant
        to be used when you need to match all the flow match keys, so, typically when
        you're removing just a subset of INT flows.

        Removal is driven by the stored flows instead of EVC ids and dpids to also
        be able to handle the force mode when an EVC no longer exists. It also follows
        the same pattern that mef_eline currently uses.

        If cookie is set but has no cookie_mask, it'll set an all 1's mask to
        simplify mappings for callers
        """
        switch_flows = defaultdict(list)
        for flows in stored_flows.values():
            for flow in flows:
                if "cookie" in flow["flow"] and "cookie_mask" not in flow["flow"]:
                    flow["flow"]["cookie_mask"] = int(0xFFFFFFFFFFFFFFFF)
                switch_flows[flow["switch"]].append(flow["flow"])
        await self._send_flows(switch_flows, "delete")
        return switch_flows

    async def _install_int_flows(
        self, stored_flows: dict[int, list[dict]]
    ) -> dict[str, list[dict]]:
        """Install INT flow mods."""
        switch_flows = defaultdict(list)
        for flows in stored_flows.values():
            for flow in flows:
                switch_flows[flow["switch"]].append(flow["flow"])
        await self._send_flows(switch_flows, "install")
        return switch_flows

    async def _send_flows(
        self, switch_flows: dict[str, list[dict]], cmd: Literal["install", "delete"]
    ):
        """
        Send batched flows by dpid to flow_manager.
        """
        for dpid, flows in switch_flows.items():
            if flows:
                await self.controller.buffers.app.aput(
                    KytosEvent(
                        f"kytos.flow_manager.flows.single.{cmd}",
                        content={
                            "dpid": dpid,
                            "force": True,
                            "flow_dict": {"flows": flows},
                        },
                    )
                )

    async def list_expected_flows(self, evcs: dict[str, dict]) -> dict[str, list[dict]]:
        """List expected flows for given EVCs."""
        evcs = utils.sorted_evcs_by_svc_lvl(evcs)
        async with AsyncExitStack() as stack:
            _ = [
                await stack.enter_async_context(self._evcs_lock[evc_id])
                for evc_id in evcs
            ]
            return await self._list_expected_flows(evcs)

    async def _list_expected_flows(
        self, evcs: dict[str, dict]
    ) -> dict[str, list[dict]]:
        """List expected flows for given EVCs."""
        evcs = self._validate_map_enable_evcs(evcs, force=True)
        stored_flows = await api.get_stored_flows(
            utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX) for evc_id in evcs
        )

        int_flows = {}
        keys_to_pop = ("inserted_at", "updated_at", "state")

        for cookie, flows in self.flow_builder.build_int_flows(
            evcs, stored_flows
        ).items():
            built_flows = []
            table_count = defaultdict(int)
            for flow in flows:
                switch = self.controller.get_switch_by_dpid(flow["switch"])
                serializer = FlowFactory.get_class(switch, Flow04)
                ser_flow = serializer.from_dict(flow["flow"], switch)
                for key in keys_to_pop:
                    flow.pop(key, None)
                flow["flow_id"] = ser_flow.id
                flow["id"] = ser_flow.match_id
                table_count[ser_flow.table_id] += 1
                built_flows.append(flow)

            evc_id = utils.get_id_from_cookie(cookie)
            int_flows[evc_id] = {
                "count_total": len(built_flows),
                "count_table": table_count,
                "flows": built_flows,
            }
        return int_flows

    async def check_consistency(
        self,
        evcs: dict[str, dict],
        outcome: Optional[str] = None,
        inconsistent_action: Optional[str] = None,
    ) -> dict[str, dict]:
        """Check consistency of INT flows."""
        evcs = utils.sorted_evcs_by_svc_lvl(evcs)
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(self._consistency_lock)
            _ = [
                await stack.enter_async_context(self._evcs_lock[evc_id])
                for evc_id in evcs
            ]

            cookies = [
                utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX) for evc_id in evcs
            ]
            expected_flows_by_evc, stored_flows_by_cookie = await asyncio.gather(
                self._list_expected_flows(evcs), api.get_stored_flows(cookies)
            )

            to_fix_missing, to_fix_alien = defaultdict(list), defaultdict(list)
            to_fix_missing_len, to_fix_alien_len = 0, 0
            to_redeploy, to_disable = {}, {}

            results = {}
            for evc_id, evc in evcs.items():
                evc_result = {}
                # Expected
                expected_data = expected_flows_by_evc.get(evc_id, {})
                expected_list = expected_data.get("flows", [])
                expected_map = {f["flow_id"]: f for f in expected_list}
                # Stored
                cookie = utils.get_cookie(evc_id, settings.INT_COOKIE_PREFIX)
                stored_list = stored_flows_by_cookie.get(cookie, [])
                stored_map = {f["flow_id"]: f for f in stored_list}

                missing_ids = set(expected_map.keys()) - set(stored_map.keys())
                alien_ids = set(stored_map.keys()) - set(expected_map.keys())

                evc_result["expected_flows"] = expected_list
                evc_result["missing_flows"] = [expected_map[v] for v in missing_ids]
                evc_result["alien_flows"] = [stored_map[v] for v in alien_ids]

                is_consistent = not missing_ids and not alien_ids
                evc_result["outcome"] = (
                    "consistent" if is_consistent else "inconsistent"
                )

                if outcome and evc_result["outcome"] != outcome:
                    continue

                results[evc_id] = evc_result
                if is_consistent:
                    continue

                if evc_result["missing_flows"]:
                    length = len(evc_result["missing_flows"])
                    log.warning(
                        f"Consistency check INT: EVC {evc_id}, missing {length} flows: "
                        f"{evc_result['missing_flows']}"
                    )
                    to_fix_missing_len += length
                    if inconsistent_action == "fix":
                        to_fix_missing[cookie].extend(evc_result["missing_flows"])

                if evc_result["alien_flows"]:
                    length = len(evc_result["alien_flows"])
                    log.warning(
                        f"Consistency check INT: EVC {evc_id}, {length} alien flows: "
                        f"{evc_result['alien_flows']}"
                    )
                    to_fix_alien_len += length
                    if inconsistent_action == "fix":
                        to_fix_alien[cookie].extend(evc_result["alien_flows"])

                if inconsistent_action == "redeploy":
                    to_redeploy[evc_id] = evc
                elif inconsistent_action == "disable":
                    to_disable[evc_id] = evc

            if to_fix_alien:
                log.info(f"Consistency check INT: will remove {to_fix_alien_len} flows")
                await self._remove_int_flows(to_fix_alien)
            if to_fix_missing:
                log.info(
                    f"Consistency check INT: will install {to_fix_missing_len} flows"
                )
                await self._install_int_flows(to_fix_missing)

        if to_redeploy:
            log.info(f"Consistency check INT: will redeploy {len(to_redeploy)} EVCs")
            await self.redeploy_int(to_redeploy)
        if to_disable:
            log.info(f"Consistency check INT: will disable {len(to_disable)} EVCs")
            await self.disable_int(evcs, force=True, reason="consistency_check")

        return results
