"""Main module of kytos/telemetry Network Application.

Napp to deploy In-band Network Telemetry over Ethernet Virtual Circuits

"""

import asyncio
import copy
import pathlib
from datetime import datetime

import napps.kytos.telemetry_int.kytos_api_helper as api
from napps.kytos.telemetry_int import settings, utils
from tenacity import RetryError

from kytos.core import KytosEvent, KytosNApp, log, rest
from kytos.core.common import EntityStatus
from kytos.core.helpers import alisten_to, avalidate_openapi_request, load_spec
from kytos.core.rest_api import HTTPException, JSONResponse, Request, aget_json_or_400

from .exceptions import (
    EVCError,
    EVCHasINT,
    EVCHasNoINT,
    EVCNotFound,
    FlowsNotFound,
    ProxyPortConflict,
    ProxyPortError,
    ProxyPortNotFound,
    ProxyPortSameSourceIntraEVC,
    ProxyPortShared,
    UnrecoverableError,
)
from .managers.int import INTManager


class Main(KytosNApp):
    """Main class of kytos/telemetry NApp.

    This class is the entry point for this NApp.
    """

    spec = load_spec(pathlib.Path(__file__).parent / "openapi.yml")

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.

        The setup method is automatically called by the controller when your
        application is loaded.

        So, if you have any setup routine, insert it here.
        """

        self.int_manager = INTManager(self.controller)
        self._ofpt_error_lock = asyncio.Lock()

    def execute(self):
        """Run after the setup method execution.

        You can also use this method in loop mode if you add to the above setup
        method a line like the following example:

            self.execute_as_loop(30)  # 30-second interval.
        """

    def shutdown(self):
        """Run when your NApp is unloaded.

        If you have some cleanup procedure, insert it here.
        """

    @rest("v1/evc/enable", methods=["POST"])
    async def enable_telemetry(self, request: Request) -> JSONResponse:
        """REST to enable INT flows on EVCs.

        If a list of evc_ids is empty, it'll enable on non-INT EVCs.
        """
        await avalidate_openapi_request(self.spec, request)

        try:
            content = await aget_json_or_400(request)
            evc_ids = content["evc_ids"]
            force = content.get("force", False)
            proxy_port_enabled = content.get("proxy_port_enabled")
        except (TypeError, KeyError):
            raise HTTPException(400, detail=f"Invalid payload: {content}")

        try:
            evcs = (
                await api.get_evcs()
                if len(evc_ids) != 1
                else await api.get_evc(evc_ids[0])
            )
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)

        if evc_ids:
            evcs = {
                evc_id: utils.set_proxy_port_value(
                    evcs.get(evc_id, {}), proxy_port_enabled
                )
                for evc_id in evc_ids
            }
        else:
            evcs = {
                k: utils.set_proxy_port_value(v, proxy_port_enabled)
                for k, v in evcs.items()
                if not utils.has_int_enabled(v)
            }
            if not evcs:
                # There's no non-INT EVCs to get enabled.
                return JSONResponse(list(evcs.keys()))

        try:
            await self.int_manager.enable_int(
                evcs,
                force=force,
                proxy_port_enabled=proxy_port_enabled,
                set_proxy_port_metadata=True,
            )
        except (EVCNotFound, FlowsNotFound, ProxyPortNotFound) as exc:
            raise HTTPException(404, detail=str(exc))
        except (EVCHasINT, ProxyPortConflict) as exc:
            raise HTTPException(409, detail=str(exc))
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)
        except UnrecoverableError as exc:
            exc_error = str(exc)
            log.error(exc_error)
            raise HTTPException(500, detail=exc_error)

        return JSONResponse(list(evcs.keys()), status_code=201)

    @rest("v1/evc/disable", methods=["POST"])
    async def disable_telemetry(self, request: Request) -> JSONResponse:
        """REST to disable/remove INT flows for an EVC_ID

        If a list of evc_ids is empty, it'll disable on all INT EVCs.
        """
        await avalidate_openapi_request(self.spec, request)

        try:
            content = await aget_json_or_400(request)
            evc_ids = content["evc_ids"]
            force = content.get("force", False)
        except (TypeError, KeyError):
            raise HTTPException(400, detail=f"Invalid payload: {content}")

        try:
            evcs = (
                await api.get_evcs()
                if len(evc_ids) != 1
                else await api.get_evc(evc_ids[0])
            )
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)

        if evc_ids:
            evcs = {evc_id: evcs.get(evc_id, {}) for evc_id in evc_ids}
        else:
            evcs = {k: v for k, v in evcs.items() if utils.has_int_enabled(v)}
            if not evcs:
                # There's no INT EVCs to get disabled.
                return JSONResponse(list(evcs.keys()))

        try:
            await self.int_manager.disable_int(evcs, force)
        except EVCNotFound as exc:
            raise HTTPException(404, detail=str(exc))
        except EVCHasNoINT as exc:
            raise HTTPException(409, detail=str(exc))
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)
        except UnrecoverableError as exc:
            exc_error = str(exc)
            log.error(exc_error)
            raise HTTPException(500, detail=exc_error)

        return JSONResponse(list(evcs.keys()))

    @rest("v1/evc")
    async def get_evcs(self, _request: Request) -> JSONResponse:
        """REST to return the list of EVCs with INT enabled"""
        try:
            evcs = await api.get_evcs(**{"metadata.telemetry.enabled": "true"})
            return JSONResponse(evcs)
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)
        except UnrecoverableError as exc:
            exc_error = str(exc)
            log.error(exc_error)
            raise HTTPException(500, detail=exc_error)

    @rest("v1/evc/expected_flows", methods=["POST"])
    async def evc_expected_flows(self, request: Request) -> JSONResponse:
        """List expected flows for given INT EVCs."""
        await avalidate_openapi_request(self.spec, request)
        try:
            content = await aget_json_or_400(request)
            evc_ids = content["evc_ids"]
        except (TypeError, KeyError):
            raise HTTPException(400, detail=f"Invalid payload: {content}")

        try:
            evcs = (
                await api.get_evcs()
                if len(evc_ids) != 1
                else await api.get_evc(evc_ids[0])
            )
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)
        except UnrecoverableError as exc:
            exc_error = str(exc)
            log.error(exc_error)
            raise HTTPException(500, detail=exc_error)

        if evc_ids:
            evcs = {evc_id: evcs.get(evc_id, {}) for evc_id in evc_ids}
        else:
            evcs = {k: v for k, v in evcs.items() if utils.has_int_enabled(v)}
            if not evcs:
                return JSONResponse({})

        try:
            int_flows = await self.int_manager.list_expected_flows(evcs)
            return JSONResponse(int_flows)
        except (EVCNotFound, FlowsNotFound, ProxyPortNotFound) as exc:
            raise HTTPException(404, detail=str(exc))
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)
        except UnrecoverableError as exc:
            exc_error = str(exc)
            log.error(exc_error)
            raise HTTPException(500, detail=exc_error)

    @rest("v1/evc/redeploy", methods=["PATCH"])
    async def redeploy_telemetry(self, request: Request) -> JSONResponse:
        """REST to redeploy INT on EVCs.

        If a list of evc_ids is empty, it'll redeploy on all INT EVCs.
        """
        await avalidate_openapi_request(self.spec, request)

        try:
            content = await aget_json_or_400(request)
            evc_ids = content["evc_ids"]
        except (TypeError, KeyError):
            raise HTTPException(400, detail=f"Invalid payload: {content}")

        try:
            evcs = (
                await api.get_evcs()
                if len(evc_ids) != 1
                else await api.get_evc(evc_ids[0])
            )
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)

        if evc_ids:
            evcs = {evc_id: evcs.get(evc_id, {}) for evc_id in evc_ids}
        else:
            evcs = {k: v for k, v in evcs.items() if utils.has_int_enabled(v)}
            if not evcs:
                raise HTTPException(404, detail="There aren't INT EVCs to redeploy")

        try:
            await self.int_manager.redeploy_int(evcs)
        except (EVCNotFound, FlowsNotFound, ProxyPortNotFound) as exc:
            raise HTTPException(404, detail=str(exc))
        except (EVCHasNoINT, ProxyPortSameSourceIntraEVC, ProxyPortShared) as exc:
            raise HTTPException(409, detail=str(exc))
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)
        except UnrecoverableError as exc:
            exc_error = str(exc)
            log.error(exc_error)
            raise HTTPException(500, detail=exc_error)

        return JSONResponse(list(evcs.keys()), status_code=201)

    @rest("v1/evc/compare")
    async def evc_compare(self, _request: Request) -> JSONResponse:
        """List and compare which INT EVCs have flows installed comparing with
        mef_eline flows and telemetry metadata. You should use this endpoint
        to confirm if both the telemetry metadata is still coherent and also
        the minimum expected number of flows. A list of EVCs will get returned
        with the inconsistent INT EVCs. If you encounter any inconsistent
        EVC you need to analyze the situation and then decide if you'd
        like to force enable or disable INT.
        """

        try:
            int_flows, mef_flows, evcs = await asyncio.gather(
                api.get_stored_flows(
                    [
                        (
                            settings.INT_COOKIE_PREFIX << 56,
                            settings.INT_COOKIE_PREFIX << 56 | 0xFFFFFFFFFFFFFF,
                        ),
                    ]
                ),
                api.get_stored_flows(
                    [
                        (
                            settings.MEF_COOKIE_PREFIX << 56,
                            settings.MEF_COOKIE_PREFIX << 56 | 0xFFFFFFFFFFFFFF,
                        ),
                    ]
                ),
                api.get_evcs(),
            )
        except RetryError as exc:
            exc_error = str(exc.last_attempt.exception())
            log.error(exc_error)
            raise HTTPException(503, detail=exc_error)
        except UnrecoverableError as exc:
            exc_error = str(exc)
            log.error(exc_error)
            raise HTTPException(500, detail=exc_error)

        response = [
            {"id": k, "name": evcs[k]["name"], "compare_reason": v}
            for k, v in self.int_manager.evc_compare(int_flows, mef_flows, evcs).items()
        ]
        return JSONResponse(response)

    @rest("v1/uni/{interface_id}/proxy_port", methods=["DELETE"])
    async def delete_proxy_port_metadata(self, request: Request) -> JSONResponse:
        """Delete proxy port metadata."""
        intf_id = request.path_params["interface_id"]
        intf = self.controller.get_interface_by_id(intf_id)
        if not intf:
            raise HTTPException(404, detail=f"Interface id {intf_id} not found")
        if "proxy_port" not in intf.metadata:
            return JSONResponse("Operation successful")

        qparams = request.query_params
        force = qparams.get("force", "false").lower() == "true"

        try:
            pp = self.int_manager.srcs_pp[self.int_manager.unis_src[intf_id]]
            if pp.evc_ids and not force:
                return JSONResponse(
                    {
                        "status_code": 409,
                        "code": 409,
                        "description": f"{pp} is in use on {len(pp.evc_ids)} EVCs",
                        "evc_ids": sorted(pp.evc_ids),
                    },
                    status_code=409,
                )
        except KeyError:
            pass

        try:
            await api.delete_proxy_port_metadata(intf_id)
            return JSONResponse("Operation successful")
        except ValueError as exc:
            raise HTTPException(404, detail=str(exc))
        except UnrecoverableError as exc:
            raise HTTPException(500, detail=str(exc))

    @rest("v1/uni/{interface_id}/proxy_port/{port_number:int}", methods=["POST"])
    async def add_proxy_port_metadata(self, request: Request) -> JSONResponse:
        """Add proxy port metadata."""
        intf_id = request.path_params["interface_id"]
        port_no = request.path_params["port_number"]
        qparams = request.query_params
        if not (intf := self.controller.get_interface_by_id(intf_id)):
            raise HTTPException(404, detail=f"Interface id {intf_id} not found")
        if "proxy_port" in intf.metadata and intf.metadata["proxy_port"] == port_no:
            return JSONResponse("Operation successful")

        force = qparams.get("force", "false").lower() == "true"
        try:
            pp = self.int_manager.get_proxy_port_or_raise(intf_id, "no_evc_id", port_no)
            if pp.status != EntityStatus.UP and not force:
                raise HTTPException(409, detail=f"{pp} status isn't UP")
            evcs = await api.get_evcs(**{"metadata.telemetry.enabled": "true"})
            self.int_manager._validate_existing_evcs_proxy_port_symmetry(intf, evcs)
            self.int_manager._validate_new_dedicated_proxy_port(intf, port_no)
        except RetryError as exc:
            raise HTTPException(424, detail=str(exc))
        except ProxyPortConflict as exc:
            raise HTTPException(409, detail=str(exc))
        except ProxyPortError as exc:
            raise HTTPException(404, detail=exc.message)

        try:
            await api.add_proxy_port_metadata(intf_id, port_no)
            return JSONResponse("Operation successful")
        except ValueError as exc:
            raise HTTPException(404, detail=str(exc))
        except UnrecoverableError as exc:
            raise HTTPException(500, detail=str(exc))

    @rest("v1/uni/proxy_port")
    async def list_uni_proxy_ports(self, _request: Request) -> JSONResponse:
        """List configured UNI proxy ports."""
        interfaces_proxy_ports = []
        for switch in self.controller.switches.copy().values():
            for intf in switch.interfaces.copy().values():
                if "proxy_port" in intf.metadata:
                    payload = {
                        "uni": {
                            "id": intf.id,
                            "status": intf.status.value,
                            "status_reason": sorted(intf.status_reason),
                        },
                        "proxy_port": {
                            "port_number": intf.metadata["proxy_port"],
                            "status": "DOWN",
                            "status_reason": [],
                        },
                    }
                    try:
                        pp = self.int_manager.get_proxy_port_or_raise(
                            intf.id, "no_evc_id"
                        )
                        payload["proxy_port"]["status"] = pp.status.value
                    except ProxyPortError as exc:
                        payload["proxy_port"]["status_reason"] = [exc.message]
                    interfaces_proxy_ports.append(payload)
        return JSONResponse(interfaces_proxy_ports)

    @alisten_to("kytos/mef_eline.evcs_loaded")
    async def on_mef_eline_evcs_loaded(self, event: KytosEvent) -> None:
        """Handle kytos/mef_eline.evcs_loaded."""
        self.int_manager.load_uni_src_proxy_ports(event.content)

    @alisten_to("kytos/of_multi_table.enable_table")
    async def on_table_enabled(self, event):
        """Handle of_multi_table.enable_table."""
        table_group = event.content.get("telemetry_int", {})
        if not table_group:
            return
        for group in table_group:
            if group not in settings.TABLE_GROUP_ALLOWED:
                log.error(
                    f'The table group "{group}" is not allowed for '
                    f"telemetry_int. Allowed table groups are "
                    f"{settings.TABLE_GROUP_ALLOWED}"
                )
                return
        self.int_manager.flow_builder.table_group.update(table_group)
        content = {"group_table": self.int_manager.flow_builder.table_group}
        event_out = KytosEvent(name="kytos/telemetry_int.enable_table", content=content)
        await self.controller.buffers.app.aput(event_out)

    @alisten_to("kytos/mef_eline.deleted")
    async def on_evc_deleted(self, event: KytosEvent) -> None:
        """On EVC deleted."""
        content = event.content
        if (
            "metadata" in content
            and "telemetry" in content["metadata"]
            and content["metadata"]["telemetry"]["enabled"]
        ):
            evc_id = content["id"]
            log.info(f"Handling mef_eline.deleted on EVC id: {evc_id}")
            await self.int_manager.disable_int({evc_id: content}, force=True)

    @alisten_to("kytos/mef_eline.deployed")
    async def on_evc_deployed(self, event: KytosEvent) -> None:
        """On EVC deployed."""
        content = event.content
        evc_id = content["id"]
        evcs = {evc_id: content}
        try:
            if (
                "metadata" in content
                and "telemetry" in content["metadata"]
                and content["metadata"]["telemetry"]["enabled"]
            ):
                log.info(f"Handling mef_eline.deployed on EVC id: {evc_id}")
                await self.int_manager.redeploy_int(evcs)
            elif (
                "metadata" in content
                and "telemetry_request" in content["metadata"]
                and "telemetry" not in content["metadata"]
            ):
                log.info(f"Handling mef_eline.deployed on EVC id: {evc_id}")
                proxy_port_enabled = content["metadata"].get("proxy_port_enabled")
                await self.int_manager.enable_int(
                    evcs,
                    force=True,
                    proxy_port_enabled=proxy_port_enabled,
                    set_proxy_port_metadata=True,
                )
        except (EVCError, RetryError, UnrecoverableError) as exc:
            excs = str(exc)
            if isinstance(exc, RetryError):
                excs = str(exc.last_attempt.exception())
            log.error(
                f"Failed when handling mef_eline.deployed: {excs}. Analyze the error "
                f"and you'll need to enable or redeploy EVC {evc_id} later"
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
                    f"Failed to set INT metadata, Exception: {excs}, "
                    f"when handling mef_eline.deployed on EVC id: {evc_id} "
                    "You need to solve the error and then force enable INT"
                )

    @alisten_to("kytos/mef_eline.undeployed")
    async def on_evc_undeployed(self, event: KytosEvent) -> None:
        """On EVC undeployed."""
        content = event.content
        if (
            not content["enabled"]
            and "metadata" in content
            and "telemetry" in content["metadata"]
            and content["metadata"]["telemetry"]["enabled"]
        ):
            metadata = {
                "telemetry": {
                    "enabled": True,
                    "status": "DOWN",
                    "status_reason": ["undeployed"],
                    "status_updated_at": datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                }
            }
            evc_id = content["id"]
            evcs = {evc_id: content}
            log.info(f"Handling mef_eline.undeployed on EVC id: {evc_id}")
            await self.int_manager.remove_int_flows(evcs, metadata, force=True)

    @alisten_to("kytos/mef_eline.(redeployed_link_down|redeployed_link_up)")
    async def on_evc_redeployed_link(self, event: KytosEvent) -> None:
        """On EVC redeployed_link_down|redeployed_link_up."""
        content = event.content
        if (
            content["enabled"]
            and "metadata" in content
            and "telemetry" in content["metadata"]
            and content["metadata"]["telemetry"]["enabled"]
        ):
            evc_id = content["id"]
            evcs = {evc_id: content}
            log.info(f"Handling {event.name}, EVC id: {evc_id}")
            try:
                await self.int_manager.redeploy_int(evcs)
            except EVCError as exc:
                log.error(
                    f"Failed to redeploy: {exc}. "
                    f"Analyze the error and you'll need to redeploy EVC {evc_id} later"
                )

    @alisten_to("kytos/mef_eline.error_redeploy_link_down")
    async def on_evc_error_redeployed_link_down(self, event: KytosEvent) -> None:
        """On EVC error_redeploy_link_down, this is supposed to happen when
        a path isn't when mef_eline handles a link down."""
        content = event.content
        if (
            content["enabled"]
            and "metadata" in content
            and "telemetry" in content["metadata"]
            and content["metadata"]["telemetry"]["enabled"]
        ):
            metadata = {
                "telemetry": {
                    "enabled": True,
                    "status": "DOWN",
                    "status_reason": ["redeployed_link_down_no_path"],
                    "status_updated_at": datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                }
            }
            evc_id = content["id"]
            evcs = {evc_id: content}
            log.info(
                f"Handling mef_eline.redeployed_link_down_no_path on EVC id: {evc_id}"
            )
            await self.int_manager.remove_int_flows(evcs, metadata, force=True)

    @alisten_to("kytos/mef_eline.failover_link_down")
    async def on_failover_link_down(self, event: KytosEvent):
        """Handle kytos/mef_eline.failover_link_down."""
        await self.int_manager.handle_failover_flows(
            copy.deepcopy(event.content), event_name="failover_link_down"
        )

    @alisten_to("kytos/mef_eline.failover_old_path")
    async def on_failover_old_path(self, event: KytosEvent):
        """Handle kytos/mef_eline.failover_old_path."""
        await self.int_manager.handle_failover_flows(
            copy.deepcopy(event.content), event_name="failover_old_path"
        )

    @alisten_to("kytos/mef_eline.failover_deployed")
    async def on_failover_deployed(self, event: KytosEvent):
        """Handle kytos/mef_eline.failover_deployed."""
        await self.int_manager.handle_failover_flows(
            copy.deepcopy(event.content), event_name="failover_deployed"
        )

    @alisten_to("kytos/topology.link_down")
    async def on_link_down(self, event):
        """Handle topology.link_down."""
        await self.int_manager.handle_pp_link_down(event.content["link"])

    @alisten_to("kytos/topology.link_up")
    async def on_link_up(self, event):
        """Handle topology.link_up."""
        await self.int_manager.handle_pp_link_up(event.content["link"])

    @alisten_to("kytos/mef_eline.uni_active_updated")
    async def on_uni_active_updated(self, event: KytosEvent) -> None:
        """On mef_eline UNI active updated."""
        content = event.content
        if (
            "metadata" in content
            and "telemetry" in content["metadata"]
            and content["metadata"]["telemetry"]["enabled"]
        ):
            evc_id, active = content["id"], content["active"]
            log.info(
                f"Handling mef_eline.uni_active_updated active {active} "
                f"on EVC id: {evc_id}"
            )

            metadata = {
                "telemetry": {
                    "enabled": True,
                    "status": "UP" if active else "DOWN",
                    "status_reason": [] if active else ["uni_down"],
                    "status_updated_at": datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                }
            }
            await api.add_evcs_metadata({evc_id: content}, metadata)

    @alisten_to("kytos/flow_manager.flow.error")
    async def on_flow_mod_error(self, event: KytosEvent):
        """On flow mod errors.

        Only OFPT_ERRORs will be handled, telemetry_int already uses force: true
        """
        flow = event.content["flow"]
        if any(
            (
                event.content.get("error_exception"),
                event.content.get("error_command") != "add",
                flow.cookie >> 56 != settings.INT_COOKIE_PREFIX,
            )
        ):
            return

        async with self._ofpt_error_lock:
            evc_id = utils.get_id_from_cookie(flow.cookie)
            evc = await api.get_evc(evc_id, exclude_archived=False)
            if (
                not evc
                or "telemetry" not in evc[evc_id]["metadata"]
                or "enabled" not in evc[evc_id]["metadata"]["telemetry"]
                or not evc[evc_id]["metadata"]["telemetry"]["enabled"]
            ):
                return

            metadata = {
                "telemetry": {
                    "enabled": False,
                    "status": "DOWN",
                    "status_reason": ["ofpt_error"],
                    "status_updated_at": datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                }
            }
            log.error(
                f"Disabling EVC({evc_id}) due to OFPT_ERROR, "
                f"error_type: {event.content.get('error_type')}, "
                f"error_code: {event.content.get('error_code')}, "
                f"flow: {flow.as_dict()} "
            )
            evcs = evc
            await self.int_manager.remove_int_flows(evcs, metadata, force=True)

    @alisten_to("kytos/topology.interfaces.metadata.removed")
    async def on_intf_metadata_removed(self, event: KytosEvent) -> None:
        """On interface metadata removed."""
        await self.int_manager.handle_pp_metadata_removed(event.content["interface"])

    @alisten_to("kytos/topology.interfaces.metadata.added")
    async def on_intf_metadata_added(self, event: KytosEvent) -> None:
        """On interface metadata added."""
        await self.int_manager.handle_pp_metadata_added(event.content["interface"])
