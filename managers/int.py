"""INTManager module."""
import asyncio
from collections import defaultdict
from datetime import datetime


from kytos.core.events import KytosEvent
from napps.kytos.telemetry_int import utils
from napps.kytos.telemetry_int import settings
from kytos.core import log
import napps.kytos.telemetry_int.kytos_api_helper as api
from napps.kytos.telemetry_int.managers import flow_builder


class INTManager:

    """INTManager encapsulates and aggregates telemetry-related functionalities."""

    def __init__(self, controller) -> None:
        """INTManager."""
        self.controller = controller

    async def disable_int(self, evcs: dict[str, dict]) -> None:
        """Disable INT on EVCs.

        evcs is a dict of prefetched EVCs from mef_eline based on evc_ids.
        """
        log.info(f"Disabling telemetry INT on EVC ids: {list(evcs.keys())}")

        stored_flows = await api.get_stored_flows(
            [utils.get_cookie(evc_id, settings.COOKIE_PREFIX) for evc_id in evcs]
        )

        metadata = {
            "telemetry": {
                "enabled": False,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            }
        }
        await asyncio.gather(
            self._remove_int_flows(stored_flows), api.add_evcs_metadata(evcs, metadata)
        )

    async def enable_int(self, evcs: dict[str, dict]) -> None:
        """Enable INT on EVCs.

        evcs is a dict of prefetched EVCs from mef_eline based on evc_ids.
        """
        log.info(f"Enabling telemetry INT on EVC ids: {list(evcs.keys())}")

        stored_flows = await api.get_stored_flows(
            [utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX) for evc_id in evcs]
        )

        stored_flows = flow_builder.build_int_flows(evcs, stored_flows)

        metadata = {
            "telemetry": {
                "enabled": True,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            }
        }
        await asyncio.gather(
            self._install_int_flows(stored_flows), api.add_evcs_metadata(evcs, metadata)
        )

    async def _remove_int_flows(
        self, stored_flows: dict[int, list[dict]]
    ) -> None:
        """Delete int flows given a prefiltered stored_flows.

        Removal is driven by the stored flows instead of EVC ids and dpids to also
        be able to handle the force mode when an EVC no longer exists. It also follows
        the same pattern that mef_eline currently uses.

        The flows will be batched per dpid based on settings.BATCH_SIZE and will wait
        for settings.BATCH_INTERVAL per batch iteration.

        """
        switch_flows = defaultdict(set)
        for cookie, flows in stored_flows.items():
            for flow in flows:
                switch_flows[flow["switch"]].add(flow["flow"]["cookie"])

        for dpid, cookies in switch_flows.items():
            cookie_vals = list(cookies)
            batch_size = settings.BATCH_SIZE
            if batch_size <= 0:
                batch_size = len(cookie_vals)

            for i in range(0, len(cookie_vals), batch_size):
                flows = [
                    {"cookie": cookie, "cookie_mask": int(0xFFFFFFFFFFFFFFFF)}
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
                await asyncio.sleep(settings.BATCH_INTERVAL)

    async def _install_int_flows(self, stored_flows: dict[int, list]) -> None:
        """Install INT flow mods.

        The flows will be batched per dpid based on settings.BATCH_SIZE and will wait
        for settings.BATCH_INTERVAL per batch iteration.
        """

        switch_flows = defaultdict(list)
        for cookie, flows in stored_flows.items():
            for flow in flows:
                switch_flows[flow["switch"]].add(flow["flow"])

        for dpid, flows in switch_flows.items():
            flow_vals = list(flows)
            batch_size = settings.BATCH_SIZE
            if batch_size <= 0:
                batch_size = len(flow_vals)

            for i in range(0, len(flow_vals), batch_size):
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
                await asyncio.sleep(settings.BATCH_INTERVAL)
