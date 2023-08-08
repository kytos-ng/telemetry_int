"""Main module of kytos/telemetry Network Application.

Napp to deploy In-band Network Telemetry over Ethernet Virtual Circuits

"""
import copy
import itertools

from napps.kytos.telemetry_int import settings

from kytos.core import KytosNApp, rest
from kytos.core.events import KytosEvent
from kytos.core.rest_api import HTTPException, JSONResponse, Request, get_json_or_400

from .exceptions import ErrorBase, EvcHasNoINT, FlowsNotFound, NoProxyPortsAvailable
from .kytos_api_helper import get_evc, get_evc_flows, get_evcs
from .proxy_port import ProxyPort
from .utils import (
    add_to_apply_actions,
    get_cookie,
    get_cookie_telemetry,
    get_evc_unis,
    get_evc_with_telemetry,
    get_path_hop_interface_ids,
    get_proxy_port,
    has_int_enabled,
    is_intra_switch_evc,
    modify_actions,
    push_flows,
    set_instructions_from_actions,
    set_new_cookie,
    set_priority,
    set_telemetry_false_for_evc,
    set_telemetry_true_for_evc,
)

# pylint: disable=fixme


class Main(KytosNApp):
    """Main class of kytos/telemetry NApp.

    This class is the entry point for this NApp.
    """

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.

        The setup method is automatically called by the controller when your
        application is loaded.

        So, if you have any setup routine, insert it here.
        """

        # TODO: only loads after all other napps are loaded.

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

    @staticmethod
    def enable_int_source(
        source_uni: dict, evc: dict, proxy_port: ProxyPort
    ) -> list[dict]:
        """At the INT source, one flow becomes 3: one for UDP on table 0,
        one for TCP on table 0, and one on table 2
        On table 0, we use just new instructions: push_int and goto_table
        On table 2, we add add_int_metadata before the original actions
        INT flows will have higher priority. We don't delete the old flows.
        """
        new_flows = []
        new_int_flow_tbl_0_tcp = {}

        # Get the original flows
        dpid = source_uni["switch"]
        for flow in get_evc_flows(get_cookie(evc["id"]), dpid).get(dpid, []):
            if flow["flow"]["match"]["in_port"] == source_uni["port_number"]:
                new_int_flow_tbl_0_tcp = flow
                break

        if not new_int_flow_tbl_0_tcp:
            raise FlowsNotFound(evc["id"])

        set_instructions_from_actions(new_int_flow_tbl_0_tcp)
        set_new_cookie(new_int_flow_tbl_0_tcp)

        # Deepcopy to use for table 2 later
        new_int_flow_tbl_2 = copy.deepcopy(new_int_flow_tbl_0_tcp)

        # Prepare TCP Flow for Table 0
        new_int_flow_tbl_0_tcp["flow"]["match"]["dl_type"] = settings.IPv4
        new_int_flow_tbl_0_tcp["flow"]["match"]["nw_proto"] = settings.TCP
        # TODO: Create an exception for when the priority has reached max value
        set_priority(new_int_flow_tbl_0_tcp)

        # The flow_manager has two outputs: instructions and actions.
        instructions = [
            {
                "instruction_type": "apply_actions",
                "actions": [{"action_type": "push_int"}],
            },
            {"instruction_type": "goto_table", "table_id": settings.INT_TABLE},
        ]
        new_int_flow_tbl_0_tcp["flow"]["instructions"] = instructions

        # Prepare UDP Flow for Table 0. Everything the same as TCP except the nw_proto
        new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
        new_int_flow_tbl_0_udp["flow"]["match"]["nw_proto"] = settings.UDP

        # Prepare Flows for Table 2 - No TCP or UDP specifics
        new_int_flow_tbl_2["flow"]["table_id"] = settings.INT_TABLE

        # if intra-switch EVC, then output port should be the proxy
        if is_intra_switch_evc(evc):
            for instruction in new_int_flow_tbl_2["flow"]["instructions"]:
                if instruction["instruction_type"] == "apply_actions":
                    for action in instruction["actions"]:
                        if action["action_type"] == "output":
                            # Since this is the INT Source, we use source
                            # to avoid worrying about single or multi
                            # home physical loops.
                            # The choice for destination is at the INT Sink.
                            action["port"] = proxy_port.source.port_number

        instructions = add_to_apply_actions(
            new_int_flow_tbl_2["flow"]["instructions"],
            new_instruction={"action_type": "add_int_metadata"},
            position=0,
        )

        new_int_flow_tbl_2["flow"]["instructions"] = instructions

        new_flows.append(new_int_flow_tbl_0_tcp)
        new_flows.append(new_int_flow_tbl_0_udp)
        new_flows.append(new_int_flow_tbl_2)

        return new_flows

    @staticmethod
    def enable_int_hop(
        evc: dict, source_uni: dict, destination_uni: dict
    ) -> list[dict]:
        """At the INT hops, one flow adds two more: one for UDP on table 0,
        one for TCP on table 0. On table 0, we add 'add_int_metadata'
        before other actions. We use source and destination to create the
        unidirectional support for telemetry.
        """

        new_flows = []
        dpid_ports, dpids = set(), set()
        intf_ids = get_path_hop_interface_ids(evc, source_uni, destination_uni)
        for interface_id in intf_ids:
            intf_split = interface_id.split(":")
            switch, port_number = ":".join(intf_split[:-1]), int(intf_split[-1])
            dpid_ports.add((switch, port_number))
            dpids.add(switch)

        for flow in itertools.chain(
            *get_evc_flows(get_cookie(evc["id"]), *dpids).values()
        ):
            if "match" not in flow["flow"] or "in_port" not in flow["flow"]["match"]:
                continue
            if (flow["switch"], flow["flow"]["match"]["in_port"]) not in dpid_ports:
                continue

            new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
            set_instructions_from_actions(new_int_flow_tbl_0_tcp)
            set_new_cookie(flow)

            # Prepare TCP Flow
            new_int_flow_tbl_0_tcp["flow"]["match"]["dl_type"] = settings.IPv4
            new_int_flow_tbl_0_tcp["flow"]["match"]["nw_proto"] = settings.TCP
            set_priority(new_int_flow_tbl_0_tcp)

            for instruction in new_int_flow_tbl_0_tcp["flow"]["instructions"]:
                if instruction["instruction_type"] == "apply_actions":
                    instruction["actions"].insert(
                        0, {"action_type": "add_int_metadata"}
                    )

            # Prepare UDP Flow
            new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
            new_int_flow_tbl_0_udp["flow"]["match"]["nw_proto"] = settings.UDP

            new_flows.append(new_int_flow_tbl_0_tcp)
            new_flows.append(new_int_flow_tbl_0_udp)

        return new_flows

    @staticmethod
    def enable_int_sink(destination_uni: dict, evc: dict, proxy_port: ProxyPort):
        """At the INT sink, one flow becomes many:
        1. Before the proxy, we do add_int_metadata as an INT hop.
        We need to keep the set_queue
        2. After the proxy, we do send_report and pop_int and output
        We only use table 0 for #1.
        We use table 2 for #2. for pop_int and output
        """
        new_flows = []
        dpid = destination_uni["switch"]
        for flow in get_evc_flows(get_cookie(evc["id"]), dpid).get(dpid, []):
            # Only consider flows coming from NNI interfaces
            if flow["flow"]["match"]["in_port"] == destination_uni["port_number"]:
                continue

            new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
            set_new_cookie(flow)

            if not new_int_flow_tbl_0_tcp:
                raise FlowsNotFound(evc["id"])

            set_instructions_from_actions(new_int_flow_tbl_0_tcp)
            # Save for pos-proxy flows
            new_int_flow_tbl_0_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)
            new_int_flow_tbl_2_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)

            # Prepare TCP Flow for Table 0 PRE proxy
            if not is_intra_switch_evc(evc):
                new_int_flow_tbl_0_tcp["flow"]["match"]["dl_type"] = settings.IPv4
                new_int_flow_tbl_0_tcp["flow"]["match"]["nw_proto"] = settings.TCP
                set_priority(new_int_flow_tbl_0_tcp)

                # Add telemetry, keep set_queue, output to the proxy port.
                output_port_no = proxy_port.source.port_number
                for instruction in new_int_flow_tbl_0_tcp["flow"]["instructions"]:
                    if instruction["instruction_type"] == "apply_actions":
                        # Keep set_queue
                        actions = modify_actions(
                            instruction["actions"],
                            ["pop_vlan", "push_vlan", "set_vlan", "output"],
                            remove=True,
                        )
                        actions.insert(0, {"action_type": "add_int_metadata"})
                        actions.append(
                            {"action_type": "output", "port": output_port_no}
                        )
                        instruction["actions"] = actions

                # Prepare UDP Flow for Table 0
                new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
                new_int_flow_tbl_0_udp["flow"]["match"]["nw_proto"] = settings.UDP

                new_flows.append(copy.deepcopy(new_int_flow_tbl_0_tcp))
                new_flows.append(copy.deepcopy(new_int_flow_tbl_0_udp))
                del instruction  # pylint: disable=W0631

            # Prepare Flows for Table 0 AFTER proxy. No difference between TCP or UDP
            in_port_no = proxy_port.destination.port_number

            new_int_flow_tbl_0_pos["flow"]["match"]["in_port"] = in_port_no
            set_priority(new_int_flow_tbl_0_tcp)

            instructions = [
                {
                    "instruction_type": "apply_actions",
                    "actions": [{"action_type": "send_report"}],
                },
                {"instruction_type": "goto_table", "table_id": settings.INT_TABLE},
            ]
            new_int_flow_tbl_0_pos["flow"]["instructions"] = instructions

            # Prepare Flows for Table 2 POS proxy
            new_int_flow_tbl_2_pos["flow"]["match"]["in_port"] = in_port_no
            new_int_flow_tbl_2_pos["flow"]["table_id"] = settings.INT_TABLE

            for instruction in new_int_flow_tbl_2_pos["flow"]["instructions"]:
                if instruction["instruction_type"] == "apply_actions":
                    instruction["actions"].insert(0, {"action_type": "pop_int"})

            new_flows.append(copy.deepcopy(new_int_flow_tbl_0_pos))
            new_flows.append(copy.deepcopy(new_int_flow_tbl_2_pos))

        return new_flows

    def provision_int_unidirectional(
        self, evc: dict, source_uni: dict, destination_uni: dict, proxy_port: ProxyPort
    ) -> bool:
        """Create INT flows from source to destination."""

        # Create flows for the first switch (INT Source)
        new_flows = self.enable_int_source(source_uni, evc, proxy_port)

        # Create flows the INT hops
        new_flows += list(self.enable_int_hop(evc, source_uni, destination_uni))

        # # Create flows for the last switch (INT Sink)
        new_flows += list(self.enable_int_sink(destination_uni, evc, proxy_port))

        return push_flows(new_flows)

    # pylint: disable=too-many-branches
    def provision_int(self, evc: dict) -> str:
        """Create telemetry flows for an EVC."""

        # TODO refactor to always ensure it has proxy port based on EP031 augmented

        # Get the EVC endpoints
        evc_id = evc["id"]
        uni_a, uni_z = get_evc_unis(evc)

        # Check if there are proxy ports on the endpoints' switches
        uni_a_proxy_port = get_proxy_port(self.controller, uni_a["interface_id"])
        uni_z_proxy_port = get_proxy_port(self.controller, uni_z["interface_id"])

        # INT is enabled per direction.
        # It's possible and acceptable to have INT just in one direction.

        # Direction uni_z -> uni_a
        if uni_a_proxy_port:
            self.provision_int_unidirectional(evc, uni_z, uni_a, uni_a_proxy_port)
            # change EVC metadata "telemetry": {"enabled": true } via API

        # Direction uni_a -> uni_z
        if uni_z_proxy_port:
            self.provision_int_unidirectional(evc, uni_a, uni_z, uni_z_proxy_port)

        # Change EVC metadata "telemetry": {"enabled": true } via API
        if uni_a_proxy_port and uni_z_proxy_port:
            if not set_telemetry_true_for_evc(evc_id, "bidirectional"):
                raise ErrorBase(
                    evc_id, "failed to add telemetry bidirectional metadata"
                )
            msg = f"INT enabled for EVC ID {evc_id} on both directions"

        elif uni_a_proxy_port or uni_z_proxy_port:
            if not set_telemetry_true_for_evc(evc_id, "unidirectional"):
                raise ErrorBase(
                    evc_id, "failed to add telemetry unidirectional metadata"
                )

            msg = f"INT enabled for EVC ID {evc_id} on direction "
            if uni_z_proxy_port:
                msg += (
                    f"{evc['uni_a']['interface_id']} -> {evc['uni_z']['interface_id']}"
                )
            else:
                msg += (
                    f"{evc['uni_z']['interface_id']} -> {evc['uni_a']['interface_id']}"
                )

        else:
            raise NoProxyPortsAvailable(evc_id)

        return msg

    # pylint: enable=too-many-branches

    def decommission_int(self, evc: dict) -> str:
        """Remove all INT flows for an EVC"""

        evc_id = evc["id"]
        self.remove_int_flows(evc)

        # Update mef_eline.
        if not set_telemetry_false_for_evc(evc_id):
            raise ErrorBase(evc_id, "failed to disable telemetry metadata")

        return f"EVC ID {evc_id} is no longer INT-enabled."

    def remove_int_flows(self, evc: dict) -> None:
        """Delete int flows of a given EVC."""
        cookie = get_cookie_telemetry(evc["id"])
        dpids = set()
        for path_item in itertools.chain(
            evc.get("current_path", []),
            evc.get("failover_path", []),
            evc.get("primary_path", []),
            evc.get("backup_path", []),
        ):
            dpids.add(path_item["endpoint_a"]["switch"])
            dpids.add(path_item["endpoint_b"]["switch"])

        for dpid in dpids:
            event = KytosEvent(
                "kytos.flow_manager.flows.delete",
                content={
                    "dpid": dpid,
                    "flow_dict": {
                        "force": True,
                        "flows": [
                            {"cookie": cookie, "cookie_mask": int(0xFFFFFFFFFFFFFFFF)}
                        ],
                    },
                },
            )
            self.controller.buffers.app.put(event)

    # REST methods

    @rest("v1/evc/enable", methods=["POST"])
    def enable_telemetry(self, request: Request) -> JSONResponse:
        """REST to enable/create INT flows for one or more EVC_IDs.
                  evcs are provided via POST as a list
        Args:
            {"evc_ids": [list of evc_ids] }

        Returns:
            200 and outcomes for each evc listed.
        """

        try:
            content = get_json_or_400(request, self.controller.loop)
            evc_ids = content["evc_ids"]
        except (TypeError, KeyError):
            raise HTTPException(400, detail=f"Invalid payload: {content}")

        status = {}
        evcs = get_evcs() if len(evc_ids) != 1 else get_evc(evc_ids[0])

        # TODO extract this and cover proxy port validations too
        for evc_id in evc_ids:
            if evc_id not in evcs:
                raise HTTPException(404, detail=f"EVC {evc_id} doesn't exist")
            if has_int_enabled(evcs[evc_id]):
                raise HTTPException(400, detail=f"EVC {evc_id} already has INT enabled")

        if not evc_ids:
            # Enable telemetry for ALL non INT EVCs.
            evcs = {k: v for k, v in evcs.items() if not has_int_enabled(v)}
        else:
            evcs = {evc_id: evcs[evc_id] for evc_id in evc_ids}

        # Process each EVC individually
        # TODO dispatch in batch and update metadata in bulk shortly after
        for evc_id, evc in evcs.items():
            try:
                status[evc_id] = self.provision_int(evc)
            except ErrorBase as err_msg:
                status[evc_id] = err_msg.message

        return JSONResponse(status)

    @rest("v1/evc/disable", methods=["POST"])
    def disable_telemetry(self, request: Request) -> JSONResponse:
        """REST to disable/remove INT flows for an EVC_ID
        Args:
            {"evc_ids": [list of evc_ids] }
        Returns:
            200 if successful
            400 is otherwise
        """
        try:
            content = get_json_or_400(request, self.controller.loop)
            evc_ids = content["evc_ids"]
        except (TypeError, KeyError):
            raise HTTPException(400, detail=f"Invalid payload: {content}")

        status = {}

        evcs = get_evcs() if len(evc_ids) != 1 else get_evc(evc_ids[0])

        # TODO extract this and cover proxy port validations too
        for evc_id in evc_ids:
            if evc_id not in evcs:
                raise HTTPException(404, detail=f"EVC {evc_id} doesn't exist")
            if not has_int_enabled(evcs[evc_id]):
                raise HTTPException(
                    400, detail=f"EVC {evc_id} doesn't have INT enabled"
                )

        if not evc_ids:
            # Enable telemetry for ALL INT EVCs.
            evcs = {k: v for k, v in evcs.items() if has_int_enabled(v)}
        else:
            evcs = {evc_id: evcs[evc_id] for evc_id in evc_ids}

        # Process each EVC individually
        # TODO dispatch in batch and update metadata in bulk shortly after
        for evc_id, evc in evcs.items():
            try:
                status[evc_id] = self.decommission_int(evc)
            except EvcHasNoINT as err_msg:
                # Ignore since it is not an issue.
                status[evc_id] = err_msg.message
            except ErrorBase as err_msg:
                # Rollback INT configuration. This error will lead to inconsistency.
                # Critical
                status[evc_id] = err_msg.message

        return JSONResponse(status)

    @rest("v1/evc")
    def get_evcs(self, _request: Request) -> JSONResponse:
        """REST to return the list of EVCs with INT enabled"""
        return JSONResponse(get_evc_with_telemetry())

    @rest("v1/sync")
    def sync_flows(self, _request: Request) -> JSONResponse:
        """Endpoint to force the telemetry napp to search for INT flows and delete them
        accordingly to the evc metadata."""

        # TODO
        # for evc_id in get_evcs_ids():
        return JSONResponse("TBD")

    @rest("v1/evc/update")
    def update_evc(self, _request: Request) -> JSONResponse:
        """If an EVC changed from unidirectional to bidirectional telemetry,
        make the change."""
        return JSONResponse({})

    # Event-driven methods: future
    def listen_for_new_evcs(self):
        """Change newly created EVC to INT-enabled EVC based on the metadata field
        (future)"""
        pass

    def listen_for_evc_change(self):
        """Change newly created EVC to INT-enabled EVC based on the
        metadata field (future)"""
        pass

    def listen_for_path_changes(self):
        """Change EVC's new path to INT-enabled EVC based on the metadata field
        when there is a path change. (future)"""
        pass

    def listen_for_evcs_removed(self):
        """Remove all INT flows belonging the just removed EVC (future)"""
        pass

    def listen_for_topology_changes(self):
        """If the topology changes, make sure it is not the loop ports.
        If so, update proxy ports"""
        # TODO:
        # self.proxy_ports = create_proxy_ports(self.proxy_ports)
        pass

    def listen_for_evc_metadata_changes(self):
        """If the proxy port changes, the flows have to be reconfigured."""
        pass
