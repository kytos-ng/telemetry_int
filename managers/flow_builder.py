"""flow_builder module responsible for building and mapping flows."""

import copy
from collections import defaultdict
import itertools

from typing import Literal

from napps.kytos.telemetry_int import utils
from napps.kytos.telemetry_int import settings
from napps.kytos.telemetry_int.exceptions import ProxyPortRequired


class FlowBuilder:
    """FlowBuilder."""

    def __init__(self):
        """Constructor of FlowBuilder."""
        self.table_group = {"evpl": 2, "epl": 3, "evpl_vlan_range": 3}

    def get_table_id(self, flow: dict) -> int:
        """Get a table_id X for a given flow based on its match type
        This is to cover AmLight pipeline specifics when table_group
        doesn't suffice."""
        dl_vlan = flow["flow"]["match"].get("dl_vlan")
        if isinstance(dl_vlan, int) and dl_vlan != 0:
            return self.table_group["evpl"]
        elif dl_vlan is None:
            return self.table_group["epl"]
        elif isinstance(dl_vlan, str) or dl_vlan == 0:
            return self.table_group["evpl_vlan_range"]
        else:
            return self.table_group[flow["flow"]["table_group"]]

    def build_int_flows(
        self,
        evcs: dict[str, dict],
        stored_flows: dict[int, list[dict]],
    ) -> dict[int, list[dict]]:
        """build INT flows.

        It'll map and create all INT flows needed, for now since each EVC
        is bidirectional, it'll provision bidirectionally too. In the future,
        if mef_eline supports unidirectional EVC, it'll follow suit accordingly.
        """
        flows_per_cookie: dict[int, list[dict]] = defaultdict(list)
        for evc_id, evc in evcs.items():
            for flow in itertools.chain(
                self._build_int_source_flows("uni_a", evc, stored_flows),
                self._build_int_source_flows("uni_z", evc, stored_flows),
                self._build_int_hop_flows(evc, stored_flows),
                self._build_int_sink_flows("uni_z", evc, stored_flows),
                self._build_int_sink_flows("uni_a", evc, stored_flows),
            ):
                cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
                flows_per_cookie[cookie].append(flow)
        return flows_per_cookie

    def build_failover_old_flows(
        self, evcs: dict[str, dict], old_flows: dict[int, list[dict]]
    ) -> dict[int, list[dict]]:
        """Build (old path) failover related to remove flows."""

        removed_flows = defaultdict(list)
        for evc_id, evc in evcs.items():
            dpid_a, dpid_z = evc["uni_a"]["switch"], evc["uni_z"]["switch"]
            cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
            sink_a_flows: list[dict] = []
            sink_z_flows: list[dict] = []

            for flow in old_flows[cookie]:
                if not sink_a_flows and flow["switch"] == dpid_a:
                    sink_a_flows = self._build_int_sink_flows(
                        "uni_a", evc, old_flows
                    )
                elif not sink_z_flows and flow["switch"] == dpid_z:
                    sink_z_flows = self._build_int_sink_flows(
                        "uni_z", evc, old_flows
                    )
                if sink_a_flows and sink_z_flows:
                    break

            hop_flows = self._build_int_hop_flows(evc, old_flows)
            removed_flows[cookie] = list(
                itertools.chain(sink_a_flows, hop_flows, sink_z_flows)
            )
        return removed_flows

    def _build_int_source_flows(
        self,
        uni_src_key: Literal["uni_a", "uni_z"],
        evc: dict,
        stored_flows: dict[int, list[dict]],
    ) -> list[dict]:
        """Build INT source flows.

        At the INT source, one flow becomes 3: one for UDP on table 0,
        one for TCP on table 0, and one on table X (2 for evpl and 3 for epl by default)
        vlan_range can have more than one ingress flow
        On table 0, we use just new instructions: push_int and goto_table
        On table X, we add add_int_metadata before the original actions
        INT flows will have higher priority.
        """
        new_flows, uni_flows = [], []
        src_uni = evc[uni_src_key]

        # Get the original flows
        dpid = src_uni["switch"]
        for flow in stored_flows[
            utils.get_cookie(evc["id"], settings.MEF_COOKIE_PREFIX)
        ]:
            if (
                flow["switch"] == dpid
                and flow["flow"]["match"]["in_port"] == src_uni["port_number"]
            ):
                uni_flows.append(flow)

        if not uni_flows:
            return []

        is_intra_switch = utils.is_intra_switch_evc(evc)
        for flow in uni_flows:
            new_int_flow_tbl_0_tcp = copy.deepcopy(flow)

            utils.set_instructions_from_actions(new_int_flow_tbl_0_tcp)
            utils.set_new_cookie(new_int_flow_tbl_0_tcp)
            utils.set_owner(new_int_flow_tbl_0_tcp)

            # Deepcopy to use for table X (2 or 3 by default for EVPL or EPL)
            new_int_flow_tbl_x = copy.deepcopy(new_int_flow_tbl_0_tcp)

            # Prepare TCP Flow for Table 0
            new_int_flow_tbl_0_tcp["flow"]["match"]["dl_type"] = settings.IPv4
            new_int_flow_tbl_0_tcp["flow"]["match"]["nw_proto"] = settings.TCP
            utils.set_priority(new_int_flow_tbl_0_tcp)

            new_table_id = self.get_table_id(new_int_flow_tbl_0_tcp)
            # The flow_manager has two outputs: instructions and actions.
            instructions = [
                {
                    "instruction_type": "apply_actions",
                    "actions": [{"action_type": "push_int"}],
                },
                {"instruction_type": "goto_table", "table_id": new_table_id},
            ]
            new_int_flow_tbl_0_tcp["flow"]["instructions"] = instructions

            # Prepare UDP Flow for Table 0.
            # Everything the same as TCP except the nw_proto
            new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
            new_int_flow_tbl_0_udp["flow"]["match"]["nw_proto"] = settings.UDP
            # Prepare Flows for Table X - No TCP or UDP specifics
            new_int_flow_tbl_x["flow"]["table_id"] = new_table_id

            # if intra-switch EVC, then output port should be the dst UNI's source port
            if is_intra_switch:
                dst_uni = evc["uni_z" if uni_src_key == "uni_a" else "uni_a"]
                proxy_port = dst_uni["proxy_port"]
                for instruction in new_int_flow_tbl_x["flow"]["instructions"]:
                    if instruction["instruction_type"] == "apply_actions":
                        for action in instruction["actions"]:
                            if action["action_type"] == "output":
                                # Since this is the INT Source, we use source
                                # to avoid worrying about single or multi
                                # home physical loops.
                                # The choice for destination is at the INT Sink.
                                action["port"] = proxy_port.source.port_number

            instructions = utils.add_to_apply_actions(
                new_int_flow_tbl_x["flow"]["instructions"],
                new_instruction={"action_type": "add_int_metadata"},
                position=0,
            )

            new_int_flow_tbl_x["flow"]["instructions"] = instructions
            new_flows.append(new_int_flow_tbl_0_tcp)
            new_flows.append(new_int_flow_tbl_0_udp)
            new_flows.append(new_int_flow_tbl_x)

        return new_flows

    def _build_int_hop_flows(
        self,
        evc: dict,
        stored_flows: dict[int, list[dict]],
    ) -> list[dict]:
        """Build INT hop flows.

        At the INT hops, one flow adds two more: one for UDP on table 0,
        one for TCP on table 0. On table 0, we add 'add_int_metadata'
        before other actions.
        """

        new_flows = []
        excluded_dpids = set([evc["uni_a"]["switch"], evc["uni_z"]["switch"]])

        for flow in stored_flows[
            utils.get_cookie(evc["id"], settings.MEF_COOKIE_PREFIX)
        ]:
            if flow["switch"] in excluded_dpids:
                continue
            if "match" not in flow["flow"] or "in_port" not in flow["flow"]["match"]:
                continue

            new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
            utils.set_instructions_from_actions(new_int_flow_tbl_0_tcp)
            utils.set_new_cookie(new_int_flow_tbl_0_tcp)
            utils.set_owner(new_int_flow_tbl_0_tcp)

            # Prepare TCP Flow
            new_int_flow_tbl_0_tcp["flow"]["match"]["dl_type"] = settings.IPv4
            new_int_flow_tbl_0_tcp["flow"]["match"]["nw_proto"] = settings.TCP
            utils.set_priority(new_int_flow_tbl_0_tcp)

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

    def _build_int_sink_flows(
        self,
        uni_dst_key: Literal["uni_a", "uni_z"],
        evc: dict,
        stored_flows: dict[int, list[dict]],
    ) -> list[dict]:
        """Build INT sink flows."""
        match utils.get_evc_proxy_port_value(evc):
            case True:
                return self._build_int_sink_flows_proxy_port(
                    uni_dst_key, evc, stored_flows
                )
            case False:
                return self._build_int_sink_flows_no_proxy_port(
                    uni_dst_key, evc, stored_flows
                )
            case _:
                if "proxy_port" in evc[uni_dst_key]:
                    return self._build_int_sink_flows_proxy_port(
                        uni_dst_key, evc, stored_flows
                    )
                return self._build_int_sink_flows_no_proxy_port(
                    uni_dst_key, evc, stored_flows
                )

    def _build_int_sink_flows_proxy_port(
        self,
        uni_dst_key: Literal["uni_a", "uni_z"],
        evc: dict,
        stored_flows: dict[int, list[dict]],
    ) -> list[dict]:
        """
        Build INT sink flows.

        At the INT sink, one flow becomes many:
        1. Before the proxy, we do add_int_metadata as an INT hop,
        and either pop the s-vlan if it has qinq or set_vlan to its c-vlan
        We need to keep the set_queue.
        2. After the proxy, we do send_report, pop_int, and output for UNI flows
        vlan range UNIs can have more than one flow.
        We only use table 0 for #1.
        We use table X (2 or 3) for #2. for pop_int and output
        """
        new_flows = []
        uni_vlan_flows = []
        pos_proxy_flows = []
        dst_uni = evc[uni_dst_key]
        proxy_port = dst_uni["proxy_port"]
        dpid = dst_uni["switch"]
        has_qinq = utils.has_qinq(evc)
        has_uni_vlan_type = utils.has_uni_vlan_type(evc, uni_dst_key)
        has_special_dl_vlan = utils.has_special_dl_vlan(evc, uni_dst_key)

        for flow in stored_flows[
            utils.get_cookie(evc["id"], settings.MEF_COOKIE_PREFIX)
        ]:
            # Only consider this sink's dpid flows
            if flow["switch"] != dpid:
                continue
            # Include UNI dl_vlan match flows
            if (
                flow["flow"]["match"]["in_port"] == dst_uni["port_number"]
                and "dl_vlan" in flow["flow"]["match"]
            ):
                uni_vlan_flows.append(flow)

        # Prepare NNI table 0 pre proxy flows
        for flow in stored_flows[
            utils.get_cookie(evc["id"], settings.MEF_COOKIE_PREFIX)
        ]:
            # Only consider this sink's dpid flows
            if flow["switch"] != dpid:
                continue
            # Only consider flows coming from NNI interfaces
            if flow["flow"]["match"]["in_port"] == dst_uni["port_number"]:
                continue

            new_int_flow_tbl_0_tcp = copy.deepcopy(flow)

            if not new_int_flow_tbl_0_tcp:
                continue

            utils.set_new_cookie(new_int_flow_tbl_0_tcp)
            utils.set_owner(new_int_flow_tbl_0_tcp)
            utils.set_instructions_from_actions(new_int_flow_tbl_0_tcp)

            # Save for pos-proxy flows
            pos_proxy_flows.append(copy.deepcopy(new_int_flow_tbl_0_tcp))

            # Prepare TCP Flow for Table 0 PRE proxy
            if not utils.is_intra_switch_evc(evc):
                new_int_flow_tbl_0_tcp["flow"]["match"]["dl_type"] = settings.IPv4
                new_int_flow_tbl_0_tcp["flow"]["match"]["nw_proto"] = settings.TCP
                utils.set_priority(new_int_flow_tbl_0_tcp)

                # Add telemetry, keep set_queue, output to the proxy port.
                output_port_no = proxy_port.source.port_number
                for instruction in new_int_flow_tbl_0_tcp["flow"]["instructions"]:
                    if instruction["instruction_type"] == "apply_actions":
                        # Keep set_queue
                        actions = utils.modify_actions(
                            instruction["actions"],
                            ["pop_vlan", "push_vlan", "set_vlan", "output"],
                            remove=True,
                        )
                        actions.insert(0, {"action_type": "add_int_metadata"})
                        if has_qinq:
                            # pop the s-vlan before sending to the loop
                            actions.insert(1, {"action_type": "pop_vlan"})
                        else:
                            # has vlan translation
                            actions.insert(
                                1,
                                {
                                    "action_type": "set_vlan",
                                    "vlan_id": dst_uni["tag"]["value"],
                                },
                            )
                        actions.append(
                            {"action_type": "output", "port": output_port_no}
                        )
                        instruction["actions"] = actions

                # Prepare UDP Flow for Table 0
                new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
                new_int_flow_tbl_0_udp["flow"]["match"]["nw_proto"] = settings.UDP

                new_flows.append(copy.deepcopy(new_int_flow_tbl_0_tcp))
                new_flows.append(copy.deepcopy(new_int_flow_tbl_0_udp))

        for flow in pos_proxy_flows:
            new_int_flow_tbl_0_pos = copy.deepcopy(flow)
            new_int_flow_tbl_x_pos = copy.deepcopy(flow)

            # Prepare Flows for Table 0 AFTER proxy. No difference between TCP or UDP
            in_port_no = proxy_port.destination.port_number

            new_int_flow_tbl_0_pos["flow"]["match"]["in_port"] = in_port_no
            utils.set_priority(new_int_flow_tbl_0_tcp)

            new_table_id = self.get_table_id(new_int_flow_tbl_x_pos)
            if has_special_dl_vlan:
                # this overwrite is needed since s-vlan transformation
                # happens before the POS flows, and we don't know if it'll be
                # a wildcard match in the future we can improve mef_eline
                # table_group to facilitate
                new_table_id = self.table_group["evpl_vlan_range"]
            instructions = [
                {
                    "instruction_type": "apply_actions",
                    "actions": [{"action_type": "send_report"}],
                },
                {
                    "instruction_type": "goto_table",
                    "table_id": new_table_id,
                },
            ]
            new_int_flow_tbl_0_pos["flow"]["instructions"] = instructions

            # Prepare Flows for Table X POS proxy
            new_int_flow_tbl_x_pos["flow"]["match"]["in_port"] = in_port_no
            new_int_flow_tbl_x_pos["flow"]["table_id"] = new_table_id

            for instruction in new_int_flow_tbl_x_pos["flow"]["instructions"]:
                if instruction["instruction_type"] == "apply_actions":
                    # Keep set_queue and output
                    instruction["actions"] = utils.modify_actions(
                        instruction["actions"],
                        ["pop_vlan", "push_vlan", "set_vlan"],
                        remove=True,
                    )
                    instruction["actions"].insert(0, {"action_type": "pop_int"})

            if uni_vlan_flows:
                # vlan range can have multiple dl_vlan match entries
                for uni_vlan_flow in uni_vlan_flows:
                    uni_vlan = uni_vlan_flow["flow"]["match"]["dl_vlan"]
                    new_int_flow_tbl_0_pos["flow"]["match"]["dl_vlan"] = uni_vlan
                    new_int_flow_tbl_x_pos["flow"]["match"]["dl_vlan"] = uni_vlan
                    new_flows.append(copy.deepcopy(new_int_flow_tbl_0_pos))
                    new_flows.append(copy.deepcopy(new_int_flow_tbl_x_pos))
            elif not uni_vlan_flows and not has_uni_vlan_type:
                # port based
                new_int_flow_tbl_0_pos["flow"]["match"].pop("dl_vlan", None)
                new_int_flow_tbl_x_pos["flow"]["match"].pop("dl_vlan", None)
                new_flows.append(copy.deepcopy(new_int_flow_tbl_0_pos))
                new_flows.append(copy.deepcopy(new_int_flow_tbl_x_pos))

        return new_flows

    def _build_int_sink_flows_no_proxy_port(
        self,
        uni_dst_key: Literal["uni_a", "uni_z"],
        evc: dict,
        stored_flows: dict[int, list[dict]],
    ) -> list[dict]:
        """
        Build INT sink flows NO proxy port, it won't add int_metadata.

        This is only supported for inter-EVCs

        At the INT sink, one flow becomes many:

        1. Table 0: send_report and go to table X (2 or 3)
        2. Table X (2 or 3): pop_int, and output
        """
        new_flows = []
        dst_uni = evc[uni_dst_key]
        dpid = dst_uni["switch"]

        if utils.is_intra_switch_evc(evc):
            raise ProxyPortRequired(evc["id"], "intra-EVC must use proxy ports")

        for flow in stored_flows[
            utils.get_cookie(evc["id"], settings.MEF_COOKIE_PREFIX)
        ]:
            # Only consider this sink's dpid flows
            if flow["switch"] != dpid:
                continue
            # Only consider flows coming from NNI interfaces
            if flow["flow"]["match"]["in_port"] == dst_uni["port_number"]:
                continue

            new_int_flow_tbl_0_tcp = copy.deepcopy(flow)

            if not new_int_flow_tbl_0_tcp:
                continue

            utils.set_new_cookie(new_int_flow_tbl_0_tcp)
            utils.set_owner(new_int_flow_tbl_0_tcp)
            utils.set_instructions_from_actions(new_int_flow_tbl_0_tcp)
            # Save flow for Table X
            new_int_flow_tbl_x_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)

            new_int_flow_tbl_0_tcp["flow"]["instructions"] = []
            new_int_flow_tbl_0_tcp["flow"]["match"]["dl_type"] = settings.IPv4
            new_int_flow_tbl_0_tcp["flow"]["match"]["nw_proto"] = settings.TCP
            utils.set_priority(new_int_flow_tbl_0_tcp)

            # INT send_report and goto_table actions
            new_table_id = self.get_table_id(new_int_flow_tbl_0_tcp)
            instructions = [
                {
                    "instruction_type": "apply_actions",
                    "actions": [{"action_type": "send_report"}],
                },
                {
                    "instruction_type": "goto_table",
                    "table_id": new_table_id,
                },
            ]
            new_int_flow_tbl_0_tcp["flow"]["instructions"] = instructions

            # Prepare UDP Flow for Table 0
            new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
            new_int_flow_tbl_0_udp["flow"]["match"]["nw_proto"] = settings.UDP

            new_flows.append(copy.deepcopy(new_int_flow_tbl_0_tcp))
            new_flows.append(copy.deepcopy(new_int_flow_tbl_0_udp))

            # Prepare Flows for Table X
            new_int_flow_tbl_x_pos["flow"]["table_id"] = new_table_id

            for instruction in new_int_flow_tbl_x_pos["flow"]["instructions"]:
                if instruction["instruction_type"] == "apply_actions":
                    instruction["actions"].insert(0, {"action_type": "pop_int"})

            new_flows.append(copy.deepcopy(new_int_flow_tbl_x_pos))

        return new_flows
