"""flow_builder module responsible for building and mapping flows."""

import copy
from collections import defaultdict
import itertools

from typing import Literal

from napps.kytos.telemetry_int import utils
from napps.kytos.telemetry_int.exceptions import FlowsNotFound
from napps.kytos.telemetry_int import settings


def build_int_flows(
    evcs: dict[str, dict], stored_flows: dict[int, list[dict]]
) -> dict[int, list[dict]]:
    """build INT flows.

    It'll map and create all INT flows needed, for now since each EVC
    is bidirectional, it'll provision bidirectionally too. In the future,
    if mef_eline supports unidirectional EVC, it'll follow suit accordingly.
    """
    flows_per_cookie: dict[int, list[dict]] = defaultdict(list)
    for evc_id, evc in evcs.items():
        for flow in itertools.chain(
            _build_int_source_flows("uni_a", evc, stored_flows),
            _build_int_source_flows("uni_z", evc, stored_flows),
            _build_int_hop_flows(evc, stored_flows),
            _build_int_sink_flows("uni_z", evc, stored_flows),
            _build_int_sink_flows("uni_a", evc, stored_flows),
        ):
            cookie = utils.get_cookie(evc_id, settings.MEF_COOKIE_PREFIX)
            flows_per_cookie[cookie].append(flow)
    return flows_per_cookie


def _build_int_source_flows(
    uni_src_key: Literal["uni_a", "uni_z"],
    evc: dict,
    stored_flows: dict[int, list[dict]],
) -> list[dict]:
    """Build INT source flows.

    At the INT source, one flow becomes 3: one for UDP on table 0,
    one for TCP on table 0, and one on table 2
    On table 0, we use just new instructions: push_int and goto_table
    On table 2, we add add_int_metadata before the original actions
    INT flows will have higher priority.
    """
    new_flows = []
    new_int_flow_tbl_0_tcp = {}
    src_uni = evc[uni_src_key]
    proxy_port = src_uni["proxy_port"]

    # Get the original flows
    dpid = src_uni["switch"]
    for flow in stored_flows[utils.get_cookie(evc["id"], settings.MEF_COOKIE_PREFIX)]:
        if (
            flow["switch"] == dpid
            and flow["flow"]["match"]["in_port"] == src_uni["port_number"]
        ):
            new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
            break

    if not new_int_flow_tbl_0_tcp:
        raise FlowsNotFound(evc["id"])

    utils.set_instructions_from_actions(new_int_flow_tbl_0_tcp)
    utils.set_new_cookie(new_int_flow_tbl_0_tcp)
    utils.set_owner(new_int_flow_tbl_0_tcp)

    # Deepcopy to use for table 2 later
    new_int_flow_tbl_2 = copy.deepcopy(new_int_flow_tbl_0_tcp)

    # Prepare TCP Flow for Table 0
    new_int_flow_tbl_0_tcp["flow"]["match"]["dl_type"] = settings.IPv4
    new_int_flow_tbl_0_tcp["flow"]["match"]["nw_proto"] = settings.TCP
    utils.set_priority(new_int_flow_tbl_0_tcp)

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
    utils.set_table_group(new_int_flow_tbl_2)

    # if intra-switch EVC, then output port should be the proxy
    if utils.is_intra_switch_evc(evc):
        for instruction in new_int_flow_tbl_2["flow"]["instructions"]:
            if instruction["instruction_type"] == "apply_actions":
                for action in instruction["actions"]:
                    if action["action_type"] == "output":
                        # Since this is the INT Source, we use source
                        # to avoid worrying about single or multi
                        # home physical loops.
                        # The choice for destination is at the INT Sink.
                        action["port"] = proxy_port.source.port_number

    instructions = utils.add_to_apply_actions(
        new_int_flow_tbl_2["flow"]["instructions"],
        new_instruction={"action_type": "add_int_metadata"},
        position=0,
    )

    new_int_flow_tbl_2["flow"]["instructions"] = instructions

    new_flows.append(new_int_flow_tbl_0_tcp)
    new_flows.append(new_int_flow_tbl_0_udp)
    new_flows.append(new_int_flow_tbl_2)

    return new_flows


def _build_int_hop_flows(
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

    for flow in stored_flows[utils.get_cookie(evc["id"], settings.MEF_COOKIE_PREFIX)]:
        if flow["switch"] in excluded_dpids:
            continue
        if "match" not in flow["flow"] or "in_port" not in flow["flow"]["match"]:
            continue

        new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
        utils.set_instructions_from_actions(new_int_flow_tbl_0_tcp)
        utils.set_new_cookie(flow)
        utils.set_owner(new_int_flow_tbl_0_tcp)

        # Prepare TCP Flow
        new_int_flow_tbl_0_tcp["flow"]["match"]["dl_type"] = settings.IPv4
        new_int_flow_tbl_0_tcp["flow"]["match"]["nw_proto"] = settings.TCP
        utils.set_priority(new_int_flow_tbl_0_tcp)

        for instruction in new_int_flow_tbl_0_tcp["flow"]["instructions"]:
            if instruction["instruction_type"] == "apply_actions":
                instruction["actions"].insert(0, {"action_type": "add_int_metadata"})

        # Prepare UDP Flow
        new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
        new_int_flow_tbl_0_udp["flow"]["match"]["nw_proto"] = settings.UDP

        new_flows.append(new_int_flow_tbl_0_tcp)
        new_flows.append(new_int_flow_tbl_0_udp)

    return new_flows


def _build_int_sink_flows(
    uni_dst_key: Literal["uni_a", "uni_z"],
    evc: dict,
    stored_flows: dict[int, list[dict]],
) -> list[dict]:
    """
    Build INT sink flows.

    At the INT sink, one flow becomes many:
    1. Before the proxy, we do add_int_metadata as an INT hop.
    We need to keep the set_queue
    2. After the proxy, we do send_report and pop_int and output
    We only use table 0 for #1.
    We use table 2 for #2. for pop_int and output
    """
    new_flows = []
    dst_uni = evc[uni_dst_key]
    proxy_port = dst_uni["proxy_port"]
    dpid = dst_uni["switch"]

    for flow in stored_flows[utils.get_cookie(evc["id"], settings.MEF_COOKIE_PREFIX)]:
        # Only consider this sink's dpid flows
        if flow["switch"] != dpid:
            continue
        # Only consider flows coming from NNI interfaces
        if flow["flow"]["match"]["in_port"] == dst_uni["port_number"]:
            continue

        new_int_flow_tbl_0_tcp = copy.deepcopy(flow)

        if not new_int_flow_tbl_0_tcp:
            raise FlowsNotFound(evc["id"])

        utils.set_new_cookie(flow)
        utils.set_owner(new_int_flow_tbl_0_tcp)
        utils.set_instructions_from_actions(new_int_flow_tbl_0_tcp)

        # Save for pos-proxy flows
        new_int_flow_tbl_0_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)
        new_int_flow_tbl_2_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)

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
                    actions.append({"action_type": "output", "port": output_port_no})
                    instruction["actions"] = actions

            # Prepare UDP Flow for Table 0
            new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
            new_int_flow_tbl_0_udp["flow"]["match"]["nw_proto"] = settings.UDP

            new_flows.append(copy.deepcopy(new_int_flow_tbl_0_tcp))
            new_flows.append(copy.deepcopy(new_int_flow_tbl_0_udp))

        # Prepare Flows for Table 0 AFTER proxy. No difference between TCP or UDP
        in_port_no = proxy_port.destination.port_number

        new_int_flow_tbl_0_pos["flow"]["match"]["in_port"] = in_port_no
        utils.set_priority(new_int_flow_tbl_0_tcp)

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
        utils.set_table_group(new_int_flow_tbl_2_pos)

        for instruction in new_int_flow_tbl_2_pos["flow"]["instructions"]:
            if instruction["instruction_type"] == "apply_actions":
                instruction["actions"].insert(0, {"action_type": "pop_int"})

        new_flows.append(copy.deepcopy(new_int_flow_tbl_0_pos))
        new_flows.append(copy.deepcopy(new_int_flow_tbl_2_pos))

    return new_flows
