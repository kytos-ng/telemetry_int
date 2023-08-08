""" Support function for main.py """

import json

from napps.kytos.telemetry_int import settings

from kytos.core import Controller, log
from kytos.core.interface import Interface

from .kytos_api_helper import (
    get_evcs,
    kytos_push_flows,
    set_telemetry_metadata_false,
    set_telemetry_metadata_true,
)
from .proxy_port import ProxyPort

# mef_eline support functions


def get_evc_with_telemetry() -> dict:
    """Retrieve the list of EVC IDs and list those with
    metadata {"telemetry": {"enabled": true}}"""

    evc_ids = {"evcs_with_telemetry": []}
    for evc in get_evcs().values():
        if has_int_enabled(evc):
            evc_ids["evcs_with_telemetry"].append(evc["id"])
    return evc_ids


def has_int_enabled(evc: dict) -> bool:
    """Check if evc has telemetry."""
    return (
        "telemetry" in evc["metadata"]
        and isinstance(evc["metadata"]["telemetry"], dict)
        and "enabled" in evc["metadata"]["telemetry"]
        and evc["metadata"]["telemetry"]["enabled"]
    )


def get_evc_unis(evc: dict) -> tuple[dict, dict]:
    """Parse evc for unis."""
    uni_a_split = evc["uni_a"]["interface_id"].split(":")
    uni_z_split = evc["uni_z"]["interface_id"].split(":")
    return (
        {
            "interface_id": evc["uni_a"]["interface_id"],
            "port_number": int(uni_a_split[-1]),
            "switch": ":".join(uni_a_split[:-1]),
        },
        {
            "interface_id": evc["uni_z"]["interface_id"],
            "port_number": int(uni_z_split[-1]),
            "switch": ":".join(uni_z_split[:-1]),
        },
    )


def set_telemetry_true_for_evc(evc_id, direction):
    """Change the telemetry's enabled metadata field to true"""
    return set_telemetry_metadata_true(evc_id, direction)


def set_telemetry_false_for_evc(evc_id):
    """Change the telemetry's enabled metadata field to false"""
    return set_telemetry_metadata_false(evc_id)


def create_proxy_port(controller: Controller, interface: Interface):
    """Return the ProxyPort class to support single and multi-home loops"""
    pp = ProxyPort(controller, interface)
    return pp if pp.is_ready() else None


def get_proxy_port(controller: Controller, intf_id: str):
    """Return the proxy port assigned to a UNI"""
    interface = controller.get_interface_by_id(intf_id)
    if not interface or "proxy_port" not in interface.metadata:
        return None
    source_intf = interface.switch.get_interface_by_port_no(
        interface.metadata.get("proxy_port")
    )
    if not source_intf:
        return None
    return create_proxy_port(controller, source_intf)


def add_to_apply_actions(instructions, new_instruction, position):
    """Create the actions list"""
    for instruction in instructions:
        if instruction["instruction_type"] == "apply_actions":
            instruction["actions"].insert(position, new_instruction)
    return instructions


def get_cookie(evc_id: str, mef_cookie_prefix=settings.MEF_COOKIE_PREFIX) -> int:
    """Return the cookie integer from evc id."""
    return int(evc_id, 16) + (mef_cookie_prefix << 56)


def get_cookie_telemetry(evc_id: str, cookie_prefix=settings.COOKIE_PREFIX) -> int:
    """Return telemetry cookie given an evc_id."""
    return int(evc_id, 16) + (cookie_prefix << 56)


# pylint: disable=fixme
def get_path_hop_interface_ids(evc, source, destination):
    """
    source: {'interface_id': x, 'port_number': int, 'switch': 'x'}
    destination: {'interface_id': x, 'port_number': int, 'switch': 'x'}
    """
    # TODO double check convergence deployment optimizations later
    # TODO double check static backup path

    source_id = source["interface_id"]
    destination_id = destination["interface_id"]

    interface_ids = []

    endpoint = (
        "endpoint_b" if evc["uni_a"]["interface_id"] == source_id else "endpoint_a"
    )

    for link in evc["current_path"]:
        if (
            not link[endpoint]["switch"] in destination_id
            and not link[endpoint]["switch"] in source_id
        ):
            interface_ids.append(link[endpoint]["id"])

    for link in evc["failover_path"]:
        if (
            not link[endpoint]["switch"] in destination_id
            and not link[endpoint]["switch"] in source_id
        ):
            interface_ids.append(link[endpoint]["id"])

    return interface_ids


def get_id_from_cookie(cookie: int) -> str:
    """Return the evc id given a cookie value."""
    evc_id = cookie & 0xFFFFFFFFFFFFFF
    return f"{evc_id:x}"


def is_intra_switch_evc(evc):
    """Returns if EVC is intra-switch (two UNIs on the same switch)"""
    uni_a, uni_z = get_evc_unis(evc)
    if uni_a["switch"] == uni_z["switch"]:
        return True
    return False


def modify_actions(actions, actions_to_change, remove=True):
    """Change the current actions
    If remove == True, remove actions_to_change from actions.
    If remove == False, keep actions_to_change, remove everything else
    Args:
        actions = current list of actions on a flow
        actions_to_change = list of actions as strings
        remove = boolean
    Return
        actions
    """
    indexes = []
    count = 0

    for action in actions:
        if remove:
            if action["action_type"] in actions_to_change:
                indexes.append(count)
        else:
            if action["action_type"] not in actions_to_change:
                indexes.append(count)
        count += 1

    for index in sorted(indexes, reverse=True):
        del actions[index]
    return actions


def print_flows(flows: list[dict]) -> None:
    """For debugging purposes"""
    log.info("===================================")
    for flow in sorted(flows, key=lambda x: x["switch"]):
        log.info(json.dumps(flow, indent=4))
        log.info("===================================")


def push_flows(flows):
    """Push INT flows to the Flow_Manager via REST.
    Args:
        flows: list of flows
    Returns:
        True if successful
        False otherwise
    """

    # Debug:
    print_flows(flows)

    for flow in flows:
        flow_to_push = {"flows": [flow]}
        if not kytos_push_flows(flow["switch"], flow_to_push):
            return False
    return True


def set_priority(flow: dict) -> dict:
    """Find a suitable priority number. EP031 describes 100 as the addition."""
    if flow["flow"]["priority"] + 100 < (2**16 - 2):
        flow["flow"]["priority"] += 100
    elif flow["flow"]["priority"] + 1 < (2**16 - 2):
        flow["flow"]["priority"] += 1
    else:
        raise ValueError(f"Flow {flow} would overflow max priority")
    return flow


def get_new_cookie(cookie: int, cookie_prefix=settings.COOKIE_PREFIX) -> int:
    """Convert from mef-eline cookie by replacing the most significant byte."""
    return (cookie & 0xFFFFFFFFFFFFFF) + (cookie_prefix << 56)


def set_new_cookie(flow: dict) -> dict:
    """Set new cookie."""
    flow["flow"]["cookie"] = get_new_cookie(flow["flow"]["cookie"])
    return flow


def set_instructions_from_actions(flow: dict) -> dict:
    """Get intructions or convert from actions."""
    if "instructions" in flow["flow"]:
        return flow

    instructions = [
        {
            "instruction_type": "apply_actions",
            "actions": flow["flow"].get("actions", []),
        }
    ]
    flow["flow"].pop("actions", None)
    flow["flow"]["instructions"] = instructions
    return flow
