""" Support function for main.py """


import requests
import json
from kytos.core import log
from napps.amlight.telemetry.settings import KYTOS_API
from napps.amlight.telemetry.settings import COOKIE_PREFIX
from napps.amlight.telemetry.kytos_api_helper import get_evcs
from napps.amlight.telemetry.kytos_api_helper import get_path
from napps.amlight.telemetry.kytos_api_helper import get_topology_interfaces
from napps.amlight.telemetry.kytos_api_helper import kytos_delete_flows
from napps.amlight.telemetry.kytos_api_helper import kytos_get_flows
from napps.amlight.telemetry.kytos_api_helper import kytos_push_flows
from napps.amlight.telemetry.kytos_api_helper import set_telemetry_metadata_true
from napps.amlight.telemetry.kytos_api_helper import set_telemetry_metadata_false
from napps.amlight.telemetry.proxy_port import ProxyPort


# mef_eline support functions
def get_evcs_ids():
    """ get the list of all EVCs' IDs """
    evc_ids = []
    for evc in get_evcs().values():
        evc_ids.append(evc["id"])
    return evc_ids


def get_evc_with_telemetry():
    """ Retrieve the list of EVC IDs and list those with
        metadata {"telemetry": {"enabled": true}} """

    evc_ids = {"evcs_with_telemetry": []}
    try:
        for evc in get_evcs().values():
            if has_int_enabled(evc):
                evc_ids["evcs_with_telemetry"].append(evc["id"])
    except Exception as err:
        return err

    return evc_ids


def has_int_enabled(evc):
    """ check if evc has telemetry. """
    if "telemetry" in evc["metadata"]:
        if "enabled" in evc["metadata"]["telemetry"]:
            if evc["metadata"]["telemetry"]["enabled"] == "true":
                return True

    return False


def get_evc(evc_id):
    """ Get EVC from MEF E-Line using evc_id provided.
    Args:
        evc_id: evc_id provided by user via REST
    Returns:
        full evc if found
        False is not found
    """
    evcs = get_evcs()
    if evc_id in evcs:
        return get_evcs()[evc_id]
    return False


def get_evc_unis(evc):
    """ Parse EVC() for unis.
    Args:
        evc: EVC.__dict__
    Returns:
        uni_a and uni_z
    """
    uni_a = dict()
    uni_a["interface"] = int(evc["uni_a"]["interface_id"].split(":")[8])
    uni_a["switch"] = ":".join(evc["uni_a"]["interface_id"].split(":")[0:8])

    uni_z = dict()
    uni_z["interface"] = int(evc["uni_z"]["interface_id"].split(":")[8])
    uni_z["switch"] = ":".join(evc["uni_z"]["interface_id"].split(":")[0:8])

    return uni_a, uni_z


def set_telemetry_true_for_evc(evc_id, direction):
    """ Change the telemetry's enabled metadata field to true """
    return set_telemetry_metadata_true(evc_id, direction)


def set_telemetry_false_for_evc(evc_id):
    """ Change the telemetry's enabled metadata field to false """
    return set_telemetry_metadata_false(evc_id)


def get_kytos_interface(switch, interface):
    """ Get the Kytos Interface as dict. Useful for multiple functions. """

    kytos_interfaces = get_topology_interfaces()["interfaces"]
    for kytos_interface in kytos_interfaces.values():
        if switch == kytos_interface["switch"]:
            if interface == kytos_interface["port_number"]:
                return kytos_interface


def create_proxy_port(switch, proxy_port):
    """ Return the ProxyPort class to support single and multi-home loops """
    pp = ProxyPort(switch=switch, proxy_port=proxy_port)
    return pp if pp.is_ready() else None


def get_proxy_port(switch, interface):
    """ Return the proxy port assigned to a UNI """
    kytos_interface = get_kytos_interface(switch, interface)

    if kytos_interface:
        if "proxy_port" in kytos_interface["metadata"]:
            return create_proxy_port(switch, kytos_interface["metadata"]["proxy_port"])

    return None


def add_to_apply_actions(instructions, new_instruction, position):
    """ Create the actions list """
    for instruction in instructions:
        if instruction["instruction_type"] == "apply_actions":
            instruction["actions"].insert(position, new_instruction)
    return instructions


def get_evc_flows(switch, evc, telemetry=False):
    """ Get EVC's flows from a specific switch.
    Args:
        switch: dpid
        evc: evc.__dict__
        telemetry: bool to indicate if we are looking for telemetry or mef_eline flows
    Returns:
        list of flows
        """
    flows = []
    flow_response = kytos_get_flows(switch)
    for flow in flow_response[switch]["flows"]:
        if evc["id"] == get_id_from_cookie(flow["cookie"], telemetry):
            flows.append(flow)

    return flows


def get_id_from_cookie(cookie, telemetry):
    """Return the evc id given a cookie value. By default, searches for mef_eline cookies. """
    if telemetry:
        evc_id = cookie - (int(COOKIE_PREFIX, 16) << 56)
    else:
        evc_id = cookie - (0xAA << 56)
    return f"{evc_id:x}".zfill(14)


def get_int_hops(evc, source, destination):
    """ Get the list of INT switches between the INT Source and INT Destination/Sink
    Args:
        evc: EVC.__dict__
        source: source UNI
        destination: destination UNI
    Returns:
        list of INT hops
    """

    int_hops = []

    if not evc["current_path"]:
        return int_hops

    by_three = 1
    # for hop in get_path_pathfinder(source["switch"], destination["switch"]):
    for hop in get_path(source["switch"], destination["switch"]):
        if by_three % 3 == 0:
            interface = int(hop.split(":")[8])
            switch = ":".join(hop.split(":")[0:8])
            if switch != destination["switch"]:
                int_hops.append((switch, interface))
        by_three += 1
    return int_hops


# def get_path_pathfinder(source, destination):
#     """ Get the path from source to destination """
#     response = requests.post(url='%s/kytos/pathfinder/v2/' % KYTOS_API,
#                              headers={'Content-Type': 'application/json'},
#                              data=json.dumps({"source": source, "destination": destination})).json()
#     return response["paths"][0]["hops"] if "paths" in response else False


def is_intra_switch_evc(evc):
    """ Returns if EVC is intra-switch (two UNIs on the same switch) """
    uni_a, uni_z = get_evc_unis(evc)
    if uni_a["switch"] == uni_z["switch"]:
        return True
    return False


def modify_actions(actions, actions_to_change, remove=True):
    """ Change the current actions
    If remove == True, remove actions_to_change from actions.
    If remove == False, keep actions_to_change, remove everything else
    Args:
        actions = current list of actions on a flow
        actions_to_change = list of actions as strings
        remove = boolean
    Return
        actions
    """
    indexes = list()
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


def print_flows(flows):
    """ For debugging purposes """
    log.info("===================================")
    for flow in flows:
        log.info(f"Switch: {flow['switch']}")
        log.info(f"Table ID: {flow['table_id']}")
        log.info(f"Match: {flow['match']}")

        for instruction in flow['instructions']:

            log.info(f"Instruction Type: {instruction['instruction_type']}")
            if 'actions' in instruction:
                for action in instruction['actions']:
                    if action['action_type'] == 'output':
                        log.info(f"Action_type: {action['action_type']} port_no: {action['port']}")
                    elif action['action_type'] == 'set_vlan':
                        log.info(f"Action_type: {action['action_type']} vlan_id: {action['vlan_id']}")
                    else:
                        log.info(f"Action_type: {action}")

        log.info("===================================")


def push_flows(flows):
    """ Push INT flows to the Flow_Manager via REST.
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

    log.info("Flows pushed with success.")
    return True


def set_priority(f_id, priority):
    """ Find a suitable priority number. EP031 describes 100 as the addition."""
    if priority + 100 < 65534:
        return priority + 100
    if priority + 1 < 65534:
        return priority + 1

    log.info(f"Error: Flow ID {f_id} has reached max priority supported")
    return priority


def get_new_cookie(cookie):
    """ Convert from mef-eline cookie (0xaa) to telemetry (0xA8)"""
    value = hex(cookie)
    value = value.replace('0xaa', COOKIE_PREFIX)
    return int(value, 16)


def retrieve_switches(evc):
    """ Retrieve switches in the EVC's current or fail-over paths
     Args:
         evc: dict
     Returns:
         list of DPIDs
    """
    switches = []
    uni_a, uni_z = get_evc_unis(evc)
    switches.append(uni_a["switch"])

    # Inter-switch EVCs
    if uni_a["switch"] != uni_z["switch"]:
        switches.append(uni_z["switch"])

        for nni in evc['current_path']:
            switches.append(nni['endpoint_a']['switch'])
            switches.append(nni['endpoint_b']['switch'])

        for nni in evc['failover_path']:
            switches.append(nni['endpoint_a']['switch'])
            switches.append(nni['endpoint_b']['switch'])

    # Remove duplicates
    return [*set(switches)]


def delete_flows(flows):
    """ Delete flows from Kytos"""

    # Debug
    print_flows(flows)

    for flow in flows:
        flow['cookie_mask'] = 18446744073709551615
        flow_to_push = {"flows": [flow]}
        if not kytos_delete_flows(flow["switch"], flow_to_push):
            return False

    return True
