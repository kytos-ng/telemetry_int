"""Main module of kytos/telemetry Network Application.

Napp to deploy In-band Network Telemetry over Ethernet Virtual Circuits

"""
import copy
import time

from napps.kytos.telemetry_int import settings
from napps.kytos.telemetry_int.support_functions import (
    add_to_apply_actions,
    delete_flows,
    get_evc,
    get_evc_flows,
    get_evc_unis,
    get_evc_with_telemetry,
    get_evcs_ids,
    get_new_cookie,
    get_proxy_port,
    get_unidirectional_path,
    has_int_enabled,
    is_intra_switch_evc,
    modify_actions,
    push_flows,
    retrieve_switches,
    set_priority,
    set_telemetry_false_for_evc,
    set_telemetry_true_for_evc,
)
from napps.kytos.telemetry_int.telemetry_exceptions import (
    EvcAlreadyHasINT,
    EvcDoesNotExist,
    EvcHasNoINT,
    FlowsNotFound,
    NoProxyPortsAvailable,
    NotPossibleToDisableTelemetry,
    NotPossibleToEnableTelemetry,
    UnsupportedFlow,
)

from kytos.core import KytosNApp, log, rest
from kytos.core.rest_api import HTTPException, JSONResponse, Request, get_json_or_400


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
        log.info(f"Disabling Napp {settings.NAPP_NAME}")

    @staticmethod
    def enable_int_source(source, evc, proxy_port):
        """ At the INT source, one flow becomes 3: one for UDP on table 0,
        one for TCP on table 0, and one on table 2
        On table 0, we use just new instructions: push_int and goto_table
        On table 2, we add add_int_metadata before the original actions
        INT flows will have higher priority. We don't delete the old flows.
        Args:
            source: source UNI
            evc: EVC.__dict__
            proxy_port: ProxyPort source assigned to destination UNI
        Returns:
            list of new flows to install
        """
        new_flows = []
        new_int_flow_tbl_0_tcp = None
        flow = {}

        # Get the original flows
        for flow in get_evc_flows(source["switch"], evc):
            if flow["match"]["in_port"] == source["interface"]:
                new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                break

        if not new_int_flow_tbl_0_tcp:
            log.info("Error: Flow not found. Kytos still loading.")
            raise FlowsNotFound(evc["id"])

        # Remove keys that need to be recycled later by Flow_Manager.
        for extraneous_key in ["stats", "id"]:
            new_int_flow_tbl_0_tcp.pop(extraneous_key, None)

        # Get cookie with telemetry's cookie prefix.
        new_int_flow_tbl_0_tcp['cookie'] = get_new_cookie(flow["cookie"])

        # Deepcopy to use for table 2 later
        new_int_flow_tbl_2 = copy.deepcopy(new_int_flow_tbl_0_tcp)

        # Check compatibility:
        if "instructions" not in new_int_flow_tbl_0_tcp:
            log.info("Error: Flow_Manager needs to support 'instructions' and it does not.")
            raise UnsupportedFlow()

        # Prepare TCP Flow for Table 0
        new_int_flow_tbl_0_tcp["match"]["dl_type"] = settings.IPv4
        new_int_flow_tbl_0_tcp["match"]["nw_proto"] = settings.TCP
        # TODO: Create an exception for when the priority has reached max value
        new_int_flow_tbl_0_tcp["priority"] = set_priority(flow["id"],
                                                          new_int_flow_tbl_0_tcp["priority"])

        # The flow_manager has two outputs: instructions and actions.
        instructions = [{"instruction_type": "apply_actions",
                         "actions": [{"action_type": "push_int"}]},
                        {"instruction_type": "goto_table", "table_id": settings.INT_TABLE}]
        new_int_flow_tbl_0_tcp["instructions"] = instructions

        # Prepare UDP Flow for Table 0. Everything the same as TCP except the nw_proto
        new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
        new_int_flow_tbl_0_udp["match"]["nw_proto"] = settings.UDP

        # Prepare Flows for Table 2 - No TCP or UDP specifics
        new_int_flow_tbl_2["table_id"] = settings.INT_TABLE

        # if intra-switch EVC, then output port should be the proxy
        if is_intra_switch_evc(evc):
            for instruction in new_int_flow_tbl_2["instructions"]:
                if instruction["instruction_type"] == "apply_actions":
                    for action in instruction["actions"]:
                        if action["action_type"] == "output":
                            # Since this is the INT Source, we use source
                            # to avoid worrying about single or multi
                            # home physical loops. The choice for destination is at the INT Sink.
                            action["port"] = proxy_port

        instructions = add_to_apply_actions(new_int_flow_tbl_2["instructions"],
                                            new_instruction={"action_type": "add_int_metadata"},
                                            position=0)

        new_int_flow_tbl_2["instructions"] = instructions

        new_flows.append(new_int_flow_tbl_0_tcp)
        new_flows.append(new_int_flow_tbl_0_udp)
        new_flows.append(new_int_flow_tbl_2)

        return new_flows

    @staticmethod
    def enable_int_hop(evc, source, destination):
        """ At the INT hops, one flow adds two more: one for UDP on table 0, one for TCP on table 0
        On table 0, we add 'add_int_metadata' before other actions. We use source and destination to
        create the unidirectional support for telemetry.

        Args:
            evc: EVC.__dict__
            source: interface_id
            destination: interface_id
        Returns:
            list of new flows to install
        """

        new_flows = []

        for interface_id in get_unidirectional_path(evc, source, destination):

            switch = ":".join(interface_id.split(":")[0:8])
            for flow in get_evc_flows(switch, evc):
                interface = int(interface_id.split(":")[8])
                if flow['match']['in_port'] == interface:

                    new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
                    new_int_flow_tbl_0_tcp['cookie'] = get_new_cookie(flow["cookie"])
                    for extraneous_key in ["stats", "id"]:
                        new_int_flow_tbl_0_tcp.pop(extraneous_key, None)

                    # Prepare TCP Flow
                    new_int_flow_tbl_0_tcp["match"]["dl_type"] = settings.IPv4
                    new_int_flow_tbl_0_tcp["match"]["nw_proto"] = settings.TCP
                    prio_ = set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])
                    new_int_flow_tbl_0_tcp["priority"] = prio_

                    for instruction in new_int_flow_tbl_0_tcp["instructions"]:
                        if instruction["instruction_type"] == "apply_actions":
                            instruction["actions"].insert(0, {"action_type": "add_int_metadata"})

                    # Prepare UDP Flow
                    new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
                    new_int_flow_tbl_0_udp["match"]["nw_proto"] = settings.UDP

                    new_flows.append(new_int_flow_tbl_0_tcp)
                    new_flows.append(new_int_flow_tbl_0_udp)

        return new_flows

    @staticmethod
    def enable_int_sink(destination, evc, proxy_port):
        """ At the INT sink, one flow becomes many:
            1. Before the proxy, we do add_int_metadata as an INT hop. We need to keep the set_queue
            2. After the proxy, we do send_report and pop_int and output
            We only use table 0 for #1.
            We use table 2 for #2. for pop_int and output
        Args:
            destination: destination UNI
            evc: EVC.__dict__
            proxy_port: ProxyPort class since both source and destination port are used.
        Returns:
            list of new flows to install
        """
        new_flows = []

        for flow in get_evc_flows(destination["switch"], evc):

            # Only consider flows coming from NNI interfaces
            if flow["match"]["in_port"] == destination["interface"]:
                continue

            new_int_flow_tbl_0_tcp = copy.deepcopy(flow)
            new_int_flow_tbl_0_tcp['cookie'] = get_new_cookie(flow["cookie"])

            if not new_int_flow_tbl_0_tcp:
                log.info("Error: Flow not found. Kytos still loading.")
                raise FlowsNotFound(evc["id"])

            # Check compatibility:
            if "instructions" not in new_int_flow_tbl_0_tcp:
                log.info("Error: Flow_Manager needs to support 'instructions' and it does not.")
                raise UnsupportedFlow()

            # Remove keys that need to be recycled later by Flow_Manager.
            for extraneous_key in ["stats", "id"]:
                new_int_flow_tbl_0_tcp.pop(extraneous_key, None)

            # Save for pos-proxy flows
            new_int_flow_tbl_0_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)
            new_int_flow_tbl_2_pos = copy.deepcopy(new_int_flow_tbl_0_tcp)

            # Prepare TCP Flow for Table 0 PRE proxy
            if not is_intra_switch_evc(evc):
                new_int_flow_tbl_0_tcp["match"]["dl_type"] = settings.IPv4
                new_int_flow_tbl_0_tcp["match"]["nw_proto"] = settings.TCP
                prio_ = set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])
                new_int_flow_tbl_0_tcp["priority"] = prio_

                # Add telemetry, keep set_queue, output to the proxy port.
                output_port_no = proxy_port.source
                for instruction in new_int_flow_tbl_0_tcp["instructions"]:
                    if instruction["instruction_type"] == "apply_actions":
                        # Keep set_queue
                        actions = modify_actions(instruction["actions"],
                                                 ["pop_vlan", "push_vlan", "set_vlan", "output"],
                                                 remove=True)
                        actions.insert(0, {"action_type": "add_int_metadata"})
                        actions.append({"action_type": "output", "port": output_port_no})
                        instruction["actions"] = actions

                # Prepare UDP Flow for Table 0
                new_int_flow_tbl_0_udp = copy.deepcopy(new_int_flow_tbl_0_tcp)
                new_int_flow_tbl_0_udp["match"]["nw_proto"] = settings.UDP

                new_flows.append(copy.deepcopy(new_int_flow_tbl_0_tcp))
                new_flows.append(copy.deepcopy(new_int_flow_tbl_0_udp))
                del instruction  # pylint: disable=W0631

            # Prepare Flows for Table 0 AFTER proxy. No difference between TCP or UDP
            in_port_no = proxy_port.destination

            new_int_flow_tbl_0_pos["match"]["in_port"] = in_port_no
            prio_ = set_priority(flow["id"], new_int_flow_tbl_0_tcp["priority"])
            new_int_flow_tbl_0_pos["priority"] = prio_

            instructions = [{"instruction_type": "apply_actions",
                             "actions": [{"action_type": "send_report"}]},
                            {"instruction_type": "goto_table", "table_id": settings.INT_TABLE}]
            new_int_flow_tbl_0_pos["instructions"] = instructions

            # Prepare Flows for Table 2 POS proxy
            new_int_flow_tbl_2_pos["match"]["in_port"] = in_port_no
            new_int_flow_tbl_2_pos["table_id"] = settings.INT_TABLE

            for instruction in new_int_flow_tbl_2_pos["instructions"]:
                if instruction["instruction_type"] == "apply_actions":
                    instruction["actions"].insert(0, {"action_type": "pop_int"})

            new_flows.append(copy.deepcopy(new_int_flow_tbl_0_pos))
            new_flows.append(copy.deepcopy(new_int_flow_tbl_2_pos))
            del new_int_flow_tbl_0_tcp
            del new_int_flow_tbl_0_udp
            del new_int_flow_tbl_0_pos
            del new_int_flow_tbl_2_pos

        return new_flows

    def provision_int_unidirectional(self, evc, source, destination, proxy_port):
        """ Create INT flows from source to destination
        Args:
             evc:
             source:
             destination:
             proxy_port: ProxyPort class assigned to source
        Returns:
             boolean
        """

        try:
            # Create flows for the first switch (INT Source)
            new_flows = self.enable_int_source(source, evc, proxy_port.source)

            # Create flows the INT hops
            new_flows += list(self.enable_int_hop(evc, source, destination))

            # # Create flows for the last switch (INT Sink)
            new_flows += list(self.enable_int_sink(destination, evc, proxy_port))

            return push_flows(new_flows)

        except FlowsNotFound:
            return False

        except Exception as err:  # pylint: disable=W0703
            log.info(f"Error: {err}")
            return False

    def provision_int(self, evc_id):
        """ Create telemetry flows for an EVC. """

        evc = get_evc(evc_id)
        if not evc:
            raise EvcDoesNotExist(evc_id)

        # Make sure evc_id isn't already INT-enabled. If changes are needed,
        # USER should disable and enable it again.
        if has_int_enabled(evc):
            raise EvcAlreadyHasINT(evc_id)

        # Get the EVC endpoints
        uni_a, uni_z = get_evc_unis(evc)

        # Check if there are proxy ports on the endpoints' switches
        uni_a_proxy_port = get_proxy_port(uni_a["switch"], uni_a["interface"])
        uni_z_proxy_port = get_proxy_port(uni_z["switch"], uni_z["interface"])

        # INT is enabled per direction.
        # It's possible and acceptable to have INT just in one direction.

        # Direction uni_z -> uni_a
        if uni_a_proxy_port:
            if not self.provision_int_unidirectional(evc, uni_z, uni_a, uni_a_proxy_port):
                # change EVC metadata "telemetry": {"enabled": true } via API
                raise NotPossibleToEnableTelemetry(evc_id)

        # Direction uni_a -> uni_z
        if uni_z_proxy_port:
            if not self.provision_int_unidirectional(evc, uni_a, uni_z, uni_z_proxy_port):
                raise NotPossibleToEnableTelemetry(evc_id)

        # Change EVC metadata "telemetry": {"enabled": true } via API
        if uni_a_proxy_port and uni_z_proxy_port:
            if not set_telemetry_true_for_evc(evc_id, "bidirectional"):
                raise NotPossibleToEnableTelemetry(evc_id)
            msg = f"INT enabled for EVC ID {evc_id} on both directions"

        elif uni_a_proxy_port or uni_z_proxy_port:
            if not set_telemetry_true_for_evc(evc_id, "unidirectional"):
                raise NotPossibleToEnableTelemetry(evc_id)

            msg = f"INT enabled for EVC ID {evc_id} on direction "
            if uni_z_proxy_port:
                msg += f"{evc['uni_a']['interface_id']} -> {evc['uni_z']['interface_id']}"
            else:
                msg += f"{evc['uni_z']['interface_id']} -> {evc['uni_a']['interface_id']}"

        else:
            raise NoProxyPortsAvailable(evc_id)

        return msg

    @staticmethod
    def remove_int_flows(evc):
        """ Search for all flows belonging to an EVC and delete them. """

        for switch in retrieve_switches(evc):
            if not delete_flows(get_evc_flows(switch, evc, telemetry=True)):
                return False

        return True

    def decommission_int(self, evc_id):
        """ Remove all INT flows for an EVC
        Args:
            evc_id: EVC to be returned to non-INT EVC
        """

        # Get EVC().dict from evc_id
        evc = get_evc(evc_id)
        if not evc:
            raise EvcDoesNotExist(evc_id)

        if not has_int_enabled(evc):
            raise EvcHasNoINT(evc_id)

        # Code to actually remove flows.
        if not self.remove_int_flows(evc):
            raise NotPossibleToDisableTelemetry(evc_id)

        # Update mef_eline.
        if not set_telemetry_false_for_evc(evc_id):
            raise NotPossibleToDisableTelemetry(evc_id)

        return f"EVC ID {evc_id} is no longer INT-enabled."

    # REST methods

    @rest('v1/evc/enable', methods=['POST'])
    def enable_telemetry(self, request: Request) -> JSONResponse:
        """ REST to enable/create INT flows for one or more EVC_IDs.
                  evcs are provided via POST as a list
        Args:
            {"evc_ids": [list of evc_ids] }

        Returns:
            200 and outcomes for each evc listed.
        """

        try:
            content = get_json_or_400(request, self.controller.loop)
            evcs = content["evc_ids"]

        except (TypeError, KeyError):
            raise HTTPException(400, detail="Incorrect request provided.")

        status = {}

        if not evcs:
            # Enable telemetry for ALL EVCs.
            evcs = get_evcs_ids()

        # Process each EVC individually
        for idx, evc_id in enumerate(evcs, start=1):

            try:
                status[evc_id] = self.provision_int(evc_id)

            except EvcDoesNotExist as err_msg:
                # Ignore since it is not an issue.
                status[evc_id] = err_msg.message

            except EvcAlreadyHasINT as err_msg:
                # Ignore since it is not an issue.
                status[evc_id] = err_msg.message

            except NoProxyPortsAvailable as err_msg:
                # TODO: document which EVC had error.
                status[evc_id] = err_msg.message

            except NotPossibleToEnableTelemetry as err_msg:
                # Rollback INT configuration. If there is proxy port,
                # and it was not possible to enable telemetry, rollback both directions.
                # It will be a decommission operation plus force.
                status[evc_id] = err_msg.message

            except Exception as err_msg:
                # All others errors
                log.err(err_msg)
                status[evc_id] = str(err_msg)

            # Process every 10 EVCs and wait 10 seconds.
            if idx % 10 == 0:
                time.sleep(10)

        return JSONResponse(status)

    @rest('v1/evc/disable', methods=['POST'])
    def disable_telemetry(self, request: Request) -> JSONResponse:
        """ REST to disable/remove INT flows for an EVC_ID
        Args:
            {"evc_ids": [list of evc_ids] }
        Returns:
            200 if successful
            400 is otherwise
        """
        try:
            content = get_json_or_400(request, self.controller.loop)
            evcs = content["evc_ids"]

        except (TypeError, KeyError):
            raise HTTPException(400, detail="Incorrect request provided.")

        status = {}

        if not evcs:
            # Disable telemetry for ALL EVCs.
            evcs = get_evcs_ids()

        for evc_id in evcs:

            try:
                status[evc_id] = self.decommission_int(evc_id)

            except EvcDoesNotExist as err_msg:
                # Ignore since it is not an issue.
                status[evc_id] = err_msg.message

            except EvcHasNoINT as err_msg:
                # Ignore since it is not an issue.
                status[evc_id] = err_msg.message

            except NotPossibleToDisableTelemetry as err_msg:
                # Rollback INT configuration. This error will lead to inconsistency.
                # Critical
                status[evc_id] = err_msg.message

            except Exception as err:
                log.err(err)
                status[evc_id] = err

        return JSONResponse(status)

    @rest('v1/evc')
    def get_evcs(self, _request: Request) -> JSONResponse:
        """ REST to return the list of EVCs with INT enabled """
        return JSONResponse(get_evc_with_telemetry())

    @rest('v1/sync')
    def sync_flows(self, _request: Request) -> JSONResponse:
        """ Endpoint to force the telemetry napp to search for INT flows and delete them
        accordingly to the evc metadata. """

        # TODO
        # for evc_id in get_evcs_ids():
        return JSONResponse("TBD")

    @rest('v1/evc/update')
    def update_evc(self, _request: Request) -> JSONResponse:
        """ If an EVC changed from unidirectional to bidirectional telemetry, make the change. """
        return JSONResponse({})

    # Event-driven methods: future
    def listen_for_new_evcs(self):
        """ Change newly created EVC to INT-enabled EVC based on the metadata field (future) """
        pass

    def listen_for_evc_change(self):
        """ Change newly created EVC to INT-enabled EVC based on the metadata field (future) """
        pass

    def listen_for_path_changes(self):
        """ Change EVC's new path to INT-enabled EVC based on the metadata field when there
        is a path change. (future) """
        pass

    def listen_for_evcs_removed(self):
        """ Remove all INT flows belonging the just removed EVC (future) """
        pass

    def listen_for_topology_changes(self):
        """ If the topology changes, make sure it is not the loop ports.
        If so, update proxy ports """
        # TODO:
        # self.proxy_ports = create_proxy_ports(self.proxy_ports)
        pass

    def listen_for_evc_metadata_changes(self):
        """ If the proxy port changes, the flows have to be reconfigured. """
        pass
