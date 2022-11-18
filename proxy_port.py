""" This class helps to handle multi-home physical loops (two ports). """

from napps.amlight.telemetry.kytos_api_helper import get_topology_interfaces


def get_kytos_interface(switch, interface):
    """ Get the Kytos Interface as dict. Useful for multiple functions. """

    kytos_interfaces = get_topology_interfaces()["interfaces"]
    for kytos_interface in kytos_interfaces.values():
        if switch == kytos_interface["switch"]:
            if interface == kytos_interface["port_number"]:
                return kytos_interface


class ProxyPort:

    def __init__(self, switch, proxy_port):
        self.switch = switch
        self.source = None
        self.destination = None
        self.process(proxy_port)

    def get_interface(self, interface):
        return get_kytos_interface(self.switch, interface)

    @staticmethod
    def is_operational(interface):
        """ """
        if interface and interface["enabled"] and interface["active"]:
            return True
        return False

    @staticmethod
    def is_loop(interface):
        """ """
        if 'looped' in interface["metadata"] and 'port_numbers' in interface["metadata"]['looped']:
            return True
        return False

    def get_destination(self, interface):
        """ """
        if self.source != interface:
            kytos_interface = self.get_interface(interface=interface)
            if self.is_operational(kytos_interface):
                return interface
            else:
                return None

        return self.source

    def process(self, proxy_port):
        """ """

        kytos_interface = self.get_interface(interface=proxy_port)

        if not self.is_operational(kytos_interface) or not self.is_loop(kytos_interface):
            return None

        self.source = kytos_interface["metadata"]['looped']['port_numbers'][0]
        self.destination = self.get_destination(kytos_interface["metadata"]['looped']['port_numbers'][1])

    def is_ready(self):
        """ """
        if self.source and self.destination:
            return True
        return False
