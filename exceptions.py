""" Customized Exceptions """


class ErrorBase(Exception):
    """Exception raised for situations where the
    EVC provided is non-existent.

    Attributes:
        evc_id -- evc ID provided
        message -- explanation of the error
    """

    def __init__(self, evc_id, message):
        self.evc_id = evc_id
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"EVC {self.evc_id} {self.message}"


class NoProxyPortsAvailable(ErrorBase):
    """Exception in case an UNI doesn't have a proxy port configured or operational.
    That's a warning."""

    def __init__(self, evc_id, message="no proxy ports available."):
        super().__init__(evc_id, message)


class EvcHasNoINT(ErrorBase):
    """Exception in case the EVC doesn't have INT/telemetry enabled but it was
    treated as if. That's a warning."""

    def __init__(self, evc_id, message="INT was not enabled for this EVC."):
        super().__init__(evc_id, message)


class FlowsNotFound(ErrorBase):
    """Exception in case the EVC's flows are not there. Used for testing and debugging.
    That's an warning. Maybe it requires some investigation."""

    def __init__(self, evc_id, message="Flow not found."):
        super().__init__(evc_id, message)
