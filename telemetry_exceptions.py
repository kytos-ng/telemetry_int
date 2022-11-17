

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
        return f'EVC {self.evc_id} {self.message}'


class EvcAlreadyHasINT(ErrorBase):
    """ """
    def __init__(self, evc_id, message="already has INT-enabled."):
        super().__init__(evc_id, message)


class EvcDoesNotExist(ErrorBase):
    """ """
    def __init__(self, evc_id, message="does not exist."):
        super().__init__(evc_id, message)


class NotPossibleToEnableTelemetry(ErrorBase):
    """ """
    def __init__(self, evc_id, message="error enabling telemetry. Check logs."):
        super().__init__(evc_id, message)

class NotPossibleToDisableTelemetry(ErrorBase):
    """ """
    def __init__(self, evc_id, message="error disabling telemetry. Check logs."):
        super().__init__(evc_id, message)


class NoProxyPortsAvailable(ErrorBase):
    """ """
    def __init__(self, evc_id, message="no proxy ports available."):
        super().__init__(evc_id, message)


class EvcHasNoINT(ErrorBase):
    """ """
    def __init__(self, evc_id, message="INT was not enabled for this EVC."):
        super().__init__(evc_id, message)


class FlowsNotFound(ErrorBase):
    def __init__(self, evc_id, message="Flow not found. Kytos still loading?"):
        super().__init__(evc_id, message)


class UnsupportedFlow(ErrorBase):
    def __init__(self, evc_id, message="Unsupported Flow found."):
        super().__init__(evc_id, message)