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
    """Exception in case an UNI doesn't have a proxy port configured or operational."""

    def __init__(self, evc_id, message="no proxy ports available"):
        super().__init__(evc_id, message)


class ProxyPortError(ErrorBase):

    """ProxyPortError."""

    def __init__(self, evc_id: str, msg: str) -> None:
        """Constructor of ProxyPortError."""
        super().__init__(evc_id, msg)


class ProxyPortNotFound(ProxyPortError):
    """ProxyPortNotFound."""

    def __init__(self, evc_id: str, msg: str) -> None:
        """Constructor of ProxyPortError."""
        super().__init__(evc_id, msg)


class ProxyPortStatusNotUP(ProxyPortError):
    """ProxyPortStatusNotUP."""

    def __init__(self, evc_id: str, msg: str) -> None:
        """Constructor of ProxyPortNotUP."""
        super().__init__(evc_id, msg)


class EVCHasNoINT(ErrorBase):
    """Exception in case the EVC doesn't have INT enabled."""

    def __init__(self, evc_id, message="INT isn't enabled"):
        super().__init__(evc_id, message)


class EVCHasINT(ErrorBase):
    """Exception in case the EVC already has INT enabled."""

    def __init__(self, evc_id, message="INT is already enabled"):
        super().__init__(evc_id, message)


class EVCNotFound(ErrorBase):
    """Exception in case the EVC isn't found."""

    def __init__(self, evc_id, message="not found"):
        super().__init__(evc_id, message)


class FlowsNotFound(ErrorBase):
    """Exception in case the EVC's flows are not there."""

    def __init__(self, evc_id, message="flows not found"):
        super().__init__(evc_id, message)


class PriorityOverflow(ErrorBase):
    """Exception in case the EVC's can't set a higher priority."""

    def __init__(self, evc_id, message="setting a higher priority would overflow"):
        super().__init__(evc_id, message)
