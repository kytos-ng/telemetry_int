""" Customized Exceptions """


class UnrecoverableError(Exception):
    """UnrecoverableError.

    Base exception for any custom exception that shouldn't be retried.
    """

    def __init__(self, message: str) -> None:
        """Constructor of UnrecoverableError."""
        self.message = message
        super().__init__(self.message)


class EVCError(UnrecoverableError):
    """Exception raised for unrecoverable EVC errors

    Attributes:
        evc_id -- evc ID provided
        message -- explanation of the error
    """

    def __init__(self, evc_id: str, message: str):
        self.evc_id = evc_id
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"EVC {self.evc_id} {self.message}"


class ProxyPortError(EVCError):
    """ProxyPortError."""


class ProxyPortNotFound(ProxyPortError):
    """ProxyPortNotFound."""


class ProxyPortStatusNotUP(ProxyPortError):
    """ProxyPortStatusNotUP."""


class ProxyPortSameSourceIntraEVC(ProxyPortError):
    """ProxyPortSameSourceIntraEVC.

    Intra EVC UNIs must use different proxy ports.
    """


class EVCHasNoINT(EVCError):
    """Exception in case the EVC doesn't have INT enabled."""

    def __init__(self, evc_id: str, message="INT isn't enabled"):
        super().__init__(evc_id, message)


class EVCHasINT(EVCError):
    """Exception in case the EVC already has INT enabled."""

    def __init__(self, evc_id: str, message="INT is already enabled"):
        super().__init__(evc_id, message)


class EVCNotFound(EVCError):
    """Exception in case the EVC isn't found."""

    def __init__(self, evc_id: str, message="not found"):
        super().__init__(evc_id, message)


class FlowsNotFound(EVCError):
    """Exception in case the EVC's flows are not there."""

    def __init__(self, evc_id: str, message="flows not found"):
        super().__init__(evc_id, message)


class PriorityOverflow(EVCError):
    """Exception in case the EVC's can't set a higher priority."""

    def __init__(self, evc_id: str, message="setting a higher priority would overflow"):
        super().__init__(evc_id, message)
