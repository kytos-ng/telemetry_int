"""Test exceptions.py"""

from napps.kytos.telemetry_int.exceptions import (
    UnrecoverableError,
    EVCError,
    ProxyPortError,
    ProxyPortNotFound,
    ProxyPortMetadataNotFound,
    ProxyPortDestNotFound,
    ProxyPortConflict,
    ProxyPortRequired,
    ProxyPortAsymmetric,
    ProxyPortStatusNotUP,
    ProxyPortSameSourceIntraEVC,
    ProxyPortShared,
    EVCHasNoINT,
    EVCHasINT,
    EVCNotFound,
    FlowsNotFound,
    PriorityOverflow,
)


class TestExceptions:
    """Test class for all exception classes."""

    def setup_method(self):
        """Set up test fixtures."""
        self.evc_id = "test_evc_id"
        self.message = "test message"

    def test_unrecoverable_error(self):
        """Test UnrecoverableError exception."""
        message = "Test error message"
        error = UnrecoverableError(message)

        assert error.message == message
        assert str(error) == message

    def test_evc_error(self):
        """Test EVCError exception."""
        error = EVCError(self.evc_id, self.message)

        assert error.evc_id == self.evc_id
        assert error.message == self.message
        assert str(error) == f"EVC {self.evc_id} {self.message}"

    def test_evc_has_no_int_default_message(self):
        """Test EVCHasNoINT with default message."""
        error = EVCHasNoINT(self.evc_id)

        assert error.evc_id == self.evc_id
        assert error.message == "INT isn't enabled"
        assert str(error) == f"EVC {self.evc_id} INT isn't enabled"

    def test_evc_has_no_int_custom_message(self):
        """Test EVCHasNoINT with custom message."""
        custom_message = "custom message"
        error = EVCHasNoINT(self.evc_id, custom_message)

        assert error.evc_id == self.evc_id
        assert error.message == custom_message
        assert str(error) == f"EVC {self.evc_id} {custom_message}"

    def test_evc_has_int_default_message(self):
        """Test EVCHasINT with default message."""
        error = EVCHasINT(self.evc_id)

        assert error.evc_id == self.evc_id
        assert error.message == "INT is already enabled"
        assert str(error) == f"EVC {self.evc_id} INT is already enabled"

    def test_evc_has_int_custom_message(self):
        """Test EVCHasINT with custom message."""
        custom_message = "custom message"
        error = EVCHasINT(self.evc_id, custom_message)

        assert error.evc_id == self.evc_id
        assert error.message == custom_message
        assert str(error) == f"EVC {self.evc_id} {custom_message}"

    def test_evc_not_found_default_message(self):
        """Test EVCNotFound with default message."""
        error = EVCNotFound(self.evc_id)

        assert error.evc_id == self.evc_id
        assert error.message == "not found"
        assert str(error) == f"EVC {self.evc_id} not found"

    def test_evc_not_found_custom_message(self):
        """Test EVCNotFound with custom message."""
        custom_message = "custom message"
        error = EVCNotFound(self.evc_id, custom_message)

        assert error.evc_id == self.evc_id
        assert error.message == custom_message
        assert str(error) == f"EVC {self.evc_id} {custom_message}"

    def test_flows_not_found_default_message(self):
        """Test FlowsNotFound with default message."""
        error = FlowsNotFound(self.evc_id)

        assert error.evc_id == self.evc_id
        assert error.message == "flows not found"
        assert str(error) == f"EVC {self.evc_id} flows not found"

    def test_flows_not_found_custom_message(self):
        """Test FlowsNotFound with custom message."""
        custom_message = "custom message"
        error = FlowsNotFound(self.evc_id, custom_message)

        assert error.evc_id == self.evc_id
        assert error.message == custom_message
        assert str(error) == f"EVC {self.evc_id} {custom_message}"

    def test_priority_overflow_default_message(self):
        """Test PriorityOverflow with default message."""
        error = PriorityOverflow(self.evc_id)

        assert error.evc_id == self.evc_id
        assert error.message == "setting a higher priority would overflow"
        assert "would overflow" in str(error)

    def test_priority_overflow_custom_message(self):
        """Test PriorityOverflow with custom message."""
        custom_message = "custom message"
        error = PriorityOverflow(self.evc_id, custom_message)

        assert error.evc_id == self.evc_id
        assert error.message == custom_message
        assert str(error) == f"EVC {self.evc_id} {custom_message}"

    def test_exception_inheritance(self):
        """Test exception inheritance hierarchy."""
        assert issubclass(EVCError, UnrecoverableError)
        assert issubclass(ProxyPortError, EVCError)
        assert issubclass(ProxyPortNotFound, ProxyPortError)
        assert issubclass(ProxyPortMetadataNotFound, ProxyPortNotFound)
        assert issubclass(ProxyPortDestNotFound, ProxyPortNotFound)
        assert issubclass(ProxyPortConflict, ProxyPortError)
        assert issubclass(ProxyPortRequired, ProxyPortConflict)
        assert issubclass(ProxyPortAsymmetric, ProxyPortConflict)
        assert issubclass(ProxyPortStatusNotUP, ProxyPortConflict)
        assert issubclass(ProxyPortSameSourceIntraEVC, ProxyPortConflict)
        assert issubclass(ProxyPortShared, ProxyPortConflict)
        assert issubclass(EVCHasNoINT, EVCError)
        assert issubclass(EVCHasINT, EVCError)
        assert issubclass(EVCNotFound, EVCError)
        assert issubclass(FlowsNotFound, EVCError)
        assert issubclass(PriorityOverflow, EVCError)

    def test_proxy_port_error_instantiation(self):
        """Test ProxyPortError and its subclasses can be instantiated."""
        errors = [
            ProxyPortError(self.evc_id, self.message),
            ProxyPortNotFound(self.evc_id, self.message),
            ProxyPortMetadataNotFound(self.evc_id, self.message),
            ProxyPortDestNotFound(self.evc_id, self.message),
            ProxyPortConflict(self.evc_id, self.message),
            ProxyPortRequired(self.evc_id, self.message),
            ProxyPortAsymmetric(self.evc_id, self.message),
            ProxyPortStatusNotUP(self.evc_id, self.message),
            ProxyPortSameSourceIntraEVC(self.evc_id, self.message),
            ProxyPortShared(self.evc_id, self.message),
        ]

        for error in errors:
            assert error.evc_id == self.evc_id
            assert error.message == self.message
            assert str(error) == f"EVC {self.evc_id} {self.message}"
