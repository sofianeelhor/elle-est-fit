class ElleEstFitError(Exception):
    """Base exception for all Elle-Est-Fit errors."""

    pass


class ValidationError(ElleEstFitError):
    """Exception raised for validation errors."""

    pass


class TechniqueError(ElleEstFitError):
    """Exception raised when a technique fails."""

    pass


class ExploitationError(ElleEstFitError):
    """Exception raised when exploitation fails."""

    pass


class ExecutionError(ElleEstFitError):
    """Exception raised when command execution fails."""

    pass
