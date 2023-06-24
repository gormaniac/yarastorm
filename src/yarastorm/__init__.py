"""The yarastorm Python Package."""

__version__ = "0.0.1"


from .lib import TelepathRetn


class BoolRetn(TelepathRetn):
    """A TelepathRetn where ``data`` is a boolean value."""
    data: bool
