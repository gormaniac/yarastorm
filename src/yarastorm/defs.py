"""The Python definition of the yarastorm Storm package."""


from . import __version__
from .lib import StormPkg


SVC_NAME = "gormo.yara"
SVC_VER = __version__
SVC_GUID = "12bc0c8c1a37a29808d97972875d3913"
SVC_SYN_MIN_VER = (2, 137, 0)

SVC_EVTS = {}


class GormoYaraPkg(StormPkg):
    """The gormo.yara Storm package for the yarastorm service."""

    pkg_name = SVC_NAME
    pkg_ver = SVC_VER
    synapse_minversion = SVC_SYN_MIN_VER


PKGDEFS = (GormoYaraPkg(),)
