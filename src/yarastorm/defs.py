"""The Python definition of the yarastorm Storm package."""


from . import __version__
from .lib import StormPkg


SVC_NAME = "gormo.yara"
SVC_VER = __version__
SVC_GUID = "12bc0c8c1a37a29808d97972875d3913"
SVC_SYN_MIN_VER = (2, 137, 0)

SVC_EVTS = {
    "add": {
        "storm": f'[(meta:source={SVC_GUID} :name={SVC_NAME})]'
    }
}


class GormoYaraPkg(StormPkg):
    """The gormo.yara Storm package for the yarastorm service."""


PKGDEFS = (GormoYaraPkg(proto_name="gormo.yara").asdict(),)
