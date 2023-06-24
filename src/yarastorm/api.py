"""The CellApi implementation for yarastorm."""


import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc

from .defs import SVC_EVTS, PKGDEFS, SVC_NAME, SVC_VER
from .lib import normver


class YaraApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the triage-sandbox service."""

    # These defaults must be overridden from the StormSvc mixin
    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS
