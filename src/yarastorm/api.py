"""The CellApi implementation for yarastorm."""


from stormlibpp.telepath import BoolRetn
from stormlibpp.utils import normver
import synapse.lib.cell as s_cell
import synapse.lib.stormsvc as s_stormsvc

from .defs import SVC_EVTS, PKGDEFS, SVC_NAME, SVC_VER


class YaraApi(s_cell.CellApi, s_stormsvc.StormSvc):
    """The Telepath API endpoints for the triage-sandbox service."""

    # These defaults must be overridden from the StormSvc mixin
    _storm_svc_name = SVC_NAME
    _storm_svc_vers = normver(SVC_VER)[1]
    _storm_svc_evts = SVC_EVTS
    _storm_svc_pkgs = PKGDEFS

    async def matchFile(self, file_sha256: str, yara_rule) -> BoolRetn:
        """Test if a Yara rule matches a given file in the Axon."""

        return await self.cell.matchFile(file_sha256, yara_rule)

    async def compileRule(self, yara_rule, check: bool = False) -> BoolRetn:
        """Compile the given Yara rule and save it to this Cell's storage."""

        return await self.cell.compileRule(yara_rule, check)
