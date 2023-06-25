"""The yarastorm service."""


import binascii
import os

from stormlibpp import s_exc
from stormlibpp.telepath import BoolRetn
import synapse.exc as s_exc
import synapse.lib.cell as s_cell
import synapse.telepath as s_telepath
# import yara

from . import yara # Using fake yara for now
from .api import YaraApi


class YaraSvc(s_cell.Cell):
    """The Cell implementation for the yarastorm service."""

    cellapi = YaraApi

    confdefs = {
        "axon_url": {
            "type": "string",
            "description": "The Telepath URL for an Axon service. "
            "This Axon is used to pull files for Yara matching.",
        },
        "rule_dir": {
            "type": "string",
            "description": "The directory that compiled Yara rules are saved in. "
            "This directory is relative to the Cell's 'dirn' path.",
            "default": "rules/",
        },
    }

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)
        self.axonurl = self.conf.get("axon_url")
        self.ruledir = os.path.abspath(
            os.path.join(self.dirn, self.conf.get("rule_dir"))
        )

    async def _getBytes(self, sha256: str) -> bytes | None:
        buffer = b""

        async with s_telepath.withTeleEnv():
            async with await s_telepath.openurl(self.axonurl) as axon:
                try:
                    async for part in axon.get(binascii.unhexlify(sha256)):
                        buffer += part
                except s_exc.NoSuchFile:
                    return None

        if len(buffer) == 0:
            return None

        return buffer

    async def matchFile(self, file_sha256: str, yara_rule) -> BoolRetn:
        """Test if a Yara rule matches a given file in the Axon."""

        file_bytes = await self._getBytes(file_sha256)

        if file_bytes is None:
            return BoolRetn(
                status=False,
                mesg=f"Unable to find bytes for {file_sha256}",
                data=False
            )

        # TODO read the compiled yara file from disk if up to date
        rule = yara.compile(source=yara_rule, error_on_warning=True)

        if rule.match(file_bytes):
            return BoolRetn(status=True, mesg="", data=True)

        return BoolRetn(status=True, mesg="", data=False)

    async def compileRule(self, yara_rule, check: bool = False) -> BoolRetn:
        """Compile the given Yara rule and save it to this Cell's storage."""

        try:
            rule = yara.compile(source=yara_rule, error_on_warning=True)
        except yara.SyntaxError as err:
            return BoolRetn(status=False, mesg=f"Yara Syntax Error - {err}", data=False)
        except yara.Error as err:
            return BoolRetn(status=False, mesg=f"Yara Error - {err}", data=False)

        if check:
            return BoolRetn(status=True, mesg="Successfully compiled rule!", data=True)

        # TODO actually save the compiled rule if check is false
        return BoolRetn(status=True, mesg="", data=True)
