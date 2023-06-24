"""The yarastorm service."""


import os

from stormlibpp import TelepathRetn
from stormlibpp.telepath import BoolRetn
import synapse.lib.cell as s_cell

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

    async def test(self, test):

        return {"status": True, "data": 'test', "mesg": 'a message'}

    async def matchFile(self, file_sha256: str, yara_rule) -> BoolRetn:
        """Test if a Yara rule matches a given file in the Axon."""

        retn = BoolRetn(status=False, mesg="", data=True)
        return retn

    async def compileRule(self, yara_rule, check: bool = False) -> BoolRetn:
        """Compile the given Yara rule and save it to this Cell's storage."""

        return TelepathRetn(status=True, mesg="", data=yara_rule)
