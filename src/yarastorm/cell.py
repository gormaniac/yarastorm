"""The yarastorm service."""


from stormlibpp.telepath import BoolRetn
import synapse.lib.cell as s_cell

from .api import YaraApi


class Yara(s_cell.Cell):
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

    async def matchFile(self, file_sha256: str, yara_rule) -> BoolRetn:
        """Test if a Yara rule matches a given file in the Axon."""

        # return BoolRetn(status=not mesg, mesg=mesg, data=matched)

    async def compileRule(self, yara_rule) -> BoolRetn:
        """Compile the given Yara rule and save it to this Cell's storage."""
