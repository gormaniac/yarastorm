"""The Cell implementation for yarastorm."""


import synapse.lib.cell as s_cell

from .api import YaraApi


class Yara(s_cell.Cell):
    """The Cell implementation for the yara service."""

    cellapi = YaraApi

    confdefs = {}

    async def __anit__(self, dirn, *args, **kwargs):
        await s_cell.Cell.__anit__(self, dirn, *args, **kwargs)
