"""The yarastorm service."""


import binascii
import os
from typing import TypedDict

from stormlibpp import utils
from stormlibpp.node import NodeTuple, StormNode
from stormlibpp.telepath import BoolRetn, TelepathRetn
import synapse.exc as s_exc
import synapse.lib.cell as s_cell
import synapse.telepath as s_telepath
import yara

from .api import YaraApi


class YaraMatch(TypedDict):
    rule: str
    sha256: str
    matched: bool


class MatchReturn(TelepathRetn):
    data: YaraMatch | None


class YaraRules:
    def __init__(self, ruledir: str) -> None:
        self.ruledir = ruledir
        self.rules = {}
        self.load()

    def load(self):
        for dname, _, fname in os.walk(self.ruledir):
            self.load_rule(utils.absjoin(dname, fname))

    def load_rule(self, rpath: str):
        with open(rpath, "rb") as fd:
            self.rules[os.path.basename(rpath).split(".")[0]] = yara.load(file=fd)

    def get(self, rule_id: str):
        if rule_id not in self.rules:
            self.load_rule(utils.absjoin(self.ruledir, rule_id))

        return self.rules.get(rule_id, None)

    def add(self, rule_id: str, compiled_rule: yara.Rules):
        rule_path = utils.absjoin(self.ruledir, rule_id)
        with open(rule_path) as fd:
            compiled_rule.save(file=fd)
        self.load_rule(rule_path)

    def get_rule_from_node(self, node: StormNode):
        rule_id = node.value
        local_mtime = os.stat(utils.absjoin(self.ruledir, rule_id)).st_mtime
        rule_mtime = node.props["updated"]
        if rule_mtime and rule_mtime > local_mtime:
            outdated = True
        else:
            outdated = False

        if (rule := self.get(rule_id)) is not None and not outdated:
            return rule
        elif node.props["text"] is not None:
            self.add(rule_id, node.props["text"])
            return self.get(rule_id)
        else:
            return None


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
        self.ruledir = utils.absjoin(self.dirn, self.conf.get("rule_dir"))
        self.rules = YaraRules(self.ruledir)

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

    async def matchFile(
        self, file_sha256: str, yara_rules: list[NodeTuple]
    ) -> MatchReturn:
        """Test if the given Yara rules match the given file in the Axon."""

        file_bytes = await self._getBytes(file_sha256)
        if file_bytes is None:
            yield MatchReturn(
                status=False,
                mesg=f"Unable to find bytes for {file_sha256}",
                data=None,
            )
            return

        for rule_node in [StormNode.unpack(rule) for rule in yara_rules]:
            rule_id = rule_node.value
            rule_obj = self.rules.get_rule_from_node(rule_node)
            if rule_obj and rule_obj.match(data=file_bytes):
                yield MatchReturn(
                    status=True,
                    mesg="",
                    data=YaraMatch(rule_id, file_sha256, True),
                )
            elif rule_obj is None:
                yield MatchReturn(
                    status=False,
                    mesg=f"There are no rule contents in it:app:yara:rule={rule_id}",
                    data=None,
                )
            else:
                yield MatchReturn(
                    status=True,
                    mesg="",
                    data=YaraMatch(rule_id, file_sha256, False),
                )

        return

    async def compileRule(self, yara_rule: NodeTuple, check: bool = False) -> BoolRetn:
        """Compile the given Yara rule and save it to this Cell's storage."""

        rulenode = StormNode.unpack(yara_rule)

        try:
            rule = yara.compile(source=rulenode.props["text"], error_on_warning=True)
        except yara.SyntaxError as err:
            return BoolRetn(status=False, mesg=f"Yara Syntax Error - {err}", data=False)
        except yara.Error as err:
            return BoolRetn(status=False, mesg=f"Yara Error - {err}", data=False)

        if check:
            return BoolRetn(status=True, mesg="Successfully compiled rule!", data=True)

        self.rules.add(rulenode.value, rule)
        return BoolRetn(status=True, mesg="", data=True)
