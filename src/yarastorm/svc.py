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
    """The results of a single Yara match attempt, either successful or unsuccessful."""

    rule: str
    sha256: str
    matched: bool


class MatchRetn(TelepathRetn):
    """A TelepathRetn that describes a Yara match on a file."""

    data: YaraMatch | None


class YaraRules:
    """Manage the Yara rules that a YaraSvc uses.

    Parameters
    ----------
    ruledir : str
        The directory that compiled Yara rules are saved in.
    """

    def __init__(self, ruledir: str) -> None:
        self.ruledir = ruledir
        self.rules = {}
        self.load()

    def load(self) -> None:
        """Load all compiled Yara rules from the ruledir into this object.
        
        Walks the ``ruledir`` and calls ``load_rule`` on each path.
        """

        for dname, _, fname in os.walk(self.ruledir):
            self.load_rule(utils.absjoin(dname, fname))

    def load_rule(self, rpath: str) -> None:
        """Load a Yara rule into this object.
        
        A loaded rule is stored in ``rules`` with a key of the file's basename.
        This should equate to the Yara rule's Synapse guid.

        The value is a compiled ``yara.Rules`` object.

        Returns
        -------
        None
        """

        with open(rpath, "rb") as fd:
            self.rules[os.path.basename(rpath)] = yara.load(file=fd)

    def get(self, rule_id: str) -> yara.Rules | None:
        """Get a Yara rule from this object, loading from disk if needed.

        Will return None if the Yara rule is not known to this object
        and the Yara rule does exist on disk.

        Parameters
        ----------
        rule_id : str
            The ID of the rule, which should equate to the rule's file basename
            on disk. This should be the same as the GUID of the rule according
            to Synapse.

        Returns
        -------
        yara.Rules | None
            The compiled ``yara.Rules`` object from this object's memory. Or
            ``None`` if the rule is not stored in this object's memory and
            cannot be loaded from disk by the given ``rule_id``.
        """

        if rule_id not in self.rules:
            self.load_rule(utils.absjoin(self.ruledir, rule_id))

        return self.rules.get(rule_id, None)

    def add(self, rule_id: str, compiled_rule: yara.Rules) -> None:
        """Write a compiled Yara rule to disk and store it in this object.

        Parameters
        ----------
        rule_id : str
            The ID of the rule, which should equate to the rule's file basename
            on disk. This should be the same as the GUID of the rule according
            to Synapse.
        compiled_rule : yara.Rules
            The compiled Yara rule.

        Returns
        -------
        None
        """

        rule_path = utils.absjoin(self.ruledir, rule_id)
        with open(rule_path) as fd:
            compiled_rule.save(file=fd)
        self.load_rule(rule_path)

    def get_rule_from_node(self, node: StormNode) -> yara.Rules | None:
        """Get a Yara rule from this object based on the given node.

        This method also handles updating the compiled rule on disk if the node
        has an ``updated`` property and the value of this property is greater
        than the compiled rule's on disk last modified timestamp.

        Rules that do not yet exist on disk will be added to this object and
        saved to disk.

        Parameters
        ----------
        node : StormNode
            The ``it:prod:yara:rule`` node to either get or create a Yara rule with.

        Returns
        -------
        yara.Rules | None
            The compiled Yara rule object or None if there was a problem.
            None may also be returned if for some reason the given node does
            not have a Yara rule stored in the ``text`` property.
        """

        rule_id = node.value
        rpath = utils.absjoin(self.ruledir, rule_id)

        if os.path.exists(rpath):
            # Checks if the node has an updated property and compares that to the
            # compiled Yara rule's on-disk last modified time.
            outdated = bool(
                node.props["updated"] and node.props["updated"] > os.stat(rpath).st_mtime
            )
        else:
            # The rule doesn't exist on disk, so it can't be out of date locally.
            outdated = False

        if (rule := self.get(rule_id)) is not None and not outdated:
            return rule
        if node.props["text"] is not None:
            try:
                self.add(rule_id, yara.compile(node.props["text"]))
            except yara.Error:
                return None
            return self.get(rule_id)

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
        self.rules = YaraRules(
            utils.absjoin(self.dirn, self.conf.get("rule_dir"))
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

    async def matchFile(
        self, file_sha256: str, yara_rules: list[NodeTuple]
    ) -> MatchRetn:
        """Test if the given Yara rules match the given file in the Axon."""

        file_bytes = await self._getBytes(file_sha256)
        if file_bytes is None:
            yield MatchRetn(
                status=False,
                mesg=f"Bytes for file:bytes:sha256={file_sha256} are not in the Axon.",
                data=None,
            )
            return

        for rule_node in [StormNode.unpack(rule) for rule in yara_rules]:
            rule_id = rule_node.value
            rule_obj = self.rules.get_rule_from_node(rule_node)
            if rule_obj and rule_obj.match(data=file_bytes):
                yield MatchRetn(
                    status=True,
                    mesg="",
                    data=YaraMatch(rule_id, file_sha256, True),
                )
            elif rule_obj is None:
                yield MatchRetn(
                    status=False,
                    mesg=f"Either it:app:yara:rule={rule_id} has no rule contents "
                    "or the rule contains an error.",
                    data=None,
                )
            else:
                yield MatchRetn(
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
