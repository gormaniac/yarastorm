"""Pytests for yarastorm."""


import synapse.tests.utils as s_tests
from yarastorm import __version__, YaraSvc
from yarastorm.defs import SVC_NAME


CMDS = (
    f"{SVC_NAME}.check",
    f"{SVC_NAME}.disable",
    f"{SVC_NAME}.release",
    f"{SVC_NAME}.scan",
)
MODS = (f"{SVC_NAME}.lib",)


class TestYaraStorm(s_tests.SynTest):
    """Test suite for the yarastorm service."""

    async def test_svc_starts(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            msgs = await core.stormlist("service.list")
            self.stormIsInPrint(f"true (svc) ({SVC_NAME} @ {__version__})", msgs)

    async def test_pkg_cmds_exist(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            for cmd in CMDS:
                assert cmd in core.stormcmds

    async def test_pkg_mods_exist(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            for mod in MODS:
                assert mod in core.stormmods

    async def test_pkg_mods_import(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            for mod in MODS:
                msgs = await core.stormlist(f"$mod = $lib.import({mod})")
                self.stormHasNoErr(msgs)

    async def test_svc_import(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            msgs = await core.stormlist(f"$svc = $lib.service.get({SVC_NAME})")
            self.stormHasNoErr(msgs)

    async def test_cmd_yara_scan(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            # Not really how we will use this - just testing right now.
            await core.nodes('[ it:app:yara:rule=* :text="test" :name="rule1"]')
            msgs = await core.stormlist(f"it:app:yara:rule | gormo.yara.scan")
            self.stormHasNoErr(msgs)
