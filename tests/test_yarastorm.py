"""Pytests for yarastorm."""


import binascii

import synapse.common as s_common
import synapse.tests.utils as s_tests
from yarastorm import __version__, YaraSvc
from yarastorm.defs import SVC_NAME


CMDS = (
    f"{SVC_NAME}.check",
    f"{SVC_NAME}.disable",
    f"{SVC_NAME}.enable",
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

    async def test_cmd_yara_check(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            await core.nodes('[ it:app:yara:rule=* :text="test" :name="rule1"]')
            await core.nodes('[ it:app:yara:rule=* :text="rule dummy { condition: true }" :name="dummy" :enabled=$lib.true]')
            msgs = await core.stormlist(f"it:app:yara:rule | gormo.yara.check")
            print(msgs)
            self.stormHasNoErr(msgs)

    async def test_cmd_yara_scan(self):
        async with self.getTestAxon() as axon:
            _, sha256 = await axon.put(b"test")
            async with self.getTestCoreProxSvc(YaraSvc, ssvc_conf={"axon_url": axon.getLocalUrl()}) as (core, prox, svc):
                await core.nodes('[ it:app:yara:rule=* :text="test" :name="rule1"]')
                await core.nodes('[ it:app:yara:rule=* :text="rule dummy { condition: true }" :name="dummy" :enabled=$lib.true]')
                await core.nodes('[ file:bytes=* ]')
                await core.nodes(f'[ file:bytes={sha256.hex()} ]')
                msgs = await core.stormlist(f"file:bytes | gormo.yara.scan")
                print(msgs)
                self.stormHasNoErr(msgs)

    async def test_cmd_yara_enable(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            rule_id = s_common.guid()
            await core.nodes(f'[ it:app:yara:rule={rule_id} :text="test" :name="rule1"]')
            msgs = await core.stormlist(f"it:app:yara:rule={rule_id} | gormo.yara.enable")
            print(msgs)
            self.stormHasNoErr(msgs)

    async def test_cmd_yara_disable(self):
        async with self.getTestCoreProxSvc(YaraSvc) as (core, prox, svc):
            rule_id = s_common.guid()
            await core.nodes(f'[ it:app:yara:rule={rule_id} :text="rule dummy {{ condition: true }}" :name="dummy" :enabled=$lib.true]')
            msgs = await core.stormlist(f"it:app:yara:rule={rule_id} | gormo.yara.disable")
            print(msgs)
            self.stormHasNoErr(msgs)
