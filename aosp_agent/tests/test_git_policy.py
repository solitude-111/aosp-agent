import subprocess
import unittest
from aosp_agent.discovery import local_git
from engine_fixtures import GitFixture, git


class GitPolicyTest(unittest.TestCase):
    def test_specific_protocol_config_cannot_reenable_lazy_fetch(self):
        with GitFixture() as fx:
            git(fx.repo, 'config', 'uploadpack.allowFilter', 'true')
            clone = fx.root / 'partial'
            subprocess.run(['git', '-c', 'protocol.file.allow=always', 'clone', '-q',
                            '--filter=blob:none', '--no-checkout', fx.repo.as_uri(), str(clone)],
                           check=True, capture_output=True)
            git(clone, 'config', 'protocol.file.allow', 'always')
            result = local_git(clone, 'show', f'{fx.target}:counter.py', check=False)
            self.assertNotEqual(result.returncode, 0)
            # A plain Git call in the disposable clone can fetch the same blob:
            # failure above is policy enforcement, not an invalid test object.
            self.assertIn('normalize_count', git(clone, 'show', f'{fx.target}:counter.py'))
