"""Run the real shell runner against a temporary envsetup stub, never Android."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


RUNNER = Path(__file__).resolve().parents[2] / 'scripts/module-build-r760.sh'
ENVSETUP = '''
get_build_var() {
    case "$1" in
        TARGET_ARCH) printf '%s\\n' x86_64 ;;
        PRODUCT_OUT) printf '%s\\n' "$FIXTURE_QUERY_PRODUCT_OUT" ;;
        *) return 1 ;;
    esac
}
get_abs_build_var() { printf '%s\\n' "$FIXTURE_PRODUCT_OUT"; }
setpaths() {
    # Exact collision in Android 12 build/make envsetup.sh:312-313.
    export ANDROID_PRODUCT_OUT=$(get_abs_build_var PRODUCT_OUT)
    export OUT=$ANDROID_PRODUCT_OUT
}
lunch() { setpaths; }
m() { printf 'fixture build adapter only\\n'; return 0; }
'''


class ModuleBuildRunnerTest(unittest.TestCase):
    def run_fixture(self, *, mode='--build-only', outside=False, symlink=False,
                    equal=False, relative=False):
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        source, output, temporary = root / 'source', root / 'output', root / 'tmp'
        (source / 'build').mkdir(parents=True); output.mkdir(); temporary.mkdir()
        (source / 'build/envsetup.sh').write_text(ENVSETUP)
        product = output / 'target/product/fixture'
        if outside: product = root / 'outside/product'
        if equal: product = output
        if symlink:
            external = root / 'outside/product'; external.mkdir(parents=True)
            product.parent.mkdir(parents=True); product.symlink_to(external, target_is_directory=True)
        else: product.mkdir(parents=True, exist_ok=True)
        (product / 'fixture.jar').write_bytes(b'temporary fixture artifact')
        artifact = root / 'artifacts'
        query = os.path.relpath(product, source) if relative else str(product)
        env = dict(os.environ, AOSP_AGENT_SOURCE_ROOT=str(source), AOSP_AGENT_OUT_DIR=str(output),
            AOSP_AGENT_TMPDIR=str(temporary), AOSP_AGENT_LUNCH='fixture-userdebug',
            AOSP_AGENT_BUILD_LOCK=str(root / 'build.lock'), AOSP_AGENT_WORKTREE=str(source),
            AOSP_AGENT_ARTIFACT_DIR=str(artifact), AOSP_AGENT_EXPECTED_ARCH='x86_64',
            AOSP_AGENT_TRANSACTION_ACTIVE='1', AOSP_AGENT_BASELINE_ACTIVE='1',
            FIXTURE_PRODUCT_OUT=str(product), FIXTURE_QUERY_PRODUCT_OUT=query)
        result = subprocess.run(['bash', str(RUNNER), mode, 'fixture'], env=env,
                                capture_output=True, text=True, timeout=10)
        return result, artifact

    def test_lunch_out_override_keeps_original_boundary_and_collects_artifact(self):
        result, artifact = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('MODULE_BUILD_EXIT=0', result.stdout)
        self.assertEqual((artifact / 'fixture.jar').read_bytes(), b'temporary fixture artifact')

    def test_baseline_with_lunch_override_remains_successful_without_collection(self):
        result, artifact = self.run_fixture(mode='--baseline')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('MODULE_BUILD_EXIT=0', result.stdout)
        self.assertEqual(list(artifact.iterdir()), [])

    def test_relative_product_output_inside_configured_root_is_supported(self):
        result, artifact = self.run_fixture(relative=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((artifact / 'fixture.jar').is_file())

    def test_real_escape_and_symlink_escape_are_still_rejected(self):
        for kwargs in ({'outside': True}, {'symlink': True}):
            with self.subTest(kwargs=kwargs):
                result, artifact = self.run_fixture(**kwargs)
                self.assertEqual(result.returncode, 125)
                self.assertIn('product output escapes controlled output view', result.stderr)
                self.assertEqual(list(artifact.iterdir()), [])

    def test_product_output_equal_to_configured_root_is_still_rejected(self):
        result, artifact = self.run_fixture(equal=True)
        self.assertEqual(result.returncode, 125)
        self.assertIn('product output escapes controlled output view', result.stderr)
        self.assertEqual(list(artifact.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
