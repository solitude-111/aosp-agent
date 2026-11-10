"""Use a real tiny Ninja graph and benign compiler input, without AOSP or models."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from aosp_agent.build_graph import collect_ninja_coverage, ninja_log_checkpoint, _source_in_command


@unittest.skipUnless(shutil.which('ninja') and shutil.which('clang'), 'requires local Ninja and clang')
class BuildGraphTest(unittest.TestCase):
    def test_source_and_compiler_must_belong_to_the_same_action(self):
        root = Path('/fixture/source'); out = Path('/fixture/out')
        for command in ('echo clang repo/main.c', 'clang unrelated.c; echo repo/main.c',
                        'clang unrelated.c && echo repo/main.c'):
            self.assertFalse(_source_in_command(command, 'repo/main.c', root, out)[0], command)
        self.assertTrue(_source_in_command('PWD=/proc/self/cwd /tools/clang -c repo/main.c -o obj.o',
                                          'repo/main.c', root, out)[0])

    @unittest.skipUnless(shutil.which('bison'), 'requires local bison for a real generated-source action')
    def test_generated_source_chain_and_scheduled_owner_are_distinct_from_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source = root / 'source'; output = root / 'out'
            (source / 'repo').mkdir(parents=True); output.mkdir()
            (source / 'repo/parser.y').write_text('%{\nint yylex(void); void yyerror(const char*);\n%}\n%%\nstart: ;\n%%\n')
            generated = output / 'soong/.intermediates/repo/demo/android_x86_64/gen/parser.c'
            artifact = generated.parent.parent / 'obj/parser.o'
            generated.parent.mkdir(parents=True); artifact.parent.mkdir(parents=True)
            graph = output / 'build.ninja'
            graph.write_text('builddir = ' + str(output) + '\nrule gen\n  command = ' + shutil.which('bison')
                + ' -o $out $in\nrule cc\n  command = ' + shutil.which('clang') + ' -c $in -o $out\nbuild '
                + str(generated) + ': gen repo/parser.y\nbuild ' + str(artifact) + ': cc ' + str(generated) + '\n')
            config = {'ninja': shutil.which('ninja'), 'output_root': str(output),
                      'environment': {'PATH': os.defpath}, 'graph_timeout': 10}
            identity = {'environment_id': 'e'*64, 'source_root': str(source)}
            receipt = {'environment_id': identity['environment_id'], 'validation_id': 'generated', 'returncode': 0}
            planned = collect_ninja_coverage(identity, config, graph, ['repo/parser.y'], root / 'receipt',
                build_receipt=receipt, require_executed=False, for_discovery=True)
            self.assertEqual(planned['uncovered'], [])
            self.assertEqual(planned['purpose'], 'scheduled_owner_discovery')
            self.assertFalse(planned['files'][0]['actions'][0]['compile_credit'])
            before = ninja_log_checkpoint(output / '.ninja_log')
            subprocess.run([config['ninja'], '-f', str(graph), str(artifact)], cwd=source,
                           check=True, capture_output=True)
            built = collect_ninja_coverage(identity, config, graph, ['repo/parser.y'], root / 'receipt',
                build_receipt={**receipt, 'validation_id': 'generated-built'}, before_log=before)
            action = built['files'][0]['actions'][0]
            self.assertTrue(action['compile_credit'])
            self.assertTrue(action['generators'][0]['executed_in_this_validation'])
            self.assertEqual(action['module'], 'demo')

    def test_actual_action_is_required_and_old_artifacts_do_not_verify_a_new_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source = root / 'source'; output = root / 'out'
            (source / 'repo').mkdir(parents=True); output.mkdir()
            (source / 'repo/main.c').write_text('int example(void) { return 7; }\n')
            artifact = output / 'soong/.intermediates/repo/demo/android_x86_64/obj/main.o'
            artifact.parent.mkdir(parents=True)
            graph = output / 'build.ninja'
            graph.write_text('builddir = ' + str(output) + '\nrule cc\n  command = '
                + shutil.which('clang') + ' -c $in -o $out\nbuild ' + str(artifact) + ': cc repo/main.c\n')
            config = {'ninja': shutil.which('ninja'), 'output_root': str(output),
                      'environment': {'PATH': os.defpath}, 'graph_timeout': 10}
            identity = {'environment_id': 'e' * 64, 'source_root': str(source)}
            before = ninja_log_checkpoint(output / '.ninja_log')
            subprocess.run([config['ninja'], '-f', str(graph), str(artifact)], cwd=source,
                           check=True, capture_output=True)
            receipt = {'environment_id': identity['environment_id'], 'validation_id': 'fixture1',
                       'returncode': 0, 'patch_sha256': 'p' * 64}
            found = collect_ninja_coverage(identity, config, graph, ['repo/main.c'], root / 'receipt',
                                           build_receipt=receipt, before_log=before)
            self.assertEqual(found['uncovered'], [])
            self.assertEqual(found['files'][0]['actions'][0]['module'], 'demo')
            self.assertTrue(found['files'][0]['actions'][0]['executed_in_this_validation'])
            self.assertEqual(found['coverage'], 'partial')
            after = ninja_log_checkpoint(output / '.ninja_log')
            stale = collect_ninja_coverage(identity, config, graph, ['repo/main.c'], root / 'receipt',
                                           build_receipt={**receipt, 'validation_id': 'fixture2'}, before_log=after)
            self.assertEqual(stale['uncovered'], ['repo/main.c'])
            wrong = collect_ninja_coverage(identity, config, graph, ['repo/main.c'], root / 'receipt',
                build_receipt={**receipt, 'environment_id': 'other'}, before_log=before)
            self.assertEqual(wrong['status'], 'GRAPH_UNAVAILABLE')

    def test_module_info_or_noncompiler_dependency_cannot_claim_source_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source = root / 'source'; output = root / 'out'
            (source / 'repo').mkdir(parents=True); output.mkdir()
            (source / 'repo/main.c').write_text('int example(void) { return 7; }\n')
            artifact = output / 'soong/.intermediates/repo/demo/android_common/main.txt'
            artifact.parent.mkdir(parents=True)
            graph = output / 'build.ninja'
            graph.write_text('builddir = ' + str(output) + '\nrule copy\n  command = cp $in $out\nbuild '
                             + str(artifact) + ': copy repo/main.c\n')
            (output / 'module-info.json').write_text('{"demo":{"path":["repo"]}}')
            before = ninja_log_checkpoint(output / '.ninja_log')
            subprocess.run([shutil.which('ninja'), '-f', str(graph), str(artifact)], cwd=source,
                           check=True, capture_output=True)
            found = collect_ninja_coverage({'environment_id': 'e'*64, 'source_root': str(source)},
                {'ninja': shutil.which('ninja'), 'output_root': str(output), 'environment': {'PATH': os.defpath},
                 'graph_timeout': 10}, graph, ['repo/main.c'], root / 'receipt', before_log=before,
                build_receipt={'environment_id': 'e'*64, 'validation_id': 'fixture', 'returncode': 0})
            self.assertEqual(found['uncovered'], ['repo/main.c'])


if __name__ == '__main__':
    unittest.main()
