"""Runtime behavior claims need target implementation provenance.

These are benign source/orchestration fixtures, not a standard-library oracle
or an Android vulnerability evaluation.
"""
import copy
from dataclasses import replace
import unittest

from aosp_agent.engine import AssessmentError
from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.mapped_impact import check_impact_proofs
from aosp_agent.platform_evidence import definition_present, receipt
from aosp_agent.prompts import IMPACT_SCHEMA, parse_impact_response
from aosp_agent.scope_evidence import check_scope
from jsonschema import validate, ValidationError
from engine_fixtures import GitFixture, git, ScriptedRuntime
import test_agent as core_tests
import test_mapped_impact as mapped_tests
from test_scope_evidence import closure_for


IMPLEMENTATION = '''package java.io;
public class File {
    private String path;
    public File(String parent, String child) { path = parent + "/" + child; }
}
'''
CALLER = '''class Caller {
    Object make() { return new java.io.File("parent", "child"); }
}
'''


def entry(path, content, **extra):
    return dict(revision='target', path=path, line_start=1, line_end=len(content.splitlines()),
                excerpt=content.rstrip(), claim='Benign source provenance fixture.', **extra)


def add_platform(proof, prefix='', unit_id=None):
    extra = {'unit_id': unit_id} if unit_id else {}
    proof['evidence'] += [entry(prefix + 'Caller.java', CALLER, **extra),
                          entry(prefix + 'File.java', IMPLEMENTATION, **extra)]
    call, impl = len(proof['evidence']) - 1, len(proof['evidence'])
    proof['causal_chain']['target_harm_evidence'].append(call)
    proof['causal_chain']['platform_semantics'] = [dict(api='java.io.File',
        behavior='The fixture constructor combines the two strings.',
        relied_at_evidence=[call], implementation_evidence=[impl])]
    return call, impl


def add_sources(fx):
    (fx.repo / 'Caller.java').write_text(CALLER)
    (fx.repo / 'File.java').write_text(IMPLEMENTATION)
    git(fx.repo, 'add', 'Caller.java', 'File.java')
    git(fx.repo, 'commit', '-q', '-m', 'add benign API provenance fixtures')
    fx.target = git(fx.repo, 'rev-parse', 'HEAD')


def map_platform_dependencies(raw):
    """Use ordinary read-only mapping and closure, without an evidence bypass."""
    proof = raw['proof_groups'][0]['impact']
    row = raw['units'][0]
    for symbol, evidence in zip(('make', 'File'), proof['evidence'][-2:]):
        row['targets'].append(dict(path=evidence['path'], symbol=symbol,
            line_start=evidence['line_start'], line_end=evidence['line_end'],
            action='read_dependency', relationship='dependency', reason='Read-only behavior evidence'))
        row['evidence'].append({**{k: v for k, v in evidence.items() if k not in ('revision', 'unit_id')},
                                'origin': 'target'})
    raw['scope_closure'] = closure_for(raw)


class PlatformEvidenceTest(unittest.TestCase):
    def test_real_target_blobs_required_and_record_is_not_semantic_proof(self):
        with GitFixture() as fx:
            add_sources(fx)
            owner = core_tests.AgentTest(); agent = owner.agent(fx)
            owner._with_counter_hunk(agent)
            raw = fx.assessment(); add_platform(raw)
            validate(raw, IMPACT_SCHEMA)
            result = agent._ground_assessment(raw)
            audit = agent.record['platform_behavior_evidence']
            self.assertEqual(audit['status'], 'SOURCE_GROUNDED')
            self.assertFalse(audit['semantic_correctness_proven'])
            self.assertFalse(audit['runtime_dispatch_proven'])
            self.assertEqual(result['status'], 'AFFECTED')
            raw['evidence'][-1]['excerpt'] = IMPLEMENTATION.replace('parent +', '"fabricated" +')
            with self.assertRaisesRegex(AssessmentError, 'excerpt does not exist'):
                agent._ground_assessment(raw)

    def test_no_implementation_cannot_promote_false_platform_claim(self):
        with GitFixture() as fx:
            owner = core_tests.AgentTest(); agent = owner.agent(fx); owner._with_counter_hunk(agent)
            raw = fx.assessment(); add_platform(raw)
            item = raw['causal_chain']['platform_semantics'][0]
            item['behavior'] = 'Automatically grants authorization to every caller.'
            item.pop('implementation_evidence')
            with self.assertRaises(ValidationError): validate(raw, IMPACT_SCHEMA)
            with self.assertRaises(ValueError): parse_impact_response(raw)
            with self.assertRaisesRegex(AssessmentError, 'implementation_evidence'):
                agent._validate_impact_causality(raw)

    def test_target_revision_callsite_separation_and_definition_are_required(self):
        with GitFixture() as fx:
            owner = core_tests.AgentTest(); agent = owner.agent(fx); owner._with_counter_hunk(agent)
            base = fx.assessment(); call, impl = add_platform(base)
            for mode in ('source_version', 'same_site', 'only_call', 'wrong_api', 'comment', 'prototype', 'invalid_index'):
                with self.subTest(mode=mode):
                    raw = copy.deepcopy(base); item = raw['causal_chain']['platform_semantics'][0]
                    e = raw['evidence'][impl - 1]
                    if mode == 'source_version': e['revision'] = 'source_fix'
                    elif mode == 'same_site': item['implementation_evidence'] = [call]
                    elif mode == 'only_call': e['excerpt'] = CALLER
                    elif mode == 'wrong_api': e['excerpt'] = IMPLEMENTATION.replace('package java.io;', 'package fixture;')
                    elif mode == 'comment': e['excerpt'] = '// ' + IMPLEMENTATION.replace('\n', '\n// ')
                    elif mode == 'prototype': e['excerpt'] = 'package java.io; abstract class File { abstract void open(); }'
                    else: item['implementation_evidence'] = [999]
                    with self.assertRaises(AssessmentError): agent._validate_impact_causality(raw)

    def test_supported_definitions_and_unsupported_forms_are_explicit(self):
        cases = [
            ('java.io.File', 'File.java', IMPLEMENTATION, True),
            ('java.io.File', 'File.java', 'package java.io; class File { File() {} }', False),
            ('java.io.File', 'File.java', 'package other; class File { File() { run(); } }', False),
            ('kotlin.io.Reader.read', 'Reader.kt', 'package kotlin.io\nclass Reader {\n fun read(): Int { return 1 }\n}\n', True),
            ('strlen', 'strlen.c', 'unsigned strlen(const char *s) { unsigned n=0; while(s[n]) n++; return n; }', True),
            ('strlen', 'strlen.c', 'unsigned strlen(const char *s);', False),
            ('strlen', 'strlen.c', 'static unsigned strlen(const char *s) { return 0; }', False),
            ('java.io.File', 'File.java', 'package java.io; class File { void unrelated() { return; } }', False),
            ('strlen', 'strlen.cpp', 'class Other { unsigned strlen(const char *s) { return 0; } };', False),
            ('strlen', 'strlen.S', 'strlen:\n ret', False),
        ]
        for api, path, content, expected in cases:
            with self.subTest(api=api, path=path, content=content):
                self.assertEqual(definition_present(api, entry(path, content)), expected)

    def test_library_under_analysis_can_supply_actual_implementation(self):
        with GitFixture() as fx:
            owner = core_tests.AgentTest(); agent = owner.agent(fx); owner._with_counter_hunk(agent)
            agent.case = replace(agent.case, repository='libcore')
            raw = fx.assessment(); add_platform(raw)
            agent._validate_impact_causality(raw)

    def test_mapped_read_dependency_does_not_expand_edit_targets(self):
        with GitFixture() as fx:
            add_sources(fx)
            controller, raw = mapped_tests.MappedImpactTest().setup_proofs(fx)
            group = raw['proof_groups'][0]; ident = group['unit_ids'][0]
            call, impl = add_platform(group['impact'], 'repo/', ident)
            map_platform_dependencies(raw)
            targets_before = copy.deepcopy(raw['units'][0]['targets'])
            grounded = controller.ground(raw)
            self.assertEqual(check_scope(controller, grounded, required=True)['status'], 'GROUNDED_MODEL_SCOPE')
            self.assertNotIn('repo/File.java', grounded['writable_paths'])
            result = check_impact_proofs(controller, grounded, required=True)
            self.assertEqual(raw['units'][0]['targets'], targets_before)
            self.assertEqual(result['groups'][0]['platform_behavior_evidence']['status'], 'SOURCE_GROUNDED')
            group['impact']['evidence'][impl - 1]['path'] = 'unadmitted/File.java'
            with self.assertRaisesRegex(AssessmentError, 'supplied repository'):
                check_impact_proofs(controller, raw, required=True)

    def test_mapped_implementation_cannot_substitute_causal_role_or_other_unit(self):
        with GitFixture() as fx:
            add_sources(fx)
            controller, base = mapped_tests.MappedImpactTest().setup_proofs(fx)
            group = base['proof_groups'][0]; ident = group['unit_ids'][0]
            call, impl = add_platform(group['impact'], 'repo/', ident)
            map_platform_dependencies(base)
            for mode in ('role', 'other_unit'):
                raw = copy.deepcopy(base); proof = raw['proof_groups'][0]['impact']
                if mode == 'role': proof['causal_chain']['target_fault_evidence'] = [impl]
                else: proof['evidence'][impl - 1]['unit_id'] = raw['proof_groups'][1]['unit_ids'][0]
                with self.subTest(mode=mode), self.assertRaises(AssessmentError):
                    check_impact_proofs(controller, raw, required=True)

    def test_empty_platform_use_has_no_verified_semantic_claim(self):
        self.assertEqual(receipt({})['status'], 'NOT_USED')
        self.assertFalse(receipt({})['semantic_correctness_proven'])

    def test_cross_repository_dependency_uses_pinned_version_and_stays_read_only(self):
        with GitFixture() as fx:
            add_sources(fx)
            old, raw = mapped_tests.MappedImpactTest().setup_proofs(fx)
            library = fx.source_root / 'libcore'; library.mkdir()
            git(library, 'init', '-q'); (library / 'File.java').write_text(IMPLEMENTATION)
            git(library, 'add', '.'); git(library, 'commit', '-q', '-m', 'pinned library fixture')
            pinned = git(library, 'rev-parse', 'HEAD')
            (library / 'File.java').write_text('package unrelated; class Different {}\n')
            git(library, 'add', '.'); git(library, 'commit', '-q', '-m', 'different checkout fixture')
            checkout = git(library, 'rev-parse', 'HEAD')
            controller = DiffBackportAgent(old.patch_bytes, fx.source_root, fx.run_root,
                task_id='cross-repository-platform', repository_keys=['repo', 'libcore'],
                pinned_heads={'repo': fx.target, 'libcore': pinned}, lazy_reads=True)
            controller.units = copy.deepcopy(old.units); controller.mapper.units = controller.units
            group = raw['proof_groups'][0]; ident = group['unit_ids'][0]
            call, impl = add_platform(group['impact'], 'repo/', ident)
            group['impact']['evidence'][impl - 1]['path'] = 'libcore/File.java'
            map_platform_dependencies(raw)
            grounded = controller.ground(raw)
            self.assertEqual(check_scope(controller, grounded, required=True)['status'], 'GROUNDED_MODEL_SCOPE')
            self.assertNotIn('libcore/File.java', grounded['writable_paths'])
            result = check_impact_proofs(controller, grounded, required=True)
            self.assertEqual(result['groups'][0]['platform_behavior_evidence']['status'], 'SOURCE_GROUNDED')
            self.assertFalse(any(t['path'].startswith('libcore/') and t['action'] == 'edit'
                                 for u in raw['units'] for t in u['targets']))
            self.assertEqual(git(library, 'rev-parse', 'HEAD'), checkout)
            self.assertEqual(git(library, 'status', '--porcelain'), '')
            group['impact']['evidence'][impl - 1]['excerpt'] = (library / 'File.java').read_text().strip()
            group['impact']['evidence'][impl - 1]['line_end'] = 1
            with self.assertRaises(AssessmentError): check_impact_proofs(controller, raw, required=True)

    def test_unresolved_claim_gets_correction_and_can_end_unknown(self):
        with GitFixture() as fx:
            # Valid JSON/shape, real grounded target text, but the purported
            # implementation comes from the donor fix. Evidence correction
            # must be possible without changing malformed-JSON retry behavior.
            bad = fx.assessment()
            bad['causal_chain']['platform_semantics'] = [dict(api='java.lang.normalize_count',
                behavior='A model assertion about the counter.',
                relied_at_evidence=[1], implementation_evidence=[3])]
            class CorrectedRuntime(ScriptedRuntime):
                def run(self, *args, **kwargs):
                    if self.calls:
                        self.assessment = fx.assessment('UNKNOWN')
                    return super().run(*args, **kwargs)
            runtime = CorrectedRuntime(bad)
            agent = core_tests.AgentTest().agent(fx, runtime)
            result = agent.run(impact_only=True, max_attempts=2)
            self.assertEqual(result['status'], 'UNKNOWN')
            self.assertEqual(len(runtime.calls), 2)
            self.assertIn('implementation_evidence', runtime.calls[-1]['prompt'])
