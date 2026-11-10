"""Local report corrections preserve claims and retain immutable-source gates."""
import copy
import json
import unittest

from aosp_agent.assessment_repair import apply_repair, digest, REPAIR_SCHEMA
from aosp_agent.engine import AospBackportAgent, AssessmentError
from aosp_agent.execution_budget import ACTIVE_EXECUTION, ExecutionBudget
from aosp_agent.platform_evidence import definition_present, signature_call_present
from aosp_agent.prompts import IMPACT_SCHEMA
from engine_fixtures import GitFixture, ScriptedRuntime


class ReportRuntime(ScriptedRuntime):
    def __init__(self, outputs):
        super().__init__(outputs[0])
        self.outputs = outputs

    def run(self, prompt, read_only, output_schema=None):
        self.calls.append({'prompt': prompt, 'schema': output_schema})
        response = self.outputs[len(self.calls) - 1]
        return {'status': 'completed', 'final_response': json.dumps(response),
                'output': copy.deepcopy(response)}


class BackendReportRepairTest(unittest.TestCase):
    def test_misplaced_field_moves_without_dropping_claim(self):
        with GitFixture() as fx:
            original = fx.assessment()
            broken = copy.deepcopy(original)
            broken['misplaced_causal_chain'] = broken.pop('causal_chain')
            correction = {'base_sha256': digest(broken), 'replacements': [],
                          'moves': [{'from': '/misplaced_causal_chain', 'path': '/causal_chain'}]}
            self.assertEqual(apply_repair(broken, correction, schema=IMPACT_SCHEMA), original)
            self.assertIn('misplaced_causal_chain', broken)
            runtime = ReportRuntime([broken, correction])
            agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case(), runtime_factory=runtime.factory)
            result = agent.run(impact_only=True, max_attempts=2)
            self.assertEqual(result['status'], 'AFFECTED')
            self.assertEqual(runtime.calls[1]['schema'], REPAIR_SCHEMA)
            self.assertTrue((agent.run_dir / 'impact-repair-2.json').exists())
            self.assertEqual(result['impact_report_rejections'][0]['diagnostic']['category'], 'REPORT_SCHEMA')

    def test_moves_cannot_discard_required_fields_or_overwrite_evidence(self):
        with GitFixture() as fx:
            raw = fx.assessment()
            for source, destination in (('/evidence', '/unused'),
                                        ('/evidence/0', '/causal_chain'),
                                        ('/causal_chain', '/reasoning')):
                correction = {'base_sha256': digest(raw), 'replacements': [],
                              'moves': [{'from': source, 'path': destination}]}
                before = copy.deepcopy(raw)
                with self.assertRaises(AssessmentError):
                    apply_repair(raw, correction, schema=IMPACT_SCHEMA)
                self.assertEqual(raw, before)

    def test_local_shape_fix_cannot_pass_fabricated_source(self):
        with GitFixture() as fx:
            raw = fx.assessment()
            raw['evidence'][0]['excerpt'] = 'invented source'
            correction = {'base_sha256': digest(raw), 'replacements': [
                {'path': '/reasoning', 'value_json': json.dumps('Changed wording, same unsupported proof.')} ]}
            runtime = ReportRuntime([raw, correction])
            agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case(), runtime_factory=runtime.factory)
            ledger = ExecutionBudget(fx.root / 'ledger', 'fixture', limits={'report_corrections': 3})
            token = ACTIVE_EXECUTION.set(ledger)
            try:
                with self.assertRaisesRegex(AssessmentError, 'excerpt does not exist'):
                    agent.run(impact_only=True, max_attempts=6)
            finally:
                ACTIVE_EXECUTION.reset(token)
            self.assertEqual(len(runtime.calls), 2)
            saved = json.loads(ledger.path.read_text())
            self.assertEqual(saved['consumed']['report_corrections'], 1)
            self.assertNotIn('candidate_turns', saved['consumed'])

    def test_retiring_a_causal_claim_cannot_keep_an_affected_verdict(self):
        with GitFixture() as fx:
            raw = fx.assessment()
            correction = {'base_sha256': digest(raw), 'replacements': [], 'retire_causal_claim': True}
            with self.assertRaisesRegex(AssessmentError, 'UNKNOWN'):
                apply_repair(raw, correction, schema=IMPACT_SCHEMA)
            correction['replacements'] = [{'path': '/status', 'value_json': '"UNKNOWN"'}]
            with self.assertRaisesRegex(AssessmentError, 'unresolved proof step'):
                apply_repair(raw, correction, schema=IMPACT_SCHEMA)

    def test_explicit_constructor_signature_is_not_erased(self):
        source = 'package java.io; class File { File(String p, String c) { use(p,c); } }'
        entry = {'path': 'File.java', 'excerpt': source}
        self.assertTrue(definition_present('java.io.File(String,String)', entry))
        self.assertFalse(definition_present('java.io.File(String,int)', entry))
        self.assertFalse(definition_present('java.io.File(String)', entry))
        caller = {'path': 'Caller.java', 'excerpt':
                  'class Caller { Object make() { return new java.io.File("p", "c"); } }'}
        self.assertTrue(signature_call_present('java.io.File(String,String)', caller))
        self.assertFalse(signature_call_present('java.io.File(String,int)', caller))
        caller['excerpt'] = 'class Caller { Object make(Object a) { return new java.io.File(a,a); } }'
        self.assertFalse(signature_call_present('java.io.File(String,String)', caller))
        caller['excerpt'] = 'class Caller { Object make() { return new other.File("p","c"); } }'
        self.assertFalse(signature_call_present('java.io.File(String,String)', caller))


if __name__ == '__main__':
    unittest.main()
