import errno
import json
from pathlib import Path
import tempfile
import unittest

from aosp_agent.failure_policy import classify_failure, terminal_retry_allowed
from aosp_agent.output_budget import (create_budget, write_bytes, write_json, OutputBudgetExceeded,
                                      CaseOutputBudgetExceeded)
from aosp_agent.sdk_runtime import _error_kind


class BatchFailurePolicyTest(unittest.TestCase):
    def test_terminal_retry_is_bounded_and_only_for_observed_transient_error(self):
        timeout = {'status': 'INCONCLUSIVE', 'completion_blocked_by': 'MODEL_TIMEOUT'}
        self.assertTrue(terminal_retry_allowed(timeout))
        self.assertFalse(terminal_retry_allowed({**timeout, 'terminal_retry_count': 1}))
        self.assertFalse(terminal_retry_allowed(timeout, 0))
        self.assertFalse(terminal_retry_allowed({'status': 'INCONCLUSIVE',
            'completion_blocked_by': 'CASE_BUDGET_EXHAUSTED'}))
        self.assertFalse(terminal_retry_allowed({'status': 'FAILED', 'error': {'kind': 'QUOTA_EXHAUSTED'}}))
        self.assertFalse(terminal_retry_allowed({'status': 'PATCH_UNVERIFIED',
            'completion_blocked_by': 'MODEL_TIMEOUT'}))

    def test_provider_balance_and_storage_pause_but_source_quotes_do_not(self):
        self.assertEqual(_error_kind('HTTP 402 Payment Required: Insufficient Balance'), 'QUOTA_EXHAUSTED')
        self.assertEqual(classify_failure({'repository_errors': {'repo': {
            'kind': 'QUOTA_EXHAUSTED', 'message': 'provider failed'}}})['action'], 'PAUSE_BATCH')
        self.assertEqual(classify_failure(OSError(errno.ENOSPC, 'No space left on device'))['scope'], 'shared')
        self.assertEqual(classify_failure({'assessment': {'message': 'Insufficient Balance'}})['scope'], 'case')

    def test_case_output_limit_does_not_spend_sibling_or_reset_batch_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = create_budget(root, 1024 * 1024)
            one = root / 'row-0001'; one.mkdir()
            child = create_budget(one, 128 * 1024, independent=True)
            with self.assertRaises(CaseOutputBudgetExceeded):
                write_bytes(one / 'large', b'x' * (128 * 1024))
            record = {'status': 'RUNNING'}
            self.assertTrue(write_json(one / 'run.json', record, control=True))
            self.assertEqual(record['completion_blocked_by'], 'CASE_OUTPUT_BUDGET_EXHAUSTED')
            self.assertEqual(classify_failure(record)['scope'], 'case')
            self.assertFalse(parent.data()['exhausted'])
            two = root / 'row-0002'; two.mkdir()
            sibling = create_budget(two, 128 * 1024, independent=True)
            write_bytes(two / 'small', b'y' * 1024)
            self.assertEqual(sibling.data()['normal_reserved'], 1024)
            self.assertGreaterEqual(parent.data()['normal_reserved'] + parent.data()['control_reserved'], 1024)

    def test_shared_output_limit_stops_all_children_and_can_save_compact_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = create_budget(root, 128 * 1024)
            row = root / 'row'; row.mkdir()
            create_budget(row, 1024 * 1024, independent=True)
            with self.assertRaises(OutputBudgetExceeded):
                write_bytes(row / 'large', b'x' * (128 * 1024))
            record = {'status': 'RUNNING', 'payload': 'old'}
            self.assertTrue(write_json(row / 'run.json', record, control=True))
            self.assertEqual(record['completion_blocked_by'], 'OUTPUT_BUDGET_EXHAUSTED')
            self.assertEqual(classify_failure(record)['scope'], 'shared')
            with self.assertRaises(OutputBudgetExceeded):
                parent.check()
