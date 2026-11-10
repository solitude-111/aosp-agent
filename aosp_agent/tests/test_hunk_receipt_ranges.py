"""Strict interpretation of the persisted source-read range protocol."""
from types import SimpleNamespace
import unittest

from aosp_agent.engine import AospBackportAgent


class HunkReceiptRangesTest(unittest.TestCase):
    def setUp(self):
        self.agent = object.__new__(AospBackportAgent)
        self.agent.location_handoff = object()
        self.agent.mapping_repository = 'repo'
        self.agent.mapping_plan = SimpleNamespace(targets=lambda key, unit_id: [
            {'path': 'Support.java', 'line_start': 10, 'line_end': 12}]
            if key == 'repo' and unit_id == 'support' else [])
        self.record = {'cmd': 'view-code', 'returncode': 0,
            'args': {'repo': 'target', 'path': 'Support.java', 'start': '10', 'end': '12'}}
        self.hunk = {'id': 'support'}

    def supports(self, **changes):
        return self.agent._tool_supports_hunk(
            {**self.record, 'args': {**self.record['args'], **changes}}, self.hunk)

    def test_canonical_decimal_and_native_int_ranges_are_compatible(self):
        for start, end in (('10', '12'), (10, 12), ('9', 10), (12, '13')):
            with self.subTest(start=start, end=end):
                self.assertTrue(self.supports(start=start, end=end))

    def test_invalid_reversed_or_unrelated_receipts_remain_rejected(self):
        for value in (True, False, 1.0, None, 0, -1, '', '0', '01', '+10', '-10',
                      ' 10', '10 ', '1e1', '10.0', 'ten', '１'):
            with self.subTest(value=str(value)[:30]):
                self.assertFalse(self.supports(start=value))
                self.assertFalse(self.supports(end=value))
        for fields in ({'start': '12', 'end': '10'}, {'start': '1', 'end': '9'},
                       {'start': '13', 'end': '20'}, {'repo': 'target:other'},
                       {'repo': 'donor'}, {'path': 'Other.java'}):
            with self.subTest(fields=fields):
                self.assertFalse(self.supports(**fields))
        for fields in ({'rejected': True}, {'read_status': 'READ_FAILED'},
                       {'read_status': 'PATH_ABSENT'}, {'cmd': 'show-commit'}):
            self.assertFalse(self.agent._tool_supports_hunk({**self.record, **fields}, self.hunk))


if __name__ == '__main__':
    unittest.main()
