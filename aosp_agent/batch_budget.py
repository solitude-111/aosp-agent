"""Small durable limits shared by a serial batch and every resumption."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil
import time

from .lifecycle import RecoveryBlocked
from .preparation import write_receipt


class BatchBudgetExceeded(RecoveryBlocked):
    limit_scope = 'batch'

    def __init__(self, kind):
        super().__init__('shared batch limit exhausted: ' + kind)
        self.kind = kind


class BatchBudget:
    DEFAULTS = {'max_model_calls': 1000, 'max_seconds': 86400,
                'max_output_bytes': 1024**3, 'min_free_bytes': 2 * 1024**3}

    def __init__(self, root, *, limits=None, output_root=None, existing=False):
        self.root = Path(root).resolve()
        if existing and not (self.root / 'batch-resource-budget.json').is_file():
            raise RecoveryBlocked('saved shared batch budget is missing; resumption cannot reset consumption')
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / 'batch-resource-budget.json'
        self.limits = {**self.DEFAULTS, **(limits or {})}
        if set(self.limits) != set(self.DEFAULTS) or any(type(v) is not int or v <= 0 for v in self.limits.values()):
            raise ValueError('invalid shared batch limits')
        with self._locked() as state:
            if not state:
                if existing: raise RecoveryBlocked('saved shared batch budget is empty')
                state.update(version=1, limits=self.limits, started_at=time.time(), model_calls=0, output_roots=[])
            elif state.get('version') != 1 or state['limits'] != self.limits:
                raise RecoveryBlocked('shared batch budget policy changed')
            if output_root and str(Path(output_root).resolve()) not in state['output_roots']:
                state['output_roots'].append(str(Path(output_root).resolve()))
            self._save(state)

    @contextmanager
    def _locked(self):
        fd = os.open(self.root / 'batch-resource-budget.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if self.path.is_symlink(): raise RecoveryBlocked('shared batch checkpoint cannot be a symlink')
            state = json.loads(self.path.read_text()) if self.path.exists() else {}
            yield state
        except RecoveryBlocked:
            raise
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RecoveryBlocked('shared batch accounting is unavailable') from exc
        finally:
            os.close(fd)

    def _save(self, state):
        write_receipt(self.path, state)

    def remaining_seconds(self):
        with self._locked() as state:
            remaining = state['limits']['max_seconds'] - max(0, time.time() - state['started_at'])
        if remaining <= 0: raise BatchBudgetExceeded('BATCH_TIME_BUDGET_EXHAUSTED')
        return remaining

    def admit_model(self):
        self.check()
        with self._locked() as state:
            if state['model_calls'] >= state['limits']['max_model_calls']:
                raise BatchBudgetExceeded('BATCH_MODEL_BUDGET_EXHAUSTED')
            state['model_calls'] += 1  # Persist before launching; failed admission is not refunded.
            self._save(state)

    def check(self):
        self.remaining_seconds()
        if shutil.disk_usage(self.root).free < self.limits['min_free_bytes']:
            raise BatchBudgetExceeded('DISK_SPACE_LOW')
        with self._locked() as state:
            roots = [Path(p) for p in state['output_roots']]
        # Sum managed payload counters, not working trees or build output. Child
        # budgets already debit their parent; count each top-level ledger once.
        from .output_budget import OutputBudget
        owners = {}
        for root in roots:
            state = OutputBudget(root).data()
            while state.get('parent_root'):
                root = Path(state['parent_root']); state = OutputBudget(root).data()
            owners[str(root)] = state
        size = 0
        for state in owners.values():
            size += state['normal_reserved'] + state['control_reserved']
        if size > self.limits['max_output_bytes']:
            raise BatchBudgetExceeded('BATCH_OUTPUT_BUDGET_EXHAUSTED')
        return size

    def snapshot(self):
        with self._locked() as state: return dict(state)
