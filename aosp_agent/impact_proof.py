"""Shared impact proof rules used by both donor and mapped multi-source paths.

Callers must ground exact evidence bytes before invoking these rules. Structural
proof obligations do not establish formal semantic or runtime security proof.
"""
from __future__ import annotations

import re
from typing import Any

from .patches import text_hunks

_PLATFORM_API_PREFIXES = (
    "java.", "javax.", "sun.", "libcore.", "kotlin.", "kotlinx.",
    "org.json.", "org.w3c.dom.", "org.w3c.sax.", "org.xml.", "org.ietf.",
)

_PLATFORM_FQCN_RE = re.compile(
    r"(?:java|javax|sun|libcore|kotlin|kotlinx|org\.json|org\.w3c\.dom|"
    r"org\.w3c\.sax|org\.xml|org\.ietf)\.[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

_LIBC_SYMBOLS = frozenset({
    "memcpy", "memmove", "memset", "memcmp", "strlen", "strcpy", "strncpy",
    "strncmp", "strcmp", "strchr", "strrchr", "strstr", "strtol", "strtoul",
    "atoi", "atol", "snprintf", "sprintf", "printf", "fprintf", "malloc",
    "calloc", "realloc", "free", "open", "close", "read", "write", "lseek",
    "fopen", "fclose", "fread", "fwrite", "exit", "abort", "getenv",
    "qsort", "bsearch",
})

def _is_platform_semantic_api(api: str) -> bool:
    """Syntactic category only, not API existence or behavioral verification."""
    from .platform_evidence import api_identity
    identity = api_identity(api)
    name = identity['name'] if identity else ''
    return bool(_PLATFORM_FQCN_RE.fullmatch(name)) or name in _LIBC_SYMBOLS

def _is_repo_implemented_platform_api(api: str, repository_roots: set[str]) -> bool:
    """True when a repository under analysis implements the api itself.

    libcore implements the Java platform namespaces and bionic the libc
    symbols; for those repositories the semantics live inside the audited
    code, are citable as evidence, and may be exactly what the donor fix
    changes — they must not be asserted from memory.
    """
    name = (api or "").strip()
    return (("libcore" in repository_roots and name.startswith(_PLATFORM_API_PREFIXES))
            or ("bionic" in repository_roots and name in _LIBC_SYMBOLS))

class AssessmentError(ValueError):
    """The model's assessment could not be grounded in immutable Git blobs."""

    kind = "ASSESSMENT_INVALID"


def evidence_error(message, index, field=None):
    """Preserve the actual rejected entry instead of inferring it from prose."""
    error = AssessmentError(message)
    error.diagnostic = {'category': 'EVIDENCE_UNGROUNDED',
        'path': f'/evidence/{index}' + ('/' + field if field else ''), 'message': message[:1200]}
    return error


def assessment_diagnostic(error, raw=None, *, wrapped=False):
    """Typed, field-addressed feedback for the existing local repair protocol."""
    from .sdk_runtime import report_diagnostic
    if getattr(error, 'validator', None):
        return report_diagnostic(error)
    if getattr(error, 'diagnostic', None):
        result = dict(error.diagnostic)
    else:
        text = str(error)
        result = {'category': 'EVIDENCE_UNGROUNDED' if isinstance(error, AssessmentError)
                  else 'REPORT_SCHEMA', 'path': '/', 'message': text[:1200]}
        impact = raw.get('impact', raw) if isinstance(raw, dict) else {}
        for field in ('causal_chain', 'scope_contract', 'proof_steps'):
            if field in text:
                result['path'] = '/' + field
                break
        else:
            if any(isinstance(entry, dict) and entry.get('path') and entry['path'] in text
                   for entry in impact.get('evidence', [])):
                # Compatibility errors without a typed location cannot identify
                # an array entry by filename: the same file/revision can recur.
                result['path'] = '/evidence'
    if wrapped and result['path'] != '/':
        result['path'] = '/impact' + result['path']
    return result


def _api_error(message, index, category, field='api'):
    error = AssessmentError(message)
    error.diagnostic = {'category': category,
                        'path': f'/causal_chain/platform_semantics/{index}/{field}',
                        'message': message}
    return error

PROOF_STEP_REQUIREMENTS = {
    "authorization_boundary": (
        "caller_controlled_input", "authority_boundary_missing",
        "sensitive_sink", "downstream_harm",
    ),
    "persistent_state_pollution": (
        "state_write", "shared_namespace", "reuse_or_inheritance",
        "consumer_role_confusion", "downstream_harm",
    ),
    "resource_bound": (
        "unbounded_input", "fix_scoped_representation", "resource_consuming_sink",
        "equivalent_bound_absent", "downstream_harm",
    ),
    "generic_data_flow": ("donor_fault", "target_fault", "downstream_harm"),
}


class CausalityChecks:
    @staticmethod
    def _evidence_matches_hunk(evidence, hunk):
        if evidence.get('unit_id') is not None and evidence['unit_id'] != hunk.get('id'):
            return False
        side = 'old_path' if evidence['revision'] == 'source_parent' else 'new_path'
        return hunk.get(side, hunk.get('path')) == evidence['path']

    @staticmethod
    def _changed_hunk_lines(hunk: dict[str, Any], revision: str) -> set[int]:
        """Return causal line numbers in a donor hunk for parent or fix.

        A pure addition has no parent-side changed lines and a pure deletion has
        no fix-side changed lines.  In those cases the hunk's adjacent context
        is the only available anchor for the unchanged side of the fix site.
        Context is never accepted when changed lines exist on that side.
        """
        changed: set[int] = set()
        context: set[int] = set()
        if revision not in ('source_parent', 'source_fix'):
            raise ValueError('donor delta requires source_parent or source_fix')
        side, marker = ('old_line', '-') if revision == 'source_parent' else ('new_line', '+')
        for part in text_hunks(hunk.get('patch', '')):
            for line in part['lines']:
                if line['marker'] == marker:
                    changed.add(line[side])
                elif line['marker'] == ' ':
                    context.add(line[side])
        return changed or context
    @staticmethod
    def _is_executable_evidence(evidence: dict[str, Any]) -> bool:
        text = evidence["excerpt"]
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        lines = []
        for line in text.splitlines():
            line = line.split("//", 1)[0].split("#", 1)[0].strip()
            if line:
                lines.append(line)
        if not lines:
            return False
        non_executable_prefixes = ("package ", "import ", "include ", "from ", "@")
        return any(not line.startswith(non_executable_prefixes) for line in lines)
    def _evidence_overlaps_donor_delta(self, evidence: dict[str, Any]) -> bool:
        if evidence["revision"] not in ("source_parent", "source_fix"):
            return False
        for hunk in self._current_hunks:
            if not self._evidence_matches_hunk(evidence, hunk):
                continue
            changed_lines = self._changed_hunk_lines(hunk, evidence["revision"])
            if any(evidence["line_start"] <= line <= evidence["line_end"]
                   for line in changed_lines):
                return True
        return False
    def _validate_impact_causality(self, assessment: dict[str, Any]) -> None:
        """Reject conclusions not tied to a fix-defined scope and proof contract."""
        status = assessment["status"]
        scope = assessment["scope_contract"]
        pattern = scope["vulnerability_pattern"]
        if scope["representation_change"] == "no_counterpart" and status == "AFFECTED":
            raise AssessmentError("AFFECTED cannot use scope_contract.representation_change=no_counterpart")
        if assessment["root_cause"]["category"] == "denial_of_service" and pattern != "resource_bound":
            raise AssessmentError("denial_of_service assessments must use the resource_bound proof pattern")
        if assessment["root_cause"]["category"] == "permission_bypass" and pattern != "authorization_boundary":
            raise AssessmentError("permission_bypass assessments must use the authorization_boundary proof pattern")

        steps = assessment["proof_steps"]
        step_ids = [step["id"] for step in steps]
        if len(step_ids) != len(set(step_ids)):
            raise AssessmentError("impact proof_steps ids must be unique")
        by_id = {step["id"]: step for step in steps}
        required = set(PROOF_STEP_REQUIREMENTS[pattern])
        if scope["representation_change"] == "equivalent_representation":
            required.add("representation_equivalence")
        missing = sorted(required - set(by_id))
        if missing:
            raise AssessmentError(f"impact proof_steps is missing required ids: {', '.join(missing)}")

        for step in steps:
            if step["resolved"] and not step["evidence"]:
                raise AssessmentError(f"resolved impact proof step {step['id']} requires evidence")
            if any(type(index) is not int or not 1 <= index <= len(assessment["evidence"])
                   for index in step["evidence"]):
                raise AssessmentError(f"impact proof step {step['id']} contains an invalid evidence index")

        if status == "UNKNOWN":
            unresolved = [step for step in steps if not step["resolved"]]
            if not unresolved:
                raise AssessmentError("UNKNOWN impact requires at least one unresolved material proof step")
        else:
            unresolved = [step for step in steps if not step["resolved"]]
            if unresolved:
                raise AssessmentError("determinate impact cannot have unresolved proof steps: "
                                      + ", ".join(step["id"] for step in unresolved))

        if status in ("NOT_AFFECTED", "ALREADY_FIXED"):
            clearing_ids = {"counterpart_absence", "equivalent_protection"}
            if scope["representation_change"] == "equivalent_representation":
                clearing_ids.add("representation_out_of_scope")
            clearing = [step for step in steps if step["id"] in clearing_ids and step["resolved"]]
            if not clearing:
                raise AssessmentError(f"{status} impact requires resolved counterpart_absence, "
                                      "equivalent_protection, or representation_out_of_scope evidence")
            if not any(assessment["evidence"][index - 1]["revision"] == "target"
                       for step in clearing for index in step["evidence"]):
                raise AssessmentError(f"{status} impact clearing proof must cite target evidence")
            if status == "ALREADY_FIXED" and not any(step["id"] == "equivalent_protection" for step in clearing):
                raise AssessmentError("ALREADY_FIXED impact requires equivalent_protection proof")

        if status == "AFFECTED":
            target_proof_ids = tuple(step_id for step_id in PROOF_STEP_REQUIREMENTS[pattern]
                                     if step_id != "donor_fault")
            for step_id in target_proof_ids:
                indices = by_id[step_id]["evidence"]
                wrong_revision = [i for i in indices if assessment["evidence"][i - 1]["revision"] != "target"]
                if not indices or wrong_revision:
                    raise AssessmentError(f"AFFECTED proof step {step_id} requires target-only evidence "
                                          f"(non-target indices: {wrong_revision})")
                non_executable = [i for i in indices if not self._is_executable_evidence(assessment["evidence"][i - 1])]
                if non_executable:
                    raise AssessmentError(f"AFFECTED proof step {step_id} must cite executable target statements "
                                          f"(non-executable indices: {non_executable})")
            if scope["representation_change"] == "equivalent_representation":
                indices = by_id["representation_equivalence"]["evidence"]
                entries = [assessment["evidence"][i - 1] for i in indices]
                non_executable = [i for i, entry in zip(indices, entries) if not self._is_executable_evidence(entry)]
                revisions = {entry["revision"] for entry in entries}
                issues = []
                if non_executable:
                    issues.append(f"must cite executable donor and target statements (non-executable indices: {non_executable})")
                if not any(self._evidence_overlaps_donor_delta(entry) for entry in entries):
                    issues.append("donor evidence must overlap the donor fix delta")
                if not revisions & {"source_parent", "source_fix"} or "target" not in revisions:
                    issues.append("must compare donor and target evidence")
                if issues:
                    raise AssessmentError("representation_equivalence " + ", ".join(issues))

        causal = assessment.get("causal_chain")
        if status != "AFFECTED":
            if causal is not None:
                raise AssessmentError("causal_chain is only valid for AFFECTED assessments")
            return
        if not isinstance(causal, dict):
            raise AssessmentError("AFFECTED assessment requires causal_chain")

        evidence = assessment["evidence"]
        roles = {
            "donor_fault_evidence": "source_parent",
            "donor_fix_evidence": "source_fix",
            "target_fault_evidence": "target",
            "target_harm_evidence": "target",
        }
        selected: dict[str, list[dict[str, Any]]] = {}
        for field, expected_revision in roles.items():
            indices = causal.get(field, [])
            if (not isinstance(indices, list) or not indices
                    or any(type(index) is not int or not 1 <= index <= len(evidence) for index in indices)):
                raise AssessmentError(f"causal_chain {field} contains an invalid evidence index")
            entries = [evidence[index - 1] for index in indices]
            if any(entry["revision"] != expected_revision for entry in entries):
                raise AssessmentError(f"causal_chain {field} requires {expected_revision} evidence")
            selected[field] = entries

        for field, revision in (("donor_fault_evidence", "source_parent"),
                                ("donor_fix_evidence", "source_fix")):
            grounded = False
            for entry in selected[field]:
                for hunk in self._current_hunks:
                    if not self._evidence_matches_hunk(entry, hunk):
                        continue
                    changed_lines = self._changed_hunk_lines(hunk, revision)
                    if any(entry["line_start"] <= line <= entry["line_end"] for line in changed_lines):
                        grounded = True
                        break
                if grounded:
                    break
            if not grounded:
                raise AssessmentError(
                    f"causal_chain {field} must overlap the donor fix's changed lines")

        for field in ("target_fault_evidence", "target_harm_evidence"):
            if not all(self._is_executable_evidence(entry) for entry in selected[field]):
                raise AssessmentError(f"causal_chain {field} must cite executable target statements")

        assumptions = causal.get("external_behavior_assumptions", [])
        if assumptions:
            raise AssessmentError(
                "AFFECTED cannot rest on uncited repository/framework behavior: "
                "causal_chain.external_behavior_assumptions must be empty. Put already "
                "grounded facts in the causal explanation and reference their source evidence. "
                "For any material unverified behavior, cite its implementation or keep the impact UNKNOWN. "
                "Use ordinary evidence for android.* and com.android.* behavior; reserve "
                "platform_semantics for recognized standard-library APIs with target implementations.")
        repository = getattr(getattr(self, "case", None), "repository", "") or ""
        repository_roots = getattr(self, '_causality_repository_roots', {repository.split("/", 1)[0]} - {""})
        causal_anchor_indices = (set(causal.get("target_fault_evidence") or [])
                                 | set(causal.get("target_harm_evidence") or []))
        for item_index, item in enumerate(causal.get("platform_semantics") or []):
            api = str(item.get("api", ""))
            if not _is_platform_semantic_api(api):
                raise _api_error(
                    f"platform_semantics entry {api!r} is not a standard-library/platform "
                    "API identity. Use one qualified class constructor or method, optionally "
                    "with an exact parameter-type signature. Repository-defined behavior requires "
                    "ordinary pinned-source evidence and causal references; do not delete the "
                    "claim or put it in external_behavior_assumptions to retain AFFECTED. "
                    "A material unresolved behavior requires UNKNOWN.", item_index,
                    'API_REPRESENTATION' if api.startswith(_PLATFORM_API_PREFIXES) else 'API_CLASSIFICATION')
            if _is_repo_implemented_platform_api(api, repository_roots) and not item.get('implementation_evidence'):
                raise AssessmentError(
                    f"platform_semantics entry {api!r} is implemented by the repository "
                    "under analysis; cite its behavior as evidence instead of asserting "
                    "it from memory")
            indices = item.get("relied_at_evidence") or []
            if (not indices or any(type(index) is not int
                                   or not 1 <= index <= len(evidence) for index in indices)):
                raise AssessmentError(
                    "platform_semantics relied_at_evidence must cite valid 1-based "
                    "evidence indices")
            if any(evidence[index - 1]["revision"] != "target" for index in indices):
                raise AssessmentError(
                    "platform_semantics must cite the target call site that relies on "
                    "the documented semantics")
            if not set(indices) <= causal_anchor_indices:
                raise AssessmentError(
                    "platform_semantics relied_at_evidence must anchor at the causal "
                    "chain's target_fault/target_harm evidence, not unrelated target code")
            if not all(self._is_executable_evidence(evidence[index - 1])
                       for index in indices):
                raise AssessmentError(
                    "platform_semantics must cite an executable target call site "
                    "(comments or declarations alone are not reliance)")
            from .platform_evidence import api_identity, signature_call_present
            simple_name = api_identity(api)['name'].rsplit('.', 1)[-1]
            if not any(re.search(rf"\b{re.escape(simple_name)}\b",
                                 evidence[index - 1]["excerpt"]) for index in indices):
                raise _api_error(
                    f"platform_semantics entry {api!r} must be cited at a target call "
                    "site whose excerpt mentions the API", item_index, 'EVIDENCE_MISSING', 'relied_at_evidence')
            if not any(signature_call_present(api, evidence[index - 1]) for index in indices):
                raise _api_error('The supplied API overload is not established by the target call. '
                                 'Preserve its signature; provide an explicit supported call binding '
                                 'or retain the unresolved premise, rather than dropping parameters.',
                                 item_index, 'EVIDENCE_MISSING', 'relied_at_evidence')
            implementation = item.get('implementation_evidence') or []
            if (not implementation or any(type(i) is not int or not 1 <= i <= len(evidence)
                                          for i in implementation)):
                raise AssessmentError('platform_semantics requires valid target implementation_evidence; '
                                      'an API name and call site do not verify behavior')
            from .platform_evidence import definition_present
            causal_sites = set(causal.get('target_fault_evidence', [])) | set(causal.get('target_harm_evidence', []))
            if set(implementation) & causal_sites:
                raise AssessmentError('platform implementation must not replace mapped causal call-site evidence')
            for index in implementation:
                entry = evidence[index - 1]
                if entry['revision'] != 'target':
                    raise AssessmentError('platform implementation evidence must use the pinned target version')
                if any(entry['path'] == evidence[i - 1]['path']
                       and entry['line_start'] <= evidence[i - 1]['line_end']
                       and evidence[i - 1]['line_start'] <= entry['line_end'] for i in indices):
                    raise AssessmentError('platform implementation evidence must be separate from the relying call site')
                if any(entry.get('unit_id') != evidence[i - 1].get('unit_id') for i in indices):
                    raise AssessmentError('platform implementation evidence must belong to the relying source unit')
                if not definition_present(api, entry):
                    raise _api_error('platform implementation evidence must contain the named API definition '
                                     'and executable body, matching every supplied parameter type; '
                                     'unsupported or different overloads remain unresolved', item_index,
                                     'EVIDENCE_MISSING', 'implementation_evidence')
