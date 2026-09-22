import json
import unittest
from pathlib import Path

from aosp_agent.case import Case, load_cases
from aosp_agent.prompts import backport_prompt, impact_prompt, parse_impact_response


class ContractTest(unittest.TestCase):
    def case_data(self):
        return {"cve": "CVE-2099-1", "project": "AOSP", "repository": "frameworks/base",
                "source_commit": "a" * 40, "source_parent": "b" * 40,
                "target_commit": "c" * 40, "files": ["src/Example.java"], "validation": []}

    def test_legacy_answers_cannot_enter_prompts(self):
        raw = self.case_data()
        raw.update(impact="SECRET_REFERENCE_IMPACT", migration="SECRET_REFERENCE_MIGRATION",
                   poc="SECRET_REFERENCE_POC")
        case = Case.from_dict(raw)
        self.assertEqual((case.impact, case.migration, case.poc), ("", "", ""))
        for prompt in (impact_prompt(case), backport_prompt(case)):
            self.assertNotIn("SECRET_REFERENCE", prompt)
        # Direct construction with old arguments must not reintroduce answer leakage either.
        direct = Case(**{**raw, "files": tuple(raw["files"]), "validation": ()})
        self.assertNotIn("SECRET_REFERENCE", impact_prompt(direct) + backport_prompt(direct))

    def test_runtime_dataset_is_separate_from_references(self):
        root = Path(__file__).resolve().parents[1] / "dataset"
        cases = load_cases(root / "cases")
        self.assertGreaterEqual(len(cases), 3)
        oracle_names = {path.stem for path in (root / "oracles").glob("*.json")}
        for path in (root / "cases").glob("*.json"):
            self.assertFalse({"impact", "migration", "poc"}.intersection(json.loads(path.read_text())))
            # Oracles are optional offline evaluation fixtures; runtime cases may
            # be added without leaking a reference answer into the input set.
            if path.stem in oracle_names:
                self.assertTrue((root / "oracles" / path.name).is_file())

    def test_repository_and_file_paths_are_bounded(self):
        for path in ("../other", "/tmp/other", "a/../b", "a//b", ".git/config",
                     "a/.git/config", "a\\b", "a\nfile", "a/*", "a/."):
            for field in ("repository", "files"):
                raw = self.case_data()
                raw[field] = [path] if field == "files" else path
                with self.subTest(field=field, path=path), self.assertRaises(ValueError):
                    Case.from_dict(raw)

    def test_absolute_shell_command_is_rejected(self):
        raw = self.case_data()
        raw["validation"] = [["/bin/bash", "script.sh"]]
        with self.assertRaises(ValueError):
            Case.from_dict(raw)

    def test_structured_impact_requires_target_evidence(self):
        raw = {"status": "AFFECTED", "evidence": [], "reasoning": "The target lacks the guard.",
               "limitations": ["Runtime reachability is unverified."]}
        with self.assertRaises(ValueError):
            parse_impact_response(json.dumps(raw))
        raw["status"] = "UNKNOWN"
        self.assertEqual(parse_impact_response(json.dumps(raw))["status"], "UNKNOWN")
        raw["status"] = "AFFECTED"
        raw["evidence"] = [{"revision": "target", "path": "src/Example.java", "line_start": 1,
                            "line_end": 1, "excerpt": "class Example {}", "claim": "No guard here."}]
        self.assertEqual(parse_impact_response(json.dumps(raw)), raw)
        raw["status"] = "ALREADY_FIXED"
        self.assertEqual(parse_impact_response(json.dumps(raw))["status"], "ALREADY_FIXED")
        raw["evidence"][0]["line_start"] = True
        with self.assertRaises(ValueError):
            parse_impact_response(json.dumps(raw))

    def test_staged_validation_is_normalized(self):
        raw = self.case_data()
        raw["validation"] = {"checks": [{"stage": "source_extracted_jvm",
                                           "argv": ["python3", "verify.py"],
                                           "artifacts": ["out/result.txt"]}]}
        case = Case.from_dict(raw)
        self.assertEqual(case.validation, (("python3", "verify.py"),))
        self.assertEqual(case.validation_checks[0]["stage"], "source_extracted_jvm")

    def test_run_record_extends_incrementally_without_renaming(self):
        from aosp_agent.engine import AospBackportAgent
        from aosp_agent.tests.engine_fixtures import GitFixture, ScriptedRuntime, write_counter, FIXED
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(FIXED)])
            result = AospBackportAgent(
                fixture.source_root, fixture.run_root, fixture.case(validation=True),
                runtime_factory=runtime.factory).run(verify=True)
            self.assertEqual(result["status"], "VALIDATED")
            # Legacy fields keep their names and meaning...
            for key in ("cve", "status", "backend", "model", "events", "impact_decision",
                        "patch_sha256", "final_verification", "original_checkout"):
                self.assertIn(key, result)
            # ...and the RetroPatch-port fields are additive (plan red line 6).
            self.assertTrue(result["commit_message"].strip())
            migration = result["mechanical_migration"]
            for key in ("hunks", "applied", "failed", "skipped", "starting_state"):
                self.assertIn(key, migration)
            attempts = result["attempts"]
            self.assertEqual(attempts[0]["strategy"], "verify_and_complete")
            for entry in attempts:
                self.assertIn("index", entry)
                self.assertIn("turn_id", entry)
                self.assertIn("patch_sha256", entry)
            claims = result["hunk_results"]
            self.assertEqual(claims[0]["id"], "f001-h001")
            self.assertIn(claims[0]["status"], ("implemented", "need_not_ported"))
            self.assertEqual(result["verification_memory"]["passed_stages"],
                             ["configured"])


if __name__ == "__main__":
    unittest.main()
