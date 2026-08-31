import importlib.util
import json
import unittest
from copy import deepcopy
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = PROJECT_ROOT / "scripts" / "validate_firmware_support_registry.py"
REGISTRY_PATH = PROJECT_ROOT / "docs" / "release" / "firmware-support-registry.json"

spec = importlib.util.spec_from_file_location("firmware_registry_validator", VALIDATOR_PATH)
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)


def registry():
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


class FirmwareSupportRegistryTests(unittest.TestCase):
    def test_canonical_registry_passes_semantic_gate(self):
        self.assertEqual(validator.validate_registry(registry()), [])

    def test_rejects_missing_released_model(self):
        value = registry()
        value["models"].pop("s21-pro")
        errors = validator.validate_registry(value)
        self.assertTrue(any("settled 13-model contract" in error for error in errors))

    def test_rejects_status_conflation(self):
        value = registry()
        value["models"]["s19"]["availability"] = "UNRELEASED"
        errors = validator.validate_registry(value)
        self.assertIn("s19: availability must be RELEASED", errors)

    def test_rejects_invented_artifact(self):
        value = registry()
        invented = deepcopy(value["artifact_ledger"]["artifacts"]["s9-xil-sysupgrade"])
        invented["model_key"] = "s21-pro"
        invented["filename"] = "invented-s21-pro.tar"
        value["artifact_ledger"]["artifacts"]["invented"] = invented
        value["models"]["s21-pro"]["artifact_ids"] = ["invented"]
        value["models"]["s21-pro"]["artifact_status"] = "VERIFIED_PREBUILT"
        errors = validator.validate_registry(value)
        self.assertTrue(any("exactly the three verified public files" in error for error in errors))

    def test_rejects_outer_signature_claim(self):
        value = registry()
        value["artifact_ledger"]["artifacts"]["s9-xil-sysupgrade"]["outer_detached_signature"] = "VERIFIED"
        errors = validator.validate_registry(value)
        self.assertTrue(any("no outer detached signature" in error for error in errors))

    def test_rejects_release_provenance_drift(self):
        value = registry()
        value["artifact_ledger"]["github_release_commit"] = "0" * 40
        errors = validator.validate_registry(value)
        self.assertTrue(any("immutable release provenance drifted" in error for error in errors))

    def test_rejects_invented_authored_release_notes(self):
        value = registry()
        value["artifact_ledger"]["github_release_notes_status"] = "PUBLISHED"
        errors = validator.validate_registry(value)
        self.assertTrue(any("immutable release provenance drifted" in error for error in errors))

    def test_rejects_public_release_history_count_drift(self):
        value = registry()
        value["artifact_ledger"]["github_public_release_count_at_review"] = 2
        errors = validator.validate_registry(value)
        self.assertTrue(any("immutable release provenance drifted" in error for error in errors))

    def test_rejects_missing_localized_model(self):
        value = registry()
        value["localizations"]["fr-CA"]["models"].pop("s21-pro")
        errors = validator.validate_registry(value)
        self.assertTrue(
            any("localizations.fr-CA.models keys/order" in error for error in errors)
        )

    def test_rejects_localized_status_override(self):
        value = registry()
        value["localizations"]["fr-CA"]["models"]["s21-pro"]["availability"] = "PUBLIÉ"
        errors = validator.validate_registry(value)
        self.assertTrue(
            any(
                "localized availability or maturity overrides are forbidden" in error
                for error in errors
            )
        )


if __name__ == "__main__":
    unittest.main()
