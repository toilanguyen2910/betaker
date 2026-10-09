"""Tier 5 Adversarial SAST Probe Test Suite (Pytest Adapter).

Integrates all 38 empirical probes from tests/adversarial_probe_m1_1.py into pytest.
"""

import pytest
import tests.adversarial_probe_m1_1 as _probe_mod

# Prevent pytest from attempting to collect helper class as a test class
_probe_mod.TestResult.__test__ = False


def _collect_all_probes():
    return (
        _probe_mod.test_sqli_adversarial_suite()
        + _probe_mod.test_cmdi_adversarial_suite()
        + _probe_mod.test_path_traversal_adversarial_suite()
        + _probe_mod.test_secrets_adversarial_suite()
        + _probe_mod.test_deserialization_adversarial_suite()
        + _probe_mod.test_corner_cases_suite()
        + _probe_mod.test_line_and_snippet_accuracy()
        + _probe_mod.test_robustness_and_boundary_suite()
    )


ALL_PROBES = _collect_all_probes()


@pytest.mark.parametrize("probe", ALL_PROBES, ids=[f"{p.category}::{p.name}" for p in ALL_PROBES])
def test_adversarial_sast_probe(probe):
    """Executes an adversarial SAST probe and verifies that it passes."""
    assert probe.passed, f"[{probe.category}] {probe.name} FAILED: {probe.details}"
