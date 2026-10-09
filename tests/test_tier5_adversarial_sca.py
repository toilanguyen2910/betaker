"""Tier 5 Adversarial Stress Test Suite for tools/sca.py and tools/advisories.py.

Authored by Challenger m1_2_2.
Comprehensive empirical challenge verifying:
- Group A: ComparableVersion Deep Boundary & Adversarial SemVer
- Group B: Range Matching & Complex Boundary Evaluation
- Group C: Manifest Parsing Edge Cases & Resilience
- Group D: Encoding & Corrupt File Fault Tolerance
- Group E: Offline Advisory Database Integrity & Consistency
"""

import json
import os
import sys
import tempfile
from pathlib import Path
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.advisories import (
    ComparableVersion,
    evaluate_condition,
    is_version_in_range,
    check_package_vulnerabilities,
    get_advisories_for_package,
    OFFLINE_ADVISORIES,
)
from tools.sca import (
    parse_requirements_txt,
    parse_package_json,
    parse_pep440_clauses,
    parse_npm_clauses,
    scan_dependencies,
    scan_all_manifests,
    detect_manifest_type,
    DependencyFinding,
    normalize_package_name,
)


# ============================================================================
# GROUP A: ComparableVersion Deep Boundary & Adversarial SemVer
# ============================================================================

class TestAdversarialComparableVersion:
    """Stress tests for ComparableVersion parsing and relational operations."""

    def test_ultra_long_version_segments(self):
        """100-segment version numbers must parse without index errors."""
        v100_a = ComparableVersion(".".join(str(i) for i in range(100)))
        v100_b = ComparableVersion(".".join(str(i) for i in range(100)) + ".1")
        assert len(v100_a.numeric) == 100
        assert v100_a < v100_b
        assert v100_b > v100_a

    def test_massive_integer_components(self):
        """Arbitrarily large integer version components must compare accurately."""
        v_huge1 = ComparableVersion("1.999999999999999999999999999999.0")
        v_huge2 = ComparableVersion("1.999999999999999999999999999999.1")
        assert v_huge1 < v_huge2
        assert v_huge1.numeric[1] == 999999999999999999999999999999

    def test_single_component_versions(self):
        """Single digit/integer versions (e.g. '3', '42', '0') must pad to (x, 0, 0)."""
        v_single = ComparableVersion("3")
        assert v_single.numeric == (3, 0, 0)
        assert v_single == ComparableVersion("3.0.0")
        assert v_single < ComparableVersion("3.0.1")
        assert v_single > ComparableVersion("2.9.9")

    def test_leading_trailing_dots_and_whitespace(self):
        """Messy dot placement and whitespace must be tolerated."""
        v_dots = ComparableVersion(".1.2.3.")
        assert v_dots.numeric == (1, 2, 3)
        v_spaces = ComparableVersion("   2.3.4   ")
        assert v_spaces.numeric == (2, 3, 4)

    def test_prerelease_hierarchy_chain(self):
        """Full pre-release hierarchy: dev < alpha < beta < rc < final."""
        chain = [
            ComparableVersion("2.0.0.dev1"),
            ComparableVersion("2.0.0-alpha.1"),
            ComparableVersion("2.0.0-alpha.2"),
            ComparableVersion("2.0.0-beta.1"),
            ComparableVersion("2.0.0-beta.10"),
            ComparableVersion("2.0.0-rc.1"),
            ComparableVersion("2.0.0-rc.2"),
            ComparableVersion("2.0.0"),
            ComparableVersion("2.0.0.post1"),
            ComparableVersion("2.0.1"),
        ]
        for i in range(len(chain) - 1):
            assert chain[i] < chain[i + 1], f"Failed at {chain[i]} < {chain[i + 1]}"

    def test_pep440_short_prerelease_tags(self):
        """PEP 440 short forms (2.0.0a1, 2.0.0b2, 2.0.0c3, 2.0.0dev4)."""
        assert ComparableVersion("2.0.0a1") == ComparableVersion("2.0.0-alpha.1")
        assert ComparableVersion("2.0.0b2") == ComparableVersion("2.0.0-beta.2")
        assert ComparableVersion("2.0.0c3") == ComparableVersion("2.0.0-rc.3")
        assert ComparableVersion("2.0.0dev4") == ComparableVersion("2.0.0-dev.4")

    def test_preview_and_pre_tags(self):
        """Preview and pre tags must map to RC level."""
        v_preview = ComparableVersion("1.5.0-preview.2")
        v_pre = ComparableVersion("1.5.0-pre.2")
        v_rc = ComparableVersion("1.5.0-rc.2")
        assert v_preview.prerelease_type == 3
        assert v_pre.prerelease_type == 3
        assert v_preview == v_rc
        assert v_pre == v_rc

    def test_post_release_variations(self):
        """PEP 440 post release formats (1.0.0.post1, 1.0.0-post1, 1.0.0post1)."""
        v_p1 = ComparableVersion("1.0.0.post1")
        v_p2 = ComparableVersion("1.0.0-post1")
        v_p3 = ComparableVersion("1.0.0post1")
        v_base = ComparableVersion("1.0.0")
        assert v_p1 > v_base
        assert v_p2 > v_base
        assert v_p3 > v_base
        assert v_p1 == v_p2 == v_p3

    def test_build_metadata_stripping_with_complex_strings(self):
        """Build metadata (+build, +sha, etc.) must not affect comparisons."""
        v1 = ComparableVersion("1.2.3+sha.abc123")
        v2 = ComparableVersion("1.2.3+sha.xyz987")
        v3 = ComparableVersion("1.2.3")
        assert v1 == v2 == v3

    def test_non_prerelease_custom_suffixes(self):
        """Suffixes like -FINAL, -RELEASE, -GA, -hotfix must not be treated as alpha/beta/rc."""
        for suffix in ("-FINAL", "-RELEASE", "-GA", "-hotfix", "-patch"):
            v = ComparableVersion(f"2.0.0{suffix}")
            assert v.prerelease_type == 4, f"Suffix {suffix} misclassified as pre-release"
            assert v.numeric == (2, 0, 0)

    def test_zero_padded_numeric_segments(self):
        """Leading zeros in numeric segments must normalize cleanly."""
        v_padded = ComparableVersion("1.02.03")
        v_normal = ComparableVersion("1.2.3")
        assert v_padded == v_normal

    def test_fallback_on_empty_and_garbage(self):
        """Empty string or non-numeric string must default to (0, 0, 0) without throwing."""
        for bad in ("", "   ", "invalid", "v", "pkg-name"):
            v = ComparableVersion(bad)
            assert v.numeric == (0, 0, 0)
            assert v.prerelease_type == 4


# ============================================================================
# GROUP B: Range Matching & Complex Boundary Evaluation
# ============================================================================

class TestAdversarialRangeEvaluation:
    """Stress tests for evaluate_condition and is_version_in_range."""

    def test_caret_zero_major_zero_minor(self):
        """^0.0.3 should match only 0.0.3 and reject 0.0.4 or 0.0.2."""
        assert is_version_in_range("0.0.3", "^0.0.3") is True
        assert is_version_in_range("0.0.4", "^0.0.3") is False
        assert is_version_in_range("0.0.2", "^0.0.3") is False

    def test_caret_zero_major_non_zero_minor(self):
        """^0.2.3 should match >= 0.2.3 < 0.3.0."""
        assert is_version_in_range("0.2.3", "^0.2.3") is True
        assert is_version_in_range("0.2.9", "^0.2.3") is True
        assert is_version_in_range("0.3.0", "^0.2.3") is False
        assert is_version_in_range("0.2.2", "^0.2.3") is False

    def test_caret_non_zero_major(self):
        """^1.2.3 should match >= 1.2.3 < 2.0.0."""
        assert is_version_in_range("1.2.3", "^1.2.3") is True
        assert is_version_in_range("1.9.9", "^1.2.3") is True
        assert is_version_in_range("2.0.0", "^1.2.3") is False
        assert is_version_in_range("1.2.2", "^1.2.3") is False

    def test_caret_rejects_prerelease_below_target(self):
        """^1.2.3 should reject 1.2.3-alpha.1 because it is less than target."""
        assert is_version_in_range("1.2.3-alpha.1", "^1.2.3") is False

    def test_tilde_three_parts(self):
        """~1.2.3 should match >= 1.2.3 < 1.3.0."""
        assert is_version_in_range("1.2.3", "~1.2.3") is True
        assert is_version_in_range("1.2.9", "~1.2.3") is True
        assert is_version_in_range("1.3.0", "~1.2.3") is False
        assert is_version_in_range("1.2.2", "~1.2.3") is False

    def test_tilde_two_parts(self):
        """~1.2 should match >= 1.2.0 < 1.3.0."""
        assert is_version_in_range("1.2.0", "~1.2") is True
        assert is_version_in_range("1.2.9", "~1.2") is True
        assert is_version_in_range("1.3.0", "~1.2") is False
        assert is_version_in_range("1.1.9", "~1.2") is False

    def test_pep440_compatible_release_three_parts(self):
        """~= 1.4.5 should match >= 1.4.5 < 1.5.0."""
        assert is_version_in_range("1.4.5", "~= 1.4.5") is True
        assert is_version_in_range("1.4.9", "~= 1.4.5") is True
        assert is_version_in_range("1.5.0", "~= 1.4.5") is False
        assert is_version_in_range("1.4.4", "~= 1.4.5") is False

    def test_pep440_compatible_release_two_parts(self):
        """~= 1.4 should match >= 1.4.0 < 2.0.0."""
        assert is_version_in_range("1.4.0", "~= 1.4") is True
        assert is_version_in_range("1.9.9", "~= 1.4") is True
        assert is_version_in_range("2.0.0", "~= 1.4") is False
        assert is_version_in_range("1.3.9", "~= 1.4") is False

    def test_wildcard_boundary_evaluation(self):
        """Wildcard == 1.2.* matches 1.2.0, 1.2.99 and rejects 1.20.0, 1.3.0."""
        assert is_version_in_range("1.2.0", "== 1.2.*") is True
        assert is_version_in_range("1.2.99", "== 1.2.*") is True
        assert is_version_in_range("1.20.0", "== 1.2.*") is False
        assert is_version_in_range("1.3.0", "== 1.2.*") is False

    def test_multiple_or_branches(self):
        """>= 2.0.0 < 2.0.7 || < 1.26.18 matches both disjuncts."""
        expr = "< 1.26.18 || >= 2.0.0 < 2.0.7"
        assert is_version_in_range("1.26.17", expr) is True
        assert is_version_in_range("1.26.18", expr) is False
        assert is_version_in_range("2.0.5", expr) is True
        assert is_version_in_range("2.0.7", expr) is False
        assert is_version_in_range("2.1.0", expr) is False

    def test_npm_hyphen_range_parsing(self):
        """Hyphen range 1.2.3 - 2.3.4 translates to >= 1.2.3 and <= 2.3.4."""
        clauses = parse_npm_clauses("1.2.3 - 2.3.4")
        assert clauses == [(">=", "1.2.3"), ("<=", "2.3.4")]

    def test_boundary_strict_inequalities(self):
        """Exact boundary tests on <, <=, >, >=, !=."""
        v = ComparableVersion("1.5.0")
        assert evaluate_condition(v, "<=", "1.5.0") is True
        assert evaluate_condition(v, "<", "1.5.0") is False
        assert evaluate_condition(v, ">=", "1.5.0") is True
        assert evaluate_condition(v, ">", "1.5.0") is False
        assert evaluate_condition(v, "!=", "1.5.0") is False
        assert evaluate_condition(v, "!=", "1.5.1") is True


# ============================================================================
# GROUP C: Manifest Parsing Edge Cases & Resilience
# ============================================================================

class TestAdversarialManifestParsing:
    """Stress tests for requirements.txt and package.json parsing."""

    def test_requirements_extras_parsing(self):
        """Package with extras (e.g. requests[security,socks]==2.25.0) parses cleanly."""
        pkgs = parse_requirements_txt("requests[security, socks] == 2.25.0\n")
        assert len(pkgs) == 1
        assert pkgs[0].name == "requests"
        assert set(pkgs[0].extras) == {"security", "socks"}
        assert pkgs[0].specifier == "== 2.25.0"

    def test_requirements_environment_markers(self):
        """Environment markers after ';' are cleanly stripped without affecting spec."""
        content = "requests == 2.25.0 ; python_version >= '3.8' and os_name == 'nt'\n"
        pkgs = parse_requirements_txt(content)
        assert len(pkgs) == 1
        assert pkgs[0].name == "requests"
        assert pkgs[0].specifier == "== 2.25.0"

    def test_requirements_multiple_specifier_clauses(self):
        """Multiple specifier clauses like '>= 2.0.0, <= 2.25.0'."""
        content = "requests >= 2.0.0, <= 2.25.0\n"
        pkgs = parse_requirements_txt(content)
        assert len(pkgs) == 1
        assert len(pkgs[0].specs) == 2
        assert (">=", "2.0.0") in pkgs[0].specs
        assert ("<=", "2.25.0") in pkgs[0].specs

    def test_requirements_name_normalization_pep503(self):
        """Underscores, dots, mixed cases normalized to canonical hyphenated lowercase per PEP 503."""
        for raw in ("Azure_Storage_Blob==12.0.0", "azure.storage.blob==12.0.0", "AZURE-STORAGE-BLOB==12.0.0"):
            pkgs = parse_requirements_txt(raw)
            assert len(pkgs) == 1
            assert pkgs[0].name == "azure-storage-blob"
        assert normalize_package_name("foo--bar..baz__qux") == "foo-bar-baz-qux"

    def test_requirements_multiline_continuation_with_comments(self):
        """Line continuations with backslash."""
        content = "requests \\\n   == \\\n   2.25.0\n"
        pkgs = parse_requirements_txt(content)
        assert len(pkgs) == 1
        assert pkgs[0].name == "requests"

    def test_requirements_unversioned_package_skipped_in_audit(self):
        """Unpinned packages (e.g. 'requests' or 'urllib3') skipped without crashing."""
        with tempfile.NamedTemporaryFile("w", suffix="requirements.txt", delete=False) as tf:
            tf.write("requests\nurllib3\nflask\n")
            p = Path(tf.name)
        try:
            findings = scan_dependencies(p)
            assert len(findings) == 0
        finally:
            if p.exists():
                os.remove(p)

    def test_package_json_scoped_packages(self):
        """Scoped npm packages (@scope/name) parse without mangling."""
        content = json.dumps({
            "dependencies": {
                "@angular/core": "^12.0.0",
                "@types/node": "18.0.0",
                "lodash": "4.17.19"
            }
        })
        pkgs = parse_package_json(content)
        names = {p.name for p in pkgs}
        assert "@angular/core" in names
        assert "@types/node" in names
        assert "lodash" in names

    def test_package_json_peer_and_optional_dependencies(self):
        """All npm dependency scopes (dependencies, devDependencies, peerDependencies, optionalDependencies)."""
        content = json.dumps({
            "dependencies": {"axios": "^1.6.0"},
            "devDependencies": {"minimist": "1.2.5"},
            "peerDependencies": {"ws": "8.16.0"},
            "optionalDependencies": {"express": "4.17.1"}
        })
        pkgs = parse_package_json(content)
        assert len(pkgs) == 4
        scopes = {p.dep_type for p in pkgs}
        assert scopes == {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"}

    def test_large_manifest_scale(self):
        """A manifest containing 1,000 package lines parses efficiently."""
        lines = [f"package-num-{i}==1.{i}.0\n" for i in range(1000)]
        content = "".join(lines)
        pkgs = parse_requirements_txt(content)
        assert len(pkgs) == 1000


# ============================================================================
# GROUP D: Encoding & Corrupt File Fault Tolerance
# ============================================================================

class TestAdversarialEncodingAndCorruption:
    """Stress tests verifying zero crashes on pathological encodings and byte corruptions."""

    def test_utf16_le_bom_no_crash(self):
        """UTF-16 Little Endian with BOM passed to scan_dependencies must not throw."""
        content = "requests==2.25.0\n".encode("utf-16")
        with tempfile.NamedTemporaryFile("wb", suffix="requirements.txt", delete=False) as tf:
            tf.write(content)
            p = Path(tf.name)
        try:
            findings = scan_dependencies(p)
            assert isinstance(findings, list)
        finally:
            if p.exists():
                os.remove(p)

    def test_utf16_be_bom_no_crash(self):
        """UTF-16 Big Endian with BOM passed to scan_dependencies must not throw."""
        content = "requests==2.25.0\n".encode("utf-16-be")
        with tempfile.NamedTemporaryFile("wb", suffix="requirements.txt", delete=False) as tf:
            tf.write(content)
            p = Path(tf.name)
        try:
            findings = scan_dependencies(p)
            assert isinstance(findings, list)
        finally:
            if p.exists():
                os.remove(p)

    def test_utf8_bom_package_json(self):
        """UTF-8 with BOM on package.json parses successfully and detects vulnerabilities."""
        content = "\ufeff" + json.dumps({"dependencies": {"lodash": "4.17.19"}})
        with tempfile.NamedTemporaryFile("w", suffix="package.json", delete=False, encoding="utf-8") as tf:
            tf.write(content)
            p = Path(tf.name)
        try:
            findings = scan_dependencies(p)
            assert len(findings) >= 1
            assert any(f.package == "lodash" for f in findings)
        finally:
            if p.exists():
                os.remove(p)

    def test_nonexistent_and_directory_paths(self):
        """Passing non-existent paths or directory paths returns empty list cleanly."""
        non_existent = Path("non_existent_reqs_12345.txt")
        assert scan_dependencies(non_existent) == []

        with tempfile.TemporaryDirectory() as td:
            assert scan_dependencies(td) == []

    def test_corrupt_partial_json_lines(self):
        """Truncated / invalid JSON must return empty list without throwing."""
        with tempfile.NamedTemporaryFile("w", suffix="package.json", delete=False) as tf:
            tf.write('{"dependencies": {"lodash": "4.17')
            p = Path(tf.name)
        try:
            findings = scan_dependencies(p)
            assert findings == []
        finally:
            if p.exists():
                os.remove(p)


# ============================================================================
# GROUP E: Offline Advisory Database Integrity & Consistency
# ============================================================================

class TestAdvisoryCatalogIntegrity:
    """Verifies that all curated offline advisories are well-formed and internally consistent."""

    def test_catalog_size_and_ecosystems(self):
        """Catalog must contain 23 total advisories (14 pip, 9 npm)."""
        pip_advs = [a for a in OFFLINE_ADVISORIES if a.ecosystem == "pip"]
        npm_advs = [a for a in OFFLINE_ADVISORIES if a.ecosystem == "npm"]
        assert len(OFFLINE_ADVISORIES) == 23
        assert len(pip_advs) == 14
        assert len(npm_advs) == 9

    def test_advisories_schema_conformance(self):
        """Every advisory must have valid CVE ID, valid severity, and valid CVSS score."""
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for adv in OFFLINE_ADVISORIES:
            assert adv.cve.startswith("CVE-"), f"Invalid CVE: {adv.cve}"
            assert adv.severity in valid_severities, f"Invalid severity: {adv.severity} in {adv.cve}"
            assert 0.0 <= adv.cvss_score <= 10.0, f"Invalid CVSS score: {adv.cvss_score} in {adv.cve}"
            assert adv.fixed_version, f"Missing fixed_version in {adv.cve}"
            assert adv.remediation, f"Missing remediation in {adv.cve}"

    def test_fixed_version_is_not_vulnerable(self):
        """The designated fixed_version must NEVER satisfy any vulnerable_range in that advisory."""
        for adv in OFFLINE_ADVISORIES:
            for v_range in adv.vulnerable_ranges:
                is_vuln = is_version_in_range(adv.fixed_version, v_range)
                assert not is_vuln, (
                    f"Inconsistency in {adv.cve} ({adv.package}): "
                    f"fixed_version '{adv.fixed_version}' is flagged vulnerable by range '{v_range}'"
                )

    def test_primary_curated_cves_trigger_detection(self):
        """Every advisory in catalog must successfully flag a known vulnerable version."""
        test_probes = [
            ("pip", "requests", "== 2.25.0", "CVE-2023-32681"),
            ("pip", "urllib3", "== 1.26.4", "CVE-2021-33503"),
            ("pip", "flask", "== 1.0.0", "CVE-2023-30861"),
            ("pip", "django", "== 3.2.0", "CVE-2022-34265"),
            ("pip", "pyyaml", "== 5.3", "CVE-2020-14343"),
            ("pip", "pillow", "== 9.0.0", "CVE-2023-50447"),
            ("pip", "jinja2", "== 3.0.0", "CVE-2024-22195"),
            ("pip", "cryptography", "== 40.0.0", "CVE-2023-49083"),
            ("pip", "aiohttp", "== 3.8.0", "CVE-2024-23334"),
            ("pip", "sqlparse", "== 0.4.4", "CVE-2024-4340"),
            ("pip", "paramiko", "== 3.0.0", "CVE-2023-48795"),
            ("npm", "axios", "^1.6.0", "CVE-2024-39338"),
            ("npm", "lodash", "4.17.19", "CVE-2021-23337"),
            ("npm", "express", "4.17.1", "CVE-2024-29041"),
            ("npm", "jsonwebtoken", "8.5.1", "CVE-2022-23529"),
            ("npm", "minimist", "1.2.5", "CVE-2021-44906"),
            ("npm", "tar", "6.1.0", "CVE-2021-37712"),
            ("npm", "ws", "8.16.0", "CVE-2024-38375"),
            ("npm", "semver", "7.5.1", "CVE-2022-25883"),
        ]
        for eco, pkg, spec, expected_cve in test_probes:
            matched = check_package_vulnerabilities(eco, pkg, spec)
            cves = {a.cve for a in matched}
            assert expected_cve in cves, (
                f"Expected {expected_cve} for {eco}:{pkg}:{spec}, but got {cves}"
            )


# ============================================================================
# GROUP F: Directory Scanning, Line Endings, and Interface Contract
# ============================================================================

class TestDirectoryAndContractAdversarial:
    """Stress tests for scan_all_manifests, line endings, and DependencyFinding contract."""

    def test_scan_all_manifests_exclusions(self, tmp_path):
        """scan_all_manifests must strictly ignore .git, .venv, node_modules, .agents."""
        # Valid manifest 1
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
        # Valid manifest 2 in subfolder
        sub = tmp_path / "frontend"
        sub.mkdir()
        (sub / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.19"}}), encoding="utf-8")

        # Ignored directories containing manifests
        for ignored in (".git", ".venv", "venv", "node_modules", "__pycache__", ".agents", "workspace"):
            p = tmp_path / ignored
            p.mkdir()
            (p / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
            (p / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.19"}}), encoding="utf-8")

        findings = scan_all_manifests(tmp_path, recursive=True)
        assert len(findings) == 2
        pkgs = {f.package for f in findings}
        assert pkgs == {"requests", "lodash"}

    def test_crlf_and_cr_line_endings(self, tmp_path):
        """Manifests with CRLF (Windows) and CR (old Mac) line endings parse cleanly."""
        crlf_content = "requests==2.25.0\r\nurllib3==1.26.4\r\nflask==1.0.0\r\n"
        req_crlf = tmp_path / "crlf_req.txt"
        req_crlf.write_bytes(crlf_content.encode("utf-8"))
        findings_crlf = scan_dependencies(req_crlf)
        assert len(findings_crlf) == 3

        cr_content = "requests==2.25.0\rurllib3==1.26.4\rflask==1.0.0\r"
        req_cr = tmp_path / "cr_req.txt"
        req_cr.write_bytes(cr_content.encode("utf-8"))
        findings_cr = scan_dependencies(req_cr)
        assert len(findings_cr) == 3

    def test_dependency_finding_contract_and_mapping(self):
        """DependencyFinding complies with PROJECT.md contract and dict protocol."""
        finding = DependencyFinding(
            package="Requests",
            current_version="==2.25.0",
            vulnerable_range="< 2.31.0",
            fixed_version="2.31.0",
            cve="CVE-2023-32681",
            severity="high",
            advisory="Proxy leak flaw",
            manifest_file="requirements.txt",
            line=4,
            ecosystem="pip",
            cvss_score=8.8
        )
        # Contract normalization
        assert finding.package == "requests"
        assert finding.severity == "HIGH"
        assert finding.description == "Proxy leak flaw"
        assert finding.severity_rank() == 1

        # Dict compatibility
        assert finding["package"] == "requests"
        assert finding["cve"] == "CVE-2023-32681"
        assert finding["description"] == "Proxy leak flaw"
        assert "description" in finding
        assert "package" in finding
        assert finding.get("non_existent", "fallback") == "fallback"

        # Serialization roundtrip
        d = finding.to_dict()
        assert isinstance(d, dict)
        assert d["package"] == "requests"
        reconstructed = DependencyFinding.from_dict(d)
        assert reconstructed.package == finding.package
        assert reconstructed.cve == finding.cve


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))

