"""Empirical stress test suite for tools/sca.py and tools/advisories.py.
Authored by Challenger M1_2.
Runs standalone with `python3 tests/test_sca_stress.py`.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

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
)

def run_suite():
    findings_bugs = []
    passes = []

    print("=" * 70)
    print("CHALLENGER M1_2 EMPIRICAL STRESS TEST SUITE")
    print("=" * 70)

    # =========================================================================
    # Group 1: SemVer and PEP 440 Pre-Release and Post-Release Comparisons
    # =========================================================================
    print("\n--- Group 1: Version Parsing & Comparisons ---")

    # 1.1: SemVer dot-separated pre-release numbers (e.g. 1.0.0-beta.2 vs 1.0.0-beta.11)
    v_b2 = ComparableVersion("1.0.0-beta.2")
    v_b11 = ComparableVersion("1.0.0-beta.11")
    if v_b2 < v_b11:
        passes.append("SemVer dot pre-release numbers (1.0.0-beta.2 < 1.0.0-beta.11)")
    else:
        findings_bugs.append({
            "id": "BUG-VER-001",
            "title": "SemVer dot-separated pre-release version numbers are ignored",
            "detail": f"ComparableVersion('1.0.0-beta.2') < ('1.0.0-beta.11') returned False ({v_b2._key()} vs {v_b11._key()})."
        })

    # 1.2: Unrelated suffix containing 'a', 'b', 'c' mistakenly flagged as pre-release
    # e.g. 1.0.0-patch, 1.0.0-stable, 1.0.0-final
    v_patch = ComparableVersion("1.0.0-patch")
    v_stable = ComparableVersion("1.0.0-stable")
    v_final = ComparableVersion("1.0.0-final")
    v_base = ComparableVersion("1.0.0")
    if v_patch.prerelease_type == 4 and v_stable.prerelease_type == 4 and v_final.prerelease_type == 4:
        passes.append("Non-prerelease tags not classified as alpha/beta/rc")
    else:
        findings_bugs.append({
            "id": "BUG-VER-002",
            "title": "Tags containing 'a', 'b', or 'c' (e.g. -patch, -stable, -final) incorrectly parsed as pre-releases",
            "detail": f"-patch={v_patch.prerelease_type}, -stable={v_stable.prerelease_type}, -final={v_final.prerelease_type} (expected 4 for final)."
        })

    # 1.3: PEP 440 post-releases vs final release
    v_post = ComparableVersion("1.0.0.post1")
    if v_post > v_base:
        passes.append("PEP 440 post-release precedence (1.0.0.post1 > 1.0.0)")
    else:
        findings_bugs.append({
            "id": "BUG-VER-003",
            "title": "PEP 440 post-release precedence failure",
            "detail": f"ComparableVersion('1.0.0.post1') > ComparableVersion('1.0.0') returned False."
        })

    # 1.4: SemVer build metadata stripping
    v_meta1 = ComparableVersion("1.0.0+build123")
    v_meta2 = ComparableVersion("1.0.0+build456")
    if v_meta1 == v_meta2 == v_base:
        passes.append("SemVer build metadata stripped in equality")
    else:
        findings_bugs.append({
            "id": "BUG-VER-004",
            "title": "SemVer build metadata affects equality",
            "detail": f"ComparableVersion('1.0.0+build123') == ('1.0.0') returned False."
        })

    # 1.5: Major-only version support in specifier regex
    m_single = parse_requirements_txt("django==3\n")
    with tempfile.NamedTemporaryFile("w", suffix="requirements.txt", delete=False) as tf:
        tf.write("django==3\n")
        tf_single = Path(tf.name)
    try:
        findings_single = scan_dependencies(tf_single)
        if len(findings_single) > 0:
            passes.append("Major-only version (django==3) detected in scan_dependencies")
        else:
            findings_bugs.append({
                "id": "BUG-VER-005",
                "title": "Major-only versions (e.g. django==3, minimist==1) skipped by regex requiring '\\d+\\.\\d+'",
                "detail": f"scan_dependencies('django==3') returned 0 findings (expected Django CVEs)."
            })
    finally:
        if tf_single.exists():
            os.remove(tf_single)

    # =========================================================================
    # Group 2: Wildcard, Caret (^), and Tilde (~) Range Evaluation
    # =========================================================================
    print("\n--- Group 2: Range Evaluation & Operators ---")

    # 2.1: Caret (^) range in is_version_in_range
    in_caret = is_version_in_range("1.5.0", "^1.2.3")
    if in_caret:
        passes.append("Caret range (^1.2.3) in is_version_in_range")
    else:
        findings_bugs.append({
            "id": "BUG-RNG-001",
            "title": "Caret range operator (^) in is_version_in_range is completely dropped by regex",
            "detail": "is_version_in_range('1.5.0', '^1.2.3') returned False because regex [=><~!] does not match '^'."
        })

    # 2.2: Wildcard (== 2.2.*) in is_version_in_range and evaluate_condition
    wildcard_221 = is_version_in_range("2.2.1", "== 2.2.*")
    wildcard_225 = is_version_in_range("2.25.0", "== 2.2.*")
    if wildcard_221 and not wildcard_225:
        passes.append("Wildcard range (== 2.2.*) correctly matches 2.2.1 and rejects 2.25.0")
    else:
        findings_bugs.append({
            "id": "BUG-RNG-002",
            "title": "Wildcard range (== 2.2.*) regex strips '*' or string prefix matches 2.25.0",
            "detail": f"is_version_in_range('2.2.1', '== 2.2.*')={wildcard_221}, ('2.25.0', '== 2.2.*')={wildcard_225}."
        })

    # 2.3: Major wildcard (== 1.*) in evaluate_condition
    v_10 = ComparableVersion("10.0.0")
    match_1_star = evaluate_condition(v_10, "==", "1.*")
    if not match_1_star:
        passes.append("Major wildcard '1.*' rejects '10.0.0'")
    else:
        findings_bugs.append({
            "id": "BUG-RNG-003",
            "title": "Wildcard evaluate_condition uses clean_raw.startswith(prefix) causing 10.0.0 to match 1.*",
            "detail": "evaluate_condition(ComparableVersion('10.0.0'), '==', '1.*') returned True."
        })

    # 2.4: Tilde range (~1.2.0)
    in_tilde = is_version_in_range("1.2.5", "~1.2.0")
    out_tilde = is_version_in_range("1.3.0", "~1.2.0")
    if in_tilde and not out_tilde:
        passes.append("Tilde range (~1.2.0) correctly evaluates")
    else:
        findings_bugs.append({
            "id": "BUG-RNG-004",
            "title": "Tilde range (~1.2.0) evaluation failure",
            "detail": f"in_tilde={in_tilde}, out_tilde={out_tilde}."
        })

    # 2.5: PEP 440 Compatible release (~=)
    in_pep_tilde = is_version_in_range("1.4.5", "~= 1.4.0")
    out_pep_tilde = is_version_in_range("1.5.0", "~= 1.4.0")
    if in_pep_tilde and not out_pep_tilde:
        passes.append("PEP 440 compatible release (~=) correctly evaluates")
    else:
        findings_bugs.append({
            "id": "BUG-RNG-005",
            "title": "PEP 440 ~= evaluation failure",
            "detail": f"in_pep_tilde={in_pep_tilde}, out_pep_tilde={out_pep_tilde}."
        })

    # =========================================================================
    # Group 3: Malformed Manifests Handling & Exception Safety
    # =========================================================================
    print("\n--- Group 3: Malformed Manifests & Fault Tolerance ---")
    manifest_cases = [
        ("empty_req.txt", "", "pip"),
        ("comment_only_req.txt", "# Only comments\n   # Indented\n", "pip"),
        ("whitespace_req.txt", "   \n\t\n   ", "pip"),
        ("garbage_req.txt", "====\n>>>><<<<\n--extra-index-url http://foo\n", "pip"),
        ("trailing_slash_eof.txt", "requests==2.25.0\\", "pip"),
        ("empty_pkg.json", "", "npm"),
        ("comments_pkg.json", "// js comment\n/* block */\n", "npm"),
        ("trailing_comma_pkg.json", '{"dependencies": {"lodash": "4.17.19",}}', "npm"),
        ("missing_deps_pkg.json", '{"name": "foo", "version": "1.0.0"}', "npm"),
        ("null_deps_pkg.json", '{"dependencies": null}', "npm"),
        ("list_deps_pkg.json", '{"dependencies": ["lodash"]}', "npm"),
        ("non_str_deps_pkg.json", '{"dependencies": {"lodash": 123}}', "npm"),
        ("git_and_file_deps_pkg.json", '{"dependencies": {"my-pkg": "git+https://github.com/foo/bar.git", "local": "file:../local"}}', "npm"),
    ]

    for filename, content, eco in manifest_cases:
        with tempfile.NamedTemporaryFile("w", suffix=filename, delete=False, encoding="utf-8") as tf:
            tf.write(content)
            tf_path = Path(tf.name)
        try:
            findings = scan_dependencies(tf_path)
            if eco == "pip":
                pkgs = parse_requirements_txt(tf_path)
            else:
                pkgs = parse_package_json(tf_path)
            passes.append(f"Manifest safety: {filename} handled cleanly (findings={len(findings)})")
        except Exception as e:
            findings_bugs.append({
                "id": "BUG-MNF-001",
                "title": f"Unhandled crash on malformed manifest: {filename}",
                "detail": f"Raised {type(e).__name__}: {e}"
            })
        finally:
            if tf_path.exists():
                os.remove(tf_path)

    # =========================================================================
    # Group 4: Encodings: UTF-8 BOM, Latin-1, CP1252, and Binary Files
    # =========================================================================
    print("\n--- Group 4: Character Encodings & Binary Payloads ---")

    # 4.1: UTF-8 with BOM
    bom_content = "\ufeffrequests==2.25.0\nurllib3==1.26.4\n".encode("utf-8-sig")
    with tempfile.NamedTemporaryFile("wb", suffix="requirements.txt", delete=False) as tf:
        tf.write(bom_content)
        tf_path = Path(tf.name)
    try:
        findings = scan_dependencies(tf_path)
        pkg_names = {f.package for f in findings}
        if "requests" in pkg_names and "urllib3" in pkg_names:
            passes.append("UTF-8 BOM handled cleanly without corrupting first package name")
        else:
            findings_bugs.append({
                "id": "BUG-ENC-001",
                "title": "UTF-8 with BOM corrupts first package name in requirements.txt",
                "detail": f"Package names found: {pkg_names} (expected 'requests' and 'urllib3')."
            })
    except Exception as e:
        findings_bugs.append({
            "id": "BUG-ENC-001",
            "title": "Exception on UTF-8 BOM requirements.txt",
            "detail": f"Raised {type(e).__name__}: {e}"
        })
    finally:
        if tf_path.exists():
            os.remove(tf_path)

    # 4.2: Latin-1 encoding with high-order byte characters in comments
    latin1_content = "# Développé par René & François\nrequests==2.25.0\n".encode("latin-1")
    with tempfile.NamedTemporaryFile("wb", suffix="requirements.txt", delete=False) as tf:
        tf.write(latin1_content)
        tf_path = Path(tf.name)
    try:
        findings = scan_dependencies(tf_path)
        pkg_names = {f.package for f in findings}
        if "requests" in pkg_names:
            passes.append("Latin-1 encoded manifest handled gracefully")
        else:
            findings_bugs.append({
                "id": "BUG-ENC-002",
                "title": "Latin-1 manifest failed to parse 'requests'",
                "detail": f"Package names found: {pkg_names}."
            })
    except Exception as e:
        findings_bugs.append({
            "id": "BUG-ENC-002",
            "title": "Exception on Latin-1 manifest",
            "detail": f"Raised {type(e).__name__}: {e}"
        })
    finally:
        if tf_path.exists():
            os.remove(tf_path)

    # 4.3: Binary file (ELF / EXE / random bytes) passed as requirements.txt
    binary_content = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00requests==2.25.0\x00\xff\xfe"
    with tempfile.NamedTemporaryFile("wb", suffix="requirements.txt", delete=False) as tf:
        tf.write(binary_content)
        tf_path = Path(tf.name)
    try:
        findings = scan_dependencies(tf_path)
        passes.append(f"Binary file passed as requirements.txt handled without crash (findings={len(findings)})")
    except Exception as e:
        findings_bugs.append({
            "id": "BUG-ENC-003",
            "title": "Crash when binary file passed to scan_dependencies",
            "detail": f"Raised {type(e).__name__}: {e}"
        })
    finally:
        if tf_path.exists():
            os.remove(tf_path)

    # 4.4: Binary file passed as package.json
    binary_json = b"\x00\x01\x02\x03\xff\xfe\xef{\"dependencies\": {\"lodash\": \"4.17.19\"}}"
    with tempfile.NamedTemporaryFile("wb", suffix="package.json", delete=False) as tf:
        tf.write(binary_json)
        tf_path = Path(tf.name)
    try:
        findings = scan_dependencies(tf_path)
        passes.append(f"Binary file passed as package.json handled without crash (findings={len(findings)})")
    except Exception as e:
        findings_bugs.append({
            "id": "BUG-ENC-004",
            "title": "Crash when binary file passed as package.json",
            "detail": f"Raised {type(e).__name__}: {e}"
        })
    finally:
        if tf_path.exists():
            os.remove(tf_path)

    # =========================================================================
    # Group 5: Detection of npm Vulnerabilities via scan_dependencies
    # =========================================================================
    print("\n--- Group 5: npm CVE Scanning in package.json ---")
    npm_pkg_content = json.dumps({
        "name": "vulnerable-app",
        "version": "1.0.0",
        "dependencies": {
            "axios": "^1.6.0",
            "lodash": "4.17.19",
            "express": "4.17.1",
            "jsonwebtoken": "8.5.1",
            "minimist": "1.2.5",
            "tar": "6.1.0",
            "ws": "8.16.0",
            "semver": "7.5.1"
        },
        "devDependencies": {
            "jest": "29.0.0"
        }
    }, indent=2)

    with tempfile.NamedTemporaryFile("w", suffix="package.json", delete=False, encoding="utf-8") as tf:
        tf.write(npm_pkg_content)
        tf_path = Path(tf.name)
    try:
        npm_findings = scan_dependencies(tf_path)
        detected_npm = {f.package for f in npm_findings}
        expected_npm = {"axios", "lodash", "express", "jsonwebtoken", "minimist", "tar", "ws", "semver"}
        missing_npm = expected_npm - detected_npm
        if not missing_npm:
            passes.append(f"All 8 npm vulnerable packages detected in package.json ({detected_npm})")
        else:
            findings_bugs.append({
                "id": "BUG-NPM-001",
                "title": f"Missing npm CVE detections in package.json: {missing_npm}",
                "detail": f"Detected: {detected_npm}, Expected: {expected_npm}"
            })
    finally:
        if tf_path.exists():
            os.remove(tf_path)

    # =========================================================================
    # Group 6: Package Specifier with Upper Bound or Operators (<, <=)
    # =========================================================================
    print("\n--- Group 6: Specifier Upper Bound Inversion ---")
    advs_upper = check_package_vulnerabilities("npm", "express", "< 4.19.2")
    if len(advs_upper) > 0:
        passes.append("Specifier '< 4.19.2' correctly flagged as vulnerable")
    else:
        findings_bugs.append({
            "id": "BUG-VULN-002",
            "title": "Strict upper-bound specifier '< 4.19.2' fails vulnerability detection",
            "detail": "check_package_vulnerabilities('npm', 'express', '< 4.19.2') returned 0 matches because candidate_ver='4.19.2' which is not '< 4.19.2'."
        })

    # =========================================================================
    # Summary Output
    # =========================================================================
    print("\n" + "=" * 70)
    print(f"SUMMARY: {len(passes)} PASSED, {len(findings_bugs)} BUGS REPRODUCED")
    print("=" * 70)
    for p in passes:
        print(f"  [PASS] {p}")
    print("-" * 70)
    for b in findings_bugs:
        print(f"  [FAIL] {b['id']}: {b['title']}")
        print(f"         {b['detail']}")

    return passes, findings_bugs


# =========================================================================
# Pytest Integration Test Functions
# =========================================================================

class TestSCAStressBattery:
    """Native pytest suite executing the Challenger M1_2 stress battery."""

    def test_sca_stress_all_checks(self):
        """Executes all 29 checks and verifies 0 bugs reproduced."""
        passes, bugs = run_suite()
        assert len(bugs) == 0, f"SCA stress tests failed with {len(bugs)} reproduced bugs: {bugs}"
        assert len(passes) >= 29, f"Expected at least 29 passing checks, got {len(passes)}"


if __name__ == "__main__":
    passes, bugs = run_suite()
    sys.exit(1 if bugs else 0)
