"""BetHacker Offline Advisory Database and Zero-Dependency Version Engine.

Provides an offline curated CVE advisory catalog (Python and Node.js) and
a pure-Python version engine supporting SemVer 2.0.0 and PEP 440 comparison logic.
Zero external dependencies: uses only Python standard library.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# 1. ZERO-DEPENDENCY VERSION ENGINE (SemVer 2.0.0 & PEP 440)
# ============================================================================

class ComparableVersion:
    """Zero-dependency, fully comparable version class supporting SemVer 2.0.0
    and PEP 440 version specifications.
    """

    __slots__ = ("raw", "numeric", "prerelease_type", "prerelease_num", "postrelease_num")

    def __init__(self, version_str: str) -> None:
        self.raw = str(version_str).strip()
        self.numeric, self.prerelease_type, self.prerelease_num, self.postrelease_num = self._parse(self.raw)

    def _parse(self, v_str: str) -> Tuple[Tuple[int, ...], int, int, int]:
        # Strip leading 'v', '=', and whitespace
        clean = re.sub(r"^[vV=\s]+", "", v_str).strip()
        # Strip build metadata (e.g. +build123)
        clean = clean.split("+")[0]

        # Check post-release (PEP 440: .post1, -post1, post1)
        post_match = re.search(r"[\.-]?post(\d+)", clean, re.IGNORECASE)
        post_num = int(post_match.group(1)) if post_match else 0
        if post_match:
            clean = clean[:post_match.start()]

        # Check pre-release (SemVer: -alpha.1, -rc.2; PEP 440: a1, b2, rc1, dev0)
        # Pre-release ranks: dev (0) < alpha/a (1) < beta/b (2) < rc/c/preview (3) < final (4)
        pre_type = 4  # 4 = Final release (no pre-release)
        pre_num = 0

        pre_match = re.search(r"[\.-]?(dev|alpha|beta|rc|preview|pre|a|b|c)(\d*)", clean, re.IGNORECASE)
        if pre_match:
            tag = pre_match.group(1).lower()
            num_str = pre_match.group(2)
            pre_num = int(num_str) if num_str else 0
            if tag in ("dev",):
                pre_type = 0
            elif tag in ("alpha", "a"):
                pre_type = 1
            elif tag in ("beta", "b"):
                pre_type = 2
            elif tag in ("rc", "preview", "pre", "c"):
                pre_type = 3
            clean = clean[:pre_match.start()]

        # Extract numeric core
        num_parts: List[int] = []
        for part in re.split(r"[\.-]", clean):
            part = part.strip()
            if part.isdigit():
                num_parts.append(int(part))
            elif part:
                lead_digits = re.match(r"^(\d+)", part)
                if lead_digits:
                    num_parts.append(int(lead_digits.group(1)))
                else:
                    break

        # Normalize to at least 3 parts (major, minor, patch)
        while len(num_parts) < 3:
            num_parts.append(0)

        return (tuple(num_parts), pre_type, pre_num, post_num)

    def _key(self) -> Tuple[Any, ...]:
        return (self.numeric, self.prerelease_type, self.prerelease_num, self.postrelease_num)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ComparableVersion):
            other = ComparableVersion(str(other))
        return self._key() == other._key()

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, ComparableVersion):
            other = ComparableVersion(str(other))
        return self._key() < other._key()

    def __le__(self, other: Any) -> bool:
        return self == other or self < other

    def __gt__(self, other: Any) -> bool:
        return not (self <= other)

    def __ge__(self, other: Any) -> bool:
        return not (self < other)

    def __repr__(self) -> str:
        return f"ComparableVersion({self.raw!r})"


def evaluate_condition(version: ComparableVersion, op: str, target_str: str) -> bool:
    """Evaluates a single operator and target version against a ComparableVersion."""
    # Handle wildcard == (e.g. 2.25.*)
    if op in ("==", "===") and "*" in target_str:
        prefix = target_str.replace("*", "").rstrip(".")
        clean_raw = version.raw.split("-")[0]
        return clean_raw.startswith(prefix)

    # Handle npm caret (^)
    if op == "^":
        target = ComparableVersion(target_str)
        if version < target:
            return False
        nums = list(target.numeric)
        if nums[0] > 0:
            upper = (nums[0] + 1, 0, 0)
        elif len(nums) > 1 and nums[1] > 0:
            upper = (0, nums[1] + 1, 0)
        else:
            upper = (0, 0, (nums[2] if len(nums) > 2 else 0) + 1)
        return version.numeric < upper

    # Handle npm tilde (~)
    if op == "~":
        target = ComparableVersion(target_str)
        if version < target:
            return False
        nums = list(target.numeric)
        upper = (nums[0], (nums[1] if len(nums) > 1 else 0) + 1, 0)
        return version.numeric < upper

    # Handle PEP 440 compatible release (~=)
    if op == "~=":
        target = ComparableVersion(target_str)
        if version < target:
            return False
        parts = target_str.split(".")
        nums = list(target.numeric)
        if len(parts) <= 2:
            upper = (nums[0] + 1, 0, 0)
        else:
            upper = (nums[0], nums[1] + 1, 0)
        return version.numeric < upper

    target = ComparableVersion(target_str)
    if op in ("==", "==="):
        return version == target
    elif op == "!=":
        return version != target
    elif op == "<":
        return version < target
    elif op == "<=":
        return version <= target
    elif op == ">":
        return version > target
    elif op == ">=":
        return version >= target
    return False


def is_version_in_range(version_str: str, range_expr: str) -> bool:
    """Evaluates whether version_str satisfies a composite range expression.
    Supports comma-separated or space-separated conditions, and '||' OR branches.
    """
    v = ComparableVersion(version_str)

    or_branches = [b.strip() for b in range_expr.split("||")]
    for branch in or_branches:
        cond_matches = re.findall(r"([=><~!]{1,3})\s*([0-9a-zA-Z\.\-\+]+)", branch)
        if not cond_matches:
            continue
        all_passed = True
        for op, target_ver in cond_matches:
            if not evaluate_condition(v, op, target_ver):
                all_passed = False
                break
        if all_passed:
            return True

    return False


# ============================================================================
# 2. ADVISORY DATA MODEL & CURATED CATALOG
# ============================================================================

@dataclass
class Advisory:
    """Represents an offline CVE vulnerability advisory in the catalog."""
    cve: str
    package: str
    ecosystem: str  # "pip" | "npm"
    vulnerable_ranges: List[str]
    fixed_version: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    cvss_score: float
    title: str
    description: str
    attack_vector: str
    remediation: str
    references: List[str] = field(default_factory=list)


OFFLINE_ADVISORIES: List[Advisory] = [
    # -----------------------------------------------------------------------
    # Python (pip) Advisory Catalog (14 CVEs)
    # -----------------------------------------------------------------------
    Advisory(
        cve="CVE-2023-32681",
        package="requests",
        ecosystem="pip",
        vulnerable_ranges=["< 2.31.0"],
        fixed_version="2.31.0",
        severity="HIGH",
        cvss_score=8.8,
        title="Unintended Leak of Proxy-Authorization Header on Redirect",
        description="Requests leaks Proxy-Authorization headers to HTTPS redirect destinations.",
        attack_vector="HTTP Redirects",
        remediation='pip install --upgrade "requests>=2.31.0"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"]
    ),
    Advisory(
        cve="CVE-2023-45803",
        package="urllib3",
        ecosystem="pip",
        vulnerable_ranges=["< 1.26.18", ">= 2.0.0 < 2.0.7"],
        fixed_version="2.0.7",
        severity="HIGH",
        cvss_score=8.1,
        title="Request Body Leaked on HTTP 303 Redirect",
        description="urllib3 does not strip request body on HTTP 303 redirects.",
        attack_vector="HTTP 303 Redirect",
        remediation='pip install --upgrade "urllib3>=2.0.7"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-45803"]
    ),
    Advisory(
        cve="CVE-2021-33503",
        package="urllib3",
        ecosystem="pip",
        vulnerable_ranges=["< 1.26.5"],
        fixed_version="1.26.5",
        severity="HIGH",
        cvss_score=7.5,
        title="Catastrophic ReDoS in URL Authority Parsing",
        description="Regular expression in urllib3 authority parsing suffers from catastrophic backtracking.",
        attack_vector="Specially crafted URL authority string",
        remediation='pip install --upgrade "urllib3>=1.26.5"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-33503"]
    ),
    Advisory(
        cve="CVE-2023-30861",
        package="flask",
        ecosystem="pip",
        vulnerable_ranges=["< 2.2.5", ">= 2.3.0 < 2.3.2"],
        fixed_version="2.3.2",
        severity="HIGH",
        cvss_score=7.5,
        title="Session Cookie Disclosure in Cached Responses",
        description="Flask responses cached by reverse proxies leak session cookies due to missing Vary: Cookie.",
        attack_vector="HTTP Proxy / CDN Caching",
        remediation='pip install --upgrade "flask>=2.3.2"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-30861"]
    ),
    Advisory(
        cve="CVE-2024-27351",
        package="django",
        ecosystem="pip",
        vulnerable_ranges=[">= 3.2 < 3.2.25", ">= 4.2.1 < 4.2.11", ">= 5.0 < 5.0.3"],
        fixed_version="4.2.11",
        severity="HIGH",
        cvss_score=9.8,
        title="ReDoS and Memory Exhaustion in Truncator",
        description="Quadratic regex evaluation in django.utils.text.Truncator causing unbounded CPU/memory exhaustion.",
        attack_vector="Untrusted HTML text input",
        remediation='pip install --upgrade "django>=4.2.11"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-27351"]
    ),
    Advisory(
        cve="CVE-2022-34265",
        package="django",
        ecosystem="pip",
        vulnerable_ranges=[">= 2.2 < 3.2.14", ">= 4.0 < 4.0.6"],
        fixed_version="4.0.6",
        severity="HIGH",
        cvss_score=9.8,
        title="SQL Injection in Trunc() and Extract() Database Functions",
        description="Raw SQL interpolation in Trunc() and Extract() database functions leads to SQL injection.",
        attack_vector="SQL function parameters",
        remediation='pip install --upgrade "django>=4.0.6"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-34265"]
    ),
    Advisory(
        cve="CVE-2020-14343",
        package="pyyaml",
        ecosystem="pip",
        vulnerable_ranges=["< 5.4"],
        fixed_version="5.4",
        severity="HIGH",
        cvss_score=9.8,
        title="Arbitrary Code Execution via Untrusted YAML in FullLoader",
        description="PyYAML FullLoader allows arbitrary Python class instantiation and code execution.",
        attack_vector="Untrusted YAML files",
        remediation='pip install --upgrade "pyyaml>=6.0.1"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"]
    ),
    Advisory(
        cve="CVE-2024-28219",
        package="pillow",
        ecosystem="pip",
        vulnerable_ranges=[">= 10.2.1 < 10.3.0"],
        fixed_version="10.3.0",
        severity="HIGH",
        cvss_score=9.8,
        title="Buffer Overflow in ImageColor.c via strncpy",
        description="Buffer overflow in ImageColor.c enables arbitrary memory overwrite and code execution.",
        attack_vector="Crafted color string inputs",
        remediation='pip install --upgrade "pillow>=10.3.0"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-28219"]
    ),
    Advisory(
        cve="CVE-2023-50447",
        package="pillow",
        ecosystem="pip",
        vulnerable_ranges=["< 10.2.0"],
        fixed_version="10.2.0",
        severity="HIGH",
        cvss_score=9.8,
        title="Arbitrary Code Execution in ImageMath.eval",
        description="ImageMath.eval environment injection allows remote code execution.",
        attack_vector="Untrusted image mathematical expressions",
        remediation='pip install --upgrade "pillow>=10.2.0"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-50447"]
    ),
    Advisory(
        cve="CVE-2024-22195",
        package="jinja2",
        ecosystem="pip",
        vulnerable_ranges=["< 3.1.3"],
        fixed_version="3.1.3",
        severity="MEDIUM",
        cvss_score=6.5,
        title="Cross-Site Scripting (XSS) in xmlattr Filter",
        description="xmlattr filter keys with special characters allow attribute injection and XSS.",
        attack_vector="XML/HTML attribute dictionaries",
        remediation='pip install --upgrade "jinja2>=3.1.3"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-22195"]
    ),
    Advisory(
        cve="CVE-2023-49083",
        package="cryptography",
        ecosystem="pip",
        vulnerable_ranges=["< 41.0.6"],
        fixed_version="41.0.6",
        severity="HIGH",
        cvss_score=7.5,
        title="NULL Pointer Dereference in PKCS7 Certificate Parsing",
        description="Loading empty PKCS7 certificates causes NULL pointer dereference and crash.",
        attack_vector="Malformed PKCS7 certificate payload",
        remediation='pip install --upgrade "cryptography>=41.0.6"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-49083"]
    ),
    Advisory(
        cve="CVE-2024-23334",
        package="aiohttp",
        ecosystem="pip",
        vulnerable_ranges=["< 3.9.2"],
        fixed_version="3.9.2",
        severity="HIGH",
        cvss_score=9.8,
        title="Directory Traversal in Static File Serving",
        description="Path traversal in aiohttp static file serving enables arbitrary file disclosure.",
        attack_vector="HTTP GET requests with path traversal sequences",
        remediation='pip install --upgrade "aiohttp>=3.9.2"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-23334"]
    ),
    Advisory(
        cve="CVE-2024-4340",
        package="sqlparse",
        ecosystem="pip",
        vulnerable_ranges=["< 0.5.0"],
        fixed_version="0.5.0",
        severity="HIGH",
        cvss_score=7.5,
        title="Recursion Depth Limit Bypass Causing Denial of Service",
        description="Nested SQL clauses trigger RecursionError causing server crash.",
        attack_vector="Deeply nested SQL expressions",
        remediation='pip install --upgrade "sqlparse>=0.5.0"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-4340"]
    ),
    Advisory(
        cve="CVE-2023-48795",
        package="paramiko",
        ecosystem="pip",
        vulnerable_ranges=["< 3.4.0"],
        fixed_version="3.4.0",
        severity="HIGH",
        cvss_score=7.5,
        title="Terrapin Attack: SSH Prefix Truncation Vulnerability",
        description="SSH protocol handshake extension message truncation flaw.",
        attack_vector="Network Man-in-the-Middle",
        remediation='pip install --upgrade "paramiko>=3.4.0"',
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-48795"]
    ),

    # -----------------------------------------------------------------------
    # Node.js (npm) Advisory Catalog (9 CVEs)
    # -----------------------------------------------------------------------
    Advisory(
        cve="CVE-2024-39338",
        package="axios",
        ecosystem="npm",
        vulnerable_ranges=["< 1.7.4"],
        fixed_version="1.7.4",
        severity="HIGH",
        cvss_score=7.5,
        title="SSRF and Credential Leak via Relative Protocol Redirect",
        description="Axios leaks credentials and sensitive headers when redirected to protocol-relative URLs.",
        attack_vector="HTTP Redirect Location header",
        remediation="npm install axios@^1.7.4",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-39338"]
    ),
    Advisory(
        cve="CVE-2021-23337",
        package="lodash",
        ecosystem="npm",
        vulnerable_ranges=["< 4.17.21"],
        fixed_version="4.17.21",
        severity="HIGH",
        cvss_score=7.2,
        title="Command Injection in lodash.template via Prototype Pollution",
        description="Insecure default template interpolation in lodash.template leads to arbitrary code execution.",
        attack_vector="Prototype pollution in template interpolation options",
        remediation="npm install lodash@^4.17.21",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
    ),
    Advisory(
        cve="CVE-2020-8203",
        package="lodash",
        ecosystem="npm",
        vulnerable_ranges=["< 4.17.19"],
        fixed_version="4.17.19",
        severity="HIGH",
        cvss_score=7.4,
        title="Prototype Pollution in lodash.set, lodash.merge",
        description="Prototype pollution via __proto__ property assignment in lodash utility functions.",
        attack_vector="Untrusted object keys",
        remediation="npm install lodash@^4.17.21",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-8203"]
    ),
    Advisory(
        cve="CVE-2024-29041",
        package="express",
        ecosystem="npm",
        vulnerable_ranges=["< 4.19.2"],
        fixed_version="4.19.2",
        severity="HIGH",
        cvss_score=7.5,
        title="Open Redirect and SSRF in res.redirect() and res.location()",
        description="Unvalidated URL protocol parsing in Express redirect methods.",
        attack_vector="Crafted redirect target URLs",
        remediation="npm install express@^4.19.2",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-29041"]
    ),
    Advisory(
        cve="CVE-2022-23529",
        package="jsonwebtoken",
        ecosystem="npm",
        vulnerable_ranges=["< 9.0.0"],
        fixed_version="9.0.0",
        severity="HIGH",
        cvss_score=9.8,
        title="Remote Code Execution via Insecure toString() on secretOrPublicKey",
        description="Arbitrary code execution via poisoned toString method on secretOrPublicKey in jwt.verify.",
        attack_vector="Untrusted verification key objects",
        remediation="npm install jsonwebtoken@^9.0.0",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-23529"]
    ),
    Advisory(
        cve="CVE-2021-44906",
        package="minimist",
        ecosystem="npm",
        vulnerable_ranges=["< 1.2.6"],
        fixed_version="1.2.6",
        severity="HIGH",
        cvss_score=9.8,
        title="Prototype Pollution in Minimist CLI Argument Parsing",
        description="Prototype pollution allows modifying Object.prototype via crafted argument keys.",
        attack_vector="CLI arguments or array inputs",
        remediation="npm install minimist@^1.2.6",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44906"]
    ),
    Advisory(
        cve="CVE-2021-37712",
        package="tar",
        ecosystem="npm",
        vulnerable_ranges=["< 6.1.9"],
        fixed_version="6.1.9",
        severity="HIGH",
        cvss_score=8.6,
        title="Arbitrary File Overwrite via Symlink and Path Traversal",
        description="node-tar symlink resolution bug enables arbitrary file creation during extraction.",
        attack_vector="Crafted TAR archives with symlinks",
        remediation="npm install tar@^6.1.9",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-37712"]
    ),
    Advisory(
        cve="CVE-2024-38375",
        package="ws",
        ecosystem="npm",
        vulnerable_ranges=["< 8.17.1"],
        fixed_version="8.17.1",
        severity="HIGH",
        cvss_score=7.5,
        title="Denial of Service via Sec-WebSocket-Extensions Header",
        description="Malformed Sec-WebSocket-Extensions header crashes WebSocket server.",
        attack_vector="HTTP WebSocket upgrade request headers",
        remediation="npm install ws@^8.17.1",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-38375"]
    ),
    Advisory(
        cve="CVE-2022-25883",
        package="semver",
        ecosystem="npm",
        vulnerable_ranges=["< 7.5.2"],
        fixed_version="7.5.2",
        severity="HIGH",
        cvss_score=7.5,
        title="Regular Expression Denial of Service (ReDoS) in Range Parsing",
        description="ReDoS vulnerability in semver complex range parsing.",
        attack_vector="Untrusted SemVer range strings",
        remediation="npm install semver@^7.5.2",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-25883"]
    ),
]


def get_advisories_for_package(ecosystem: str, package_name: str) -> List[Advisory]:
    """Retrieves all advisories matching ecosystem and canonical package name."""
    norm_pkg = package_name.strip().lower().replace("_", "-")
    return [
        adv for adv in OFFLINE_ADVISORIES
        if adv.ecosystem == ecosystem and adv.package.lower().replace("_", "-") == norm_pkg
    ]


def check_package_vulnerabilities(
    ecosystem: str, package_name: str, declared_spec: str
) -> List[Advisory]:
    """Evaluates whether a declared package version specifier matches any known
    advisories in the offline database.
    """
    advisories = get_advisories_for_package(ecosystem, package_name)
    vulnerable_matches: List[Advisory] = []

    m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9\.\-]*)?)", declared_spec)
    candidate_ver = m.group(1) if m else None

    for adv in advisories:
        is_vuln = False
        if candidate_ver:
            # Check strictly against vulnerable ranges
            if adv.vulnerable_ranges:
                for v_range in adv.vulnerable_ranges:
                    if is_version_in_range(candidate_ver, v_range):
                        is_vuln = True
                        break
            elif adv.fixed_version:
                cand = ComparableVersion(candidate_ver)
                fix = ComparableVersion(adv.fixed_version)
                if cand < fix and f">={adv.fixed_version}" not in declared_spec:
                    is_vuln = True
        else:
            # Unpinned dependency without version
            is_vuln = False

        if is_vuln and adv not in vulnerable_matches:
            vulnerable_matches.append(adv)

    return vulnerable_matches
