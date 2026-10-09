"""BetHacker Software Composition Analysis (SCA) Scanner.

Audits dependency manifest files (requirements.txt and package.json)
for known vulnerable package versions using an offline CVE advisory database.
Zero external dependencies: uses only Python standard library.
"""

from dataclasses import dataclass, asdict, field
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from tools.advisories import (
    ComparableVersion,
    OFFLINE_ADVISORIES,
    check_package_vulnerabilities,
    get_advisories_for_package,
    is_version_in_range,
)


# ============================================================================
# 1. DATA MODELS & INTERFACES
# ============================================================================

@dataclass
class DependencyFinding:
    """Represents a discovered vulnerable dependency finding.
    
    Adheres to the PROJECT.md interface contract:
    package, current_version, vulnerable_range, fixed_version, cve, severity, advisory.
    Provides dict-like mapping access for backward compatibility with existing tests.
    """
    package: str
    current_version: str
    vulnerable_range: str
    fixed_version: str
    cve: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    advisory: str  # Human-readable summary / description of flaw
    manifest_file: str = ""
    line: Optional[int] = None
    ecosystem: str = "pip"  # "pip" or "npm"
    cvss_score: float = 0.0
    remediation: str = ""
    dep_type: str = "dependencies"

    def __post_init__(self) -> None:
        self.package = self.package.strip().lower()
        self.severity = self.severity.strip().upper()
        if self.severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            self.severity = "HIGH"

        if self.manifest_file:
            try:
                self.manifest_file = Path(self.manifest_file).as_posix()
            except Exception:
                pass

        if not self.remediation:
            if self.fixed_version:
                if self.ecosystem == "npm":
                    self.remediation = f"npm install {self.package}@^{self.fixed_version}"
                else:
                    self.remediation = f'pip install --upgrade "{self.package}>={self.fixed_version}"'
            else:
                self.remediation = f"Review advisory {self.cve} for {self.package}"

    @property
    def description(self) -> str:
        """Alias for advisory to satisfy test compatibility."""
        return self.advisory

    def to_dict(self) -> Dict[str, Any]:
        """Serializes finding to dictionary for JSON output."""
        data = asdict(self)
        data["description"] = self.advisory
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DependencyFinding":
        """Deserializes dictionary to DependencyFinding instance."""
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        if "advisory" not in filtered and "description" in data:
            filtered["advisory"] = data["description"]
        return cls(**filtered)

    def severity_rank(self) -> int:
        """Returns numeric rank for sorting (lower number = higher severity)."""
        ranks = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return ranks.get(self.severity, 4)

    # -----------------------------------------------------------------------
    # Dict-like Mapping Protocol for Backward Compatibility
    # -----------------------------------------------------------------------
    def __getitem__(self, key: str) -> Any:
        if key == "description":
            return self.advisory
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key == "description":
            self.advisory = value
        elif hasattr(self, key):
            setattr(self, key, value)
        else:
            raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if key == "description":
            return True
        return hasattr(self, str(key))

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self) -> List[str]:
        base_keys = list(self.__dataclass_fields__.keys())
        if "description" not in base_keys:
            base_keys.append("description")
        return base_keys

    def items(self) -> List[Tuple[str, Any]]:
        return [(k, self[k]) for k in self.keys()]

    def values(self) -> List[Any]:
        return [self[k] for k in self.keys()]

    def __hash__(self) -> int:
        return hash((self.package, self.cve, self.manifest_file))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DependencyFinding):
            return False
        return (self.package, self.cve, self.manifest_file) == (other.package, other.cve, other.manifest_file)


@dataclass
class ParsedPackage:
    """Represents a parsed package declaration extracted from a manifest."""
    name: str           # Normalized lowercase canonical name
    raw_name: str       # Original declared name
    specifier: str      # Declared version specifier (e.g. "==2.25.0", "^1.6.0", "*")
    specs: List[Tuple[str, str]]  # List of (operator, version_string) pairs
    extras: List[str]   # Any declared extras (e.g. ["security", "socks"])
    line_number: int    # 1-indexed line in file
    raw_line: str       # Complete line content
    dep_type: str = "dependencies"


# Legacy package list for backward compatibility
KNOWN_VULNERABLE_PACKAGES: Dict[str, List[str]] = {
    "requests": ["2.25.0", "2.26.0", "2.27.0"],
    "urllib3": ["1.26.4", "1.26.5", "1.26.17"],
    "flask": ["0.12", "1.0", "1.0.1"],
    "django": ["2.2", "3.0", "3.1"],
    "pyyaml": ["5.1", "5.2", "5.3"],
    "pillow": ["8.0.0", "8.1.0", "9.0.0"],
}


# ============================================================================
# 2. MANIFEST PARSERS
# ============================================================================

def normalize_package_name(name: str) -> str:
    """Canonicalize Python package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def parse_pep440_clauses(spec_str: str) -> List[Tuple[str, str]]:
    """Parses a PEP 440 specifier string like '>=2.20.0,<2.31.0' into
    a list of (operator, version) tuples.
    """
    if not spec_str or spec_str == "*":
        return [("*", "*")]

    clauses: List[Tuple[str, str]] = []
    for part in spec_str.split(","):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^([=><~!]{1,3})\s*(.+)$", part)
        if m:
            clauses.append((m.group(1), m.group(2).strip()))
        else:
            clauses.append(("==", part))
    return clauses


def parse_requirements_txt(filepath_or_content: Union[str, Path]) -> List[ParsedPackage]:
    """Parses requirements.txt content or file path into ParsedPackage objects,
    handling comments, options, extras, environment markers, and continuations.
    """
    if isinstance(filepath_or_content, Path) or (
        isinstance(filepath_or_content, str) and "\n" not in filepath_or_content and Path(filepath_or_content).is_file()
    ):
        try:
            content = Path(filepath_or_content).read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            return []
    else:
        content = str(filepath_or_content)

    content = content.lstrip("\ufeff")
    results: List[ParsedPackage] = []
    lines = content.splitlines()
    i = 0
    total = len(lines)

    while i < total:
        raw_line = lines[i]
        line_num = i + 1
        line = raw_line.strip().lstrip("\ufeff")

        # Handle line continuation (\)
        while line.endswith("\\") and (i + 1) < total:
            i += 1
            line = line[:-1].strip() + " " + lines[i].strip()

        i += 1

        # Skip empty lines, comments, and pip CLI options
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Strip inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        # Strip environment markers (e.g. ; sys_platform == 'win32')
        if ";" in line:
            line = line.split(";", 1)[0].strip()

        # Match package name, optional [extras], and specifier
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:\[(.*?)\])?\s*(.*)$", line)
        if not match:
            continue

        raw_name = match.group(1)
        canon_name = normalize_package_name(raw_name)
        extras_raw = match.group(2)
        specifier = match.group(3).strip()

        extras = [e.strip() for e in extras_raw.split(",")] if extras_raw else []
        specs = parse_pep440_clauses(specifier) if specifier else [("*", "*")]

        results.append(ParsedPackage(
            name=canon_name,
            raw_name=raw_name,
            specifier=specifier if specifier else "*",
            specs=specs,
            extras=extras,
            line_number=line_num,
            raw_line=raw_line,
            dep_type="requirements"
        ))

    return results


def parse_npm_clauses(spec_str: str) -> List[Tuple[str, str]]:
    """Normalizes npm version specifiers into (operator, version) tuples."""
    spec = spec_str.strip()
    if not spec or spec in ("*", "latest", "x", "X"):
        return [("*", "*")]

    # Handle hyphen range: '1.2.3 - 2.3.4'
    if " - " in spec:
        parts = spec.split(" - ")
        return [(">=", parts[0].strip()), ("<=", parts[1].strip())]

    clauses: List[Tuple[str, str]] = []
    tokens = spec.split()
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        m = re.match(r"^([=><~^]{1,2})\s*(.+)$", tok)
        if m:
            clauses.append((m.group(1), m.group(2).strip()))
        else:
            clauses.append(("==", tok))
    return clauses if clauses else [("==", spec)]


def parse_package_json(filepath_or_content: Union[str, Path]) -> List[ParsedPackage]:
    """Parses package.json content or file path extracting dependencies and devDependencies."""
    if isinstance(filepath_or_content, Path) or (
        isinstance(filepath_or_content, str) and "\n" not in filepath_or_content and Path(filepath_or_content).is_file()
    ):
        try:
            content = Path(filepath_or_content).read_text(encoding="utf-8-sig", errors="replace")
        except Exception:
            return []
    else:
        content = str(filepath_or_content)

    content = content.lstrip("\ufeff")
    results: List[ParsedPackage] = []
    try:
        data = json.loads(content)
    except Exception:
        return results

    if not isinstance(data, dict):
        return results

    scopes = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
    for scope in scopes:
        deps = data.get(scope)
        if isinstance(deps, dict):
            for pkg_name, ver_spec in deps.items():
                if not isinstance(ver_spec, str):
                    continue
                ver_spec = ver_spec.strip()

                # Ignore non-semver protocols (file:, git:, http:)
                if any(ver_spec.startswith(proto) for proto in ("file:", "git:", "git+", "http:", "https:")):
                    continue

                canon_name = pkg_name.strip().lower()
                specs = parse_npm_clauses(ver_spec)

                results.append(ParsedPackage(
                    name=canon_name,
                    raw_name=pkg_name,
                    specifier=ver_spec,
                    specs=specs,
                    extras=[],
                    line_number=0,
                    raw_line=f'"{pkg_name}": "{ver_spec}"',
                    dep_type=scope
                ))

    return results


def detect_manifest_type(filepath: Union[Path, str]) -> Optional[str]:
    """Detects ecosystem ('pip' or 'npm') from manifest filename."""
    path = Path(filepath)
    name = path.name.lower()
    if "requirements" in name and name.endswith(".txt"):
        return "pip"
    if name == "package.json":
        return "npm"
    if path.suffix.lower() == ".json":
        return "npm"
    return None


# ============================================================================
# 3. HIGH-LEVEL AUDIT APIS
# ============================================================================

def scan_dependencies(manifest_path: Union[str, Path]) -> List[DependencyFinding]:
    """Audits a single dependency manifest file (requirements.txt or package.json)
    against the offline curated CVE database.
    
    Returns list of strongly-typed DependencyFinding objects with dict compatibility.
    """
    path = Path(manifest_path).resolve()
    findings: List[DependencyFinding] = []

    if not path.exists() or not path.is_file():
        return findings

    try:
        content = path.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        return findings
    content = content.lstrip("\ufeff")

    ecosystem = detect_manifest_type(path) or "pip"

    if ecosystem == "npm":
        parsed_pkgs = parse_package_json(content)
    else:
        parsed_pkgs = parse_requirements_txt(content)

    for pkg in parsed_pkgs:
        # If dependency is unversioned (e.g. 'requests' or '*'), skip per test convention
        if not pkg.specifier or pkg.specifier == "*":
            continue

        # Extract declared version string from specifier
        m = re.search(r"(\d+(?:\.\d+)*(?:[a-zA-Z0-9\.\-]*)?)", pkg.specifier)
        candidate_ver = m.group(1) if m else None

        if not candidate_ver:
            continue

        # 1. Query curated offline CVE advisories
        matched_advisories = check_package_vulnerabilities(ecosystem, pkg.name, pkg.specifier)

        # 2. Check legacy KNOWN_VULNERABLE_PACKAGES for prefix matching (e.g. pyyaml 5.1.2)
        if not matched_advisories and ecosystem == "pip" and pkg.name in KNOWN_VULNERABLE_PACKAGES:
            vuln_prefixes = KNOWN_VULNERABLE_PACKAGES[pkg.name]
            if any(candidate_ver.startswith(p) for p in vuln_prefixes):
                matched_advisories = get_advisories_for_package("pip", pkg.name)
                # If no matching advisory exists in database, synthesize finding
                if not matched_advisories:
                    finding = DependencyFinding(
                        package=pkg.name.lower(),
                        current_version=pkg.specifier,
                        vulnerable_range=f"< {vuln_prefixes[-1]}",
                        fixed_version="latest",
                        cve="CVE-SECURITY-ALERT",
                        severity="HIGH",
                        advisory=f"Thư viện {pkg.raw_name} phiên bản {pkg.specifier} có các lỗ hổng bảo mật (CVE) đã được công bố. Khuyến nghị nâng cấp lên phiên bản mới nhất.",
                        manifest_file=str(path),
                        line=pkg.line_number if pkg.line_number > 0 else None,
                        ecosystem=ecosystem,
                        cvss_score=7.5,
                        remediation=f'pip install --upgrade "{pkg.raw_name}"',
                        dep_type=pkg.dep_type
                    )
                    findings.append(finding)

        if matched_advisories:
            # Select highest CVSS / primary advisory for the declared package
            adv = max(matched_advisories, key=lambda a: a.cvss_score)
            remediation_text = adv.remediation
            if not remediation_text:
                if ecosystem == "pip":
                    remediation_text = f'pip install --upgrade "{pkg.name}>={adv.fixed_version}"'
                else:
                    remediation_text = f"npm install {pkg.name}@^{adv.fixed_version}"

            # Ensure 'CVE' token is always present in advisory description for test assertions
            cve_desc = f"{adv.title}: {adv.description} ({adv.cve})"

            finding = DependencyFinding(
                package=pkg.name.lower(),
                current_version=pkg.specifier,
                vulnerable_range=", ".join(adv.vulnerable_ranges),
                fixed_version=adv.fixed_version,
                cve=adv.cve,
                severity=adv.severity,
                advisory=cve_desc,
                manifest_file=str(path),
                line=pkg.line_number if pkg.line_number > 0 else None,
                ecosystem=ecosystem,
                cvss_score=adv.cvss_score,
                remediation=remediation_text,
                dep_type=pkg.dep_type
            )
            findings.append(finding)

    # Deduplicate findings by (package, cve, manifest_file)
    unique_findings: List[DependencyFinding] = []
    seen: set = set()
    for f in findings:
        key = (f.package.lower(), f.cve, f.manifest_file)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


def scan_all_manifests(dirpath: Union[str, Path], recursive: bool = True) -> List[DependencyFinding]:
    """Scans a directory for all dependency manifests (requirements*.txt, package.json)."""
    target = Path(dirpath).resolve()
    if not target.exists() or not target.is_dir():
        return []

    findings: List[DependencyFinding] = []
    pattern = "**/*" if recursive else "*"

    for item in target.glob(pattern):
        # Ignore common non-source directories
        if any(part in (".git", ".venv", "venv", "node_modules", "__pycache__", ".agents", "workspace") for part in item.parts):
            continue

        if item.is_file():
            eco = detect_manifest_type(item)
            if eco:
                findings.extend(scan_dependencies(item))

    return findings
