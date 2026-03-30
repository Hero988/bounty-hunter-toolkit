#!/usr/bin/env python3
"""
OData $metadata Security Analyzer
==================================
Parses OData $metadata XML (v2 and v4) and produces a security-focused
analysis including writable fields, IDOR candidates, PII exposure,
sensitive fields, and auto-generated curl test commands.

Usage:
    python odata_analyzer.py <metadata-url-or-file> [output-dir]
        --cookies <cookie-file>
        --header "Name: Value"
"""

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse

try:
    import urllib.request
    import urllib.error
    import ssl
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

# ---------------------------------------------------------------------------
# OData namespace mappings
# ---------------------------------------------------------------------------
NAMESPACES = {
    # EDMX wrappers
    "edmx_v2": "http://schemas.microsoft.com/ado/2007/06/edmx",
    "edmx_v4": "http://docs.oasis-open.org/odata/ns/edmx",
    # EDM schemas
    "edm_v2": "http://schemas.microsoft.com/ado/2008/09/edm",
    "edm_v4": "http://docs.oasis-open.org/odata/ns/edm",
    # SAP annotations
    "sap": "http://www.sap.com/Protocols/SAPData",
}

# Additional EDM namespaces seen in the wild (v1, v1.1, v3, etc.)
EXTRA_EDM_NAMESPACES = [
    "http://schemas.microsoft.com/ado/2006/04/edm",
    "http://schemas.microsoft.com/ado/2007/05/edm",
    "http://schemas.microsoft.com/ado/2009/11/edm",
]

# Regex patterns for security-relevant field names
PII_PATTERNS = [
    re.compile(r"e[-_]?mail", re.I),
    re.compile(r"phone", re.I),
    re.compile(r"ssn|social.?sec", re.I),
    re.compile(r"address|street|city|zip|postal", re.I),
    re.compile(r"(first|last|full|display|user)[-_.]?name", re.I),
    re.compile(r"birth[-_.]?date|date[-_.]?of[-_.]?birth|dob", re.I),
    re.compile(r"national[-_.]?id|passport|driver.?lic", re.I),
    re.compile(r"tax[-_.]?id|tin\b", re.I),
    re.compile(r"gender|sex\b", re.I),
    re.compile(r"salary|wage|income|compensation", re.I),
]

SENSITIVE_PATTERNS = [
    re.compile(r"password|passwd|pwd\b", re.I),
    re.compile(r"token", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"\bapi[-_.]?key\b", re.I),
    re.compile(r"\bkey\b", re.I),
    re.compile(r"auth", re.I),
    re.compile(r"credential", re.I),
    re.compile(r"session[-_.]?id", re.I),
    re.compile(r"private", re.I),
    re.compile(r"cookie", re.I),
    re.compile(r"jwt\b", re.I),
    re.compile(r"bearer", re.I),
    re.compile(r"oauth", re.I),
    re.compile(r"refresh[-_.]?token", re.I),
    re.compile(r"access[-_.]?token", re.I),
]

XSS_PAYLOAD = '<script>alert("XSS")</script>'

# Text-like EDM types that could carry XSS payloads
TEXT_TYPES = {
    "edm.string", "string",
    "edm.binary", "binary",
    "edm.stream", "stream",
}

# ---------------------------------------------------------------------------
# Fetching / reading metadata
# ---------------------------------------------------------------------------

def fetch_metadata(source, cookies_file=None, headers=None):
    """Fetch $metadata from a URL or read from a local file."""
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        return _fetch_from_url(source, cookies_file, headers)
    else:
        return _read_from_file(source)


def _read_from_file(path):
    """Read metadata XML from a local file."""
    real_path = os.path.expanduser(path)
    if not os.path.isfile(real_path):
        print(f"[!] File not found: {real_path}", file=sys.stderr)
        sys.exit(1)
    with open(real_path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _fetch_from_url(url, cookies_file=None, headers=None):
    """Fetch metadata XML from an HTTP(S) URL."""
    if not HAS_URLLIB:
        print("[!] urllib is not available.", file=sys.stderr)
        sys.exit(1)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url)
    req.add_header("Accept", "application/xml")
    req.add_header("User-Agent", "ODataAnalyzer/1.0")

    if cookies_file:
        cookie_path = os.path.expanduser(cookies_file)
        if os.path.isfile(cookie_path):
            with open(cookie_path, "r") as cf:
                cookie_val = cf.read().strip()
            req.add_header("Cookie", cookie_val)
        else:
            print(f"[!] Cookie file not found: {cookie_path}", file=sys.stderr)

    if headers:
        for h in headers:
            if ":" in h:
                name, value = h.split(":", 1)
                req.add_header(name.strip(), value.strip())

    try:
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        data = resp.read()
        return data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        print(f"[!] HTTP {exc.code}: {exc.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"[!] URL error: {exc.reason}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Fetch error: {exc}", file=sys.stderr)
        sys.exit(1)

# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _detect_namespaces(xml_text):
    """Detect which EDM namespace is in use and return (edmx_ns, edm_ns)."""
    edmx_ns = None
    edm_ns = None

    if NAMESPACES["edmx_v4"] in xml_text:
        edmx_ns = NAMESPACES["edmx_v4"]
    elif NAMESPACES["edmx_v2"] in xml_text:
        edmx_ns = NAMESPACES["edmx_v2"]

    if NAMESPACES["edm_v4"] in xml_text:
        edm_ns = NAMESPACES["edm_v4"]
    elif NAMESPACES["edm_v2"] in xml_text:
        edm_ns = NAMESPACES["edm_v2"]
    else:
        for ns in EXTRA_EDM_NAMESPACES:
            if ns in xml_text:
                edm_ns = ns
                break

    return edmx_ns, edm_ns


def _tag(ns, local):
    """Build a namespaced tag string for ElementTree."""
    if ns:
        return f"{{{ns}}}{local}"
    return local


def _sap_attr(attr_name):
    """Build a SAP-annotated attribute name."""
    return f"{{{NAMESPACES['sap']}}}{attr_name}"

# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

class ODataMetadataParser:
    """Parses OData $metadata XML into structured data."""

    def __init__(self, xml_text):
        self.xml_text = xml_text
        self.edmx_ns, self.edm_ns = _detect_namespaces(xml_text)
        self.root = ET.fromstring(xml_text)

        self.entity_types = []       # list of dicts
        self.entity_sets = []        # list of dicts
        self.nav_properties = []     # list of dicts
        self.function_imports = []   # list of dicts
        self.association_sets = []   # list of dicts
        self.complex_types = []      # list of dicts
        self.schemas = []            # namespace strings

        self._odata_version = "unknown"
        if self.edm_ns and "oasis" in self.edm_ns:
            self._odata_version = "v4"
        elif self.edm_ns:
            self._odata_version = "v2/v3"

    # ---- public API -------------------------------------------------------

    def parse(self):
        """Run the full parse."""
        schemas = self._find_schemas()
        for schema_el, schema_ns in schemas:
            self.schemas.append(schema_ns)
            self._parse_entity_types(schema_el, schema_ns)
            self._parse_complex_types(schema_el, schema_ns)
            self._parse_entity_containers(schema_el, schema_ns)
            self._parse_associations(schema_el, schema_ns)

    # ---- internals --------------------------------------------------------

    def _find_schemas(self):
        """Locate all Schema elements regardless of namespace nesting."""
        results = []
        edm_ns = self.edm_ns

        # Try direct path: Edmx > DataServices > Schema
        if self.edmx_ns:
            ds_tag = _tag(self.edmx_ns, "DataServices")
            for ds in self.root.iter(ds_tag):
                if edm_ns:
                    for schema in ds.iter(_tag(edm_ns, "Schema")):
                        ns = schema.attrib.get("Namespace", "")
                        results.append((schema, ns))
        # Fallback: search entire tree for Schema in known namespaces
        if not results:
            all_edm = [self.edm_ns] if self.edm_ns else []
            all_edm += [NAMESPACES["edm_v2"], NAMESPACES["edm_v4"]] + EXTRA_EDM_NAMESPACES
            seen = set()
            for ns in all_edm:
                if not ns or ns in seen:
                    continue
                seen.add(ns)
                for schema in self.root.iter(_tag(ns, "Schema")):
                    sns = schema.attrib.get("Namespace", "")
                    results.append((schema, sns))
                    if not self.edm_ns:
                        self.edm_ns = ns
        return results

    def _parse_entity_types(self, schema_el, schema_ns):
        """Parse EntityType elements."""
        edm = self.edm_ns
        for et in schema_el.findall(_tag(edm, "EntityType")):
            et_name = et.attrib.get("Name", "")
            full_name = f"{schema_ns}.{et_name}" if schema_ns else et_name

            # Keys
            keys = []
            key_el = et.find(_tag(edm, "Key"))
            if key_el is not None:
                for pr in key_el.findall(_tag(edm, "PropertyRef")):
                    keys.append(pr.attrib.get("Name", ""))

            # Properties
            properties = []
            for prop in et.findall(_tag(edm, "Property")):
                p = self._parse_property(prop)
                p["is_key"] = p["name"] in keys
                properties.append(p)

            # Navigation properties
            navs = []
            for nav in et.findall(_tag(edm, "NavigationProperty")):
                nav_info = {
                    "name": nav.attrib.get("Name", ""),
                    "relationship": nav.attrib.get("Relationship", ""),
                    "from_role": nav.attrib.get("FromRole", ""),
                    "to_role": nav.attrib.get("ToRole", ""),
                    # v4 uses Type attribute
                    "type": nav.attrib.get("Type", ""),
                    "partner": nav.attrib.get("Partner", ""),
                    "entity_type": full_name,
                }
                navs.append(nav_info)
                self.nav_properties.append(nav_info)

            self.entity_types.append({
                "name": et_name,
                "full_name": full_name,
                "keys": keys,
                "properties": properties,
                "navigation_properties": navs,
                "base_type": et.attrib.get("BaseType", ""),
                "abstract": et.attrib.get("Abstract", "false").lower() == "true",
            })

    def _parse_property(self, prop_el):
        """Parse a single Property element."""
        sap = NAMESPACES["sap"]
        name = prop_el.attrib.get("Name", "")
        edm_type = prop_el.attrib.get("Type", "")
        max_len = prop_el.attrib.get("MaxLength", "")
        nullable = prop_el.attrib.get("Nullable", "true")
        creatable = prop_el.attrib.get(_sap_attr("creatable"), "")
        updatable = prop_el.attrib.get(_sap_attr("updatable"), "")
        label = prop_el.attrib.get(_sap_attr("label"), "")
        filterable = prop_el.attrib.get(_sap_attr("filterable"), "")
        sortable = prop_el.attrib.get(_sap_attr("sortable"), "")

        return {
            "name": name,
            "type": edm_type,
            "max_length": max_len,
            "nullable": nullable,
            "creatable": creatable,
            "updatable": updatable,
            "label": label,
            "filterable": filterable,
            "sortable": sortable,
            "is_key": False,
        }

    def _parse_complex_types(self, schema_el, schema_ns):
        """Parse ComplexType elements."""
        edm = self.edm_ns
        for ct in schema_el.findall(_tag(edm, "ComplexType")):
            ct_name = ct.attrib.get("Name", "")
            props = []
            for prop in ct.findall(_tag(edm, "Property")):
                props.append(self._parse_property(prop))
            self.complex_types.append({
                "name": ct_name,
                "full_name": f"{schema_ns}.{ct_name}" if schema_ns else ct_name,
                "properties": props,
            })

    def _parse_entity_containers(self, schema_el, schema_ns):
        """Parse EntityContainer elements (EntitySets, FunctionImports)."""
        edm = self.edm_ns
        for ec in schema_el.findall(_tag(edm, "EntityContainer")):
            container_name = ec.attrib.get("Name", "")

            # EntitySets
            for es in ec.findall(_tag(edm, "EntitySet")):
                self.entity_sets.append({
                    "name": es.attrib.get("Name", ""),
                    "entity_type": es.attrib.get("EntityType", ""),
                    "container": container_name,
                    "creatable": es.attrib.get(_sap_attr("creatable"), ""),
                    "updatable": es.attrib.get(_sap_attr("updatable"), ""),
                    "deletable": es.attrib.get(_sap_attr("deletable"), ""),
                    "pageable": es.attrib.get(_sap_attr("pageable"), ""),
                    "content_version": es.attrib.get(_sap_attr("content-version"), ""),
                })

            # FunctionImports
            for fi in ec.findall(_tag(edm, "FunctionImport")):
                params = []
                for p in fi.findall(_tag(edm, "Parameter")):
                    params.append({
                        "name": p.attrib.get("Name", ""),
                        "type": p.attrib.get("Type", ""),
                        "mode": p.attrib.get("Mode", ""),
                        "nullable": p.attrib.get("Nullable", "true"),
                        "max_length": p.attrib.get("MaxLength", ""),
                    })
                self.function_imports.append({
                    "name": fi.attrib.get("Name", ""),
                    "return_type": fi.attrib.get("ReturnType", ""),
                    "entity_set": fi.attrib.get("EntitySet", ""),
                    "http_method": fi.attrib.get("m:HttpMethod",
                                     fi.attrib.get("HttpMethod", "")),
                    "parameters": params,
                    "container": container_name,
                })

    def _parse_associations(self, schema_el, schema_ns):
        """Parse Association and AssociationSet elements (v2/v3)."""
        edm = self.edm_ns

        # Associations (for reference)
        associations = {}
        for assoc in schema_el.findall(_tag(edm, "Association")):
            a_name = assoc.attrib.get("Name", "")
            ends = []
            for end in assoc.findall(_tag(edm, "End")):
                ends.append({
                    "type": end.attrib.get("Type", ""),
                    "multiplicity": end.attrib.get("Multiplicity", ""),
                    "role": end.attrib.get("Role", ""),
                })
            associations[a_name] = ends

        # AssociationSets (inside EntityContainer)
        for ec in schema_el.findall(_tag(edm, "EntityContainer")):
            for as_el in ec.findall(_tag(edm, "AssociationSet")):
                as_name = as_el.attrib.get("Name", "")
                as_assoc = as_el.attrib.get("Association", "")
                ends = []
                for end in as_el.findall(_tag(edm, "End")):
                    ends.append({
                        "entity_set": end.attrib.get("EntitySet", ""),
                        "role": end.attrib.get("Role", ""),
                    })
                self.association_sets.append({
                    "name": as_name,
                    "association": as_assoc,
                    "ends": ends,
                })

    # ---- result accessors -------------------------------------------------

    def get_results(self):
        return {
            "odata_version": self._odata_version,
            "schemas": self.schemas,
            "entity_types": self.entity_types,
            "entity_sets": self.entity_sets,
            "navigation_properties": self.nav_properties,
            "function_imports": self.function_imports,
            "association_sets": self.association_sets,
            "complex_types": self.complex_types,
        }

# ---------------------------------------------------------------------------
# Security analysis
# ---------------------------------------------------------------------------

class SecurityAnalyzer:
    """Performs security-focused analysis on parsed OData metadata."""

    def __init__(self, parsed):
        self.parsed = parsed
        self.xss_candidates = []
        self.idor_candidates = []
        self.pii_fields = []
        self.sensitive_fields = []

    def analyze(self):
        self._find_xss_candidates()
        self._find_idor_candidates()
        self._find_pii_fields()
        self._find_sensitive_fields()

    def _is_text_type(self, edm_type):
        return edm_type.lower().replace(" ", "") in TEXT_TYPES

    def _find_xss_candidates(self):
        """Writable text fields are XSS injection candidates."""
        for et in self.parsed["entity_types"]:
            for prop in et["properties"]:
                if not self._is_text_type(prop["type"]):
                    continue
                # Consider writable if creatable/updatable is not explicitly false
                creatable = prop.get("creatable", "").lower() != "false"
                updatable = prop.get("updatable", "").lower() != "false"
                if creatable or updatable:
                    self.xss_candidates.append({
                        "entity_type": et["full_name"],
                        "property": prop["name"],
                        "type": prop["type"],
                        "max_length": prop["max_length"],
                        "creatable": creatable,
                        "updatable": updatable,
                    })

    def _find_idor_candidates(self):
        """Entity keys are IDOR testing candidates."""
        for et in self.parsed["entity_types"]:
            if not et["keys"]:
                continue
            key_props = [p for p in et["properties"] if p["is_key"]]
            # Find matching entity set
            matching_sets = [
                es["name"] for es in self.parsed["entity_sets"]
                if et["full_name"] in es.get("entity_type", "")
                   or et["name"] in es.get("entity_type", "")
            ]
            self.idor_candidates.append({
                "entity_type": et["full_name"],
                "keys": [{"name": k["name"], "type": k["type"]} for k in key_props],
                "entity_sets": matching_sets,
            })

    def _find_pii_fields(self):
        """Identify PII fields by name patterns."""
        for et in self.parsed["entity_types"]:
            for prop in et["properties"]:
                for pat in PII_PATTERNS:
                    if pat.search(prop["name"]):
                        self.pii_fields.append({
                            "entity_type": et["full_name"],
                            "property": prop["name"],
                            "type": prop["type"],
                            "pattern_matched": pat.pattern,
                        })
                        break

    def _find_sensitive_fields(self):
        """Identify sensitive fields (passwords, tokens, secrets)."""
        for et in self.parsed["entity_types"]:
            for prop in et["properties"]:
                for pat in SENSITIVE_PATTERNS:
                    if pat.search(prop["name"]):
                        self.sensitive_fields.append({
                            "entity_type": et["full_name"],
                            "property": prop["name"],
                            "type": prop["type"],
                            "pattern_matched": pat.pattern,
                        })
                        break

    def get_results(self):
        return {
            "xss_candidates": self.xss_candidates,
            "idor_candidates": self.idor_candidates,
            "pii_fields": self.pii_fields,
            "sensitive_fields": self.sensitive_fields,
            "summary": {
                "xss_candidate_count": len(self.xss_candidates),
                "idor_candidate_count": len(self.idor_candidates),
                "pii_field_count": len(self.pii_fields),
                "sensitive_field_count": len(self.sensitive_fields),
            },
        }

# ---------------------------------------------------------------------------
# Test command generation
# ---------------------------------------------------------------------------

def generate_test_commands(base_url, parsed, security, cookies_file=None, custom_headers=None):
    """Generate curl commands for testing each entity."""
    lines = [
        "#!/usr/bin/env bash",
        "# OData Security Test Commands",
        f"# Generated: {datetime.now().isoformat()}",
        f"# Target: {base_url}",
        "#",
        "# WARNING: These commands are for authorized penetration testing ONLY.",
        "# Ensure you have proper authorization before running any of these commands.",
        "",
        f'BASE_URL="{base_url}"',
        "",
    ]

    # Build common curl flags
    curl_extras = []
    if cookies_file:
        curl_extras.append(f'-b "{cookies_file}"')
    if custom_headers:
        for h in custom_headers:
            curl_extras.append(f'-H "{h}"')
    extra_str = " ".join(curl_extras)
    if extra_str:
        extra_str = " " + extra_str

    # Derive service root from metadata URL
    service_root = base_url
    if "$metadata" in service_root:
        service_root = service_root.split("$metadata")[0].rstrip("/")

    lines.append(f'SERVICE_ROOT="{service_root}"')
    lines.append("")

    # --- READ tests for each EntitySet ---
    lines.append("# " + "=" * 70)
    lines.append("# READ tests (GET requests)")
    lines.append("# " + "=" * 70)
    lines.append("")

    for es in parsed["entity_sets"]:
        es_name = es["name"]
        lines.append(f"# --- EntitySet: {es_name} ---")
        # Basic read
        lines.append(f'echo "[*] Reading {es_name}..."')
        lines.append(
            f'curl -sk -o /dev/null -w "%{{http_code}}" '
            f'"$SERVICE_ROOT/{es_name}?$top=1&$format=json"{extra_str}'
        )
        lines.append("")

        # Read with $select to probe individual properties
        et_match = _find_entity_type(parsed, es.get("entity_type", ""))
        if et_match:
            key_parts = []
            for k in et_match["keys"]:
                kp = [p for p in et_match["properties"] if p["name"] == k]
                ktype = kp[0]["type"] if kp else "Edm.String"
                if "int" in ktype.lower() or "decimal" in ktype.lower():
                    key_parts.append(f"{k}=1")
                elif "guid" in ktype.lower():
                    key_parts.append(f"{k}=guid'00000000-0000-0000-0000-000000000001'")
                else:
                    key_parts.append(f"{k}='TESTID1'")
            key_str = ",".join(key_parts)
            if key_str:
                lines.append(f"# Single entity read (IDOR test - vary the key values)")
                lines.append(
                    f'curl -sk "$SERVICE_ROOT/{es_name}({key_str})?$format=json"{extra_str}'
                )
                lines.append("")

    # --- WRITE tests (XSS payloads) ---
    lines.append("")
    lines.append("# " + "=" * 70)
    lines.append("# WRITE tests (POST/PUT with XSS payloads)")
    lines.append("# " + "=" * 70)
    lines.append("")

    # Group XSS candidates by entity type
    xss_by_entity = {}
    for xss in security.get("xss_candidates", []):
        et_name = xss["entity_type"]
        xss_by_entity.setdefault(et_name, []).append(xss)

    for et_full_name, xss_list in xss_by_entity.items():
        # Find matching entity set
        matching_sets = [
            es["name"] for es in parsed["entity_sets"]
            if et_full_name in es.get("entity_type", "")
               or et_full_name.split(".")[-1] in es.get("entity_type", "")
        ]
        if not matching_sets:
            continue
        es_name = matching_sets[0]

        # Build JSON payload with XSS in text fields
        payload_parts = []
        for xss in xss_list:
            escaped_payload = XSS_PAYLOAD.replace('"', '\\"')
            payload_parts.append(f'    "{xss["property"]}": "{escaped_payload}"')

        payload_json = "{\n" + ",\n".join(payload_parts) + "\n}"

        lines.append(f"# --- XSS test for {es_name} ({et_full_name}) ---")
        lines.append(f"# Writable text fields: {', '.join(x['property'] for x in xss_list)}")
        lines.append(
            f"curl -sk -X POST \"$SERVICE_ROOT/{es_name}\" "
            f"-H \"Content-Type: application/json\" "
            f"-d '{payload_json}'{extra_str}"
        )
        lines.append("")

    # --- FunctionImport tests ---
    if parsed["function_imports"]:
        lines.append("")
        lines.append("# " + "=" * 70)
        lines.append("# FunctionImport tests")
        lines.append("# " + "=" * 70)
        lines.append("")
        for fi in parsed["function_imports"]:
            fi_name = fi["name"]
            method = fi.get("http_method", "GET").upper() or "GET"
            params_str = ""
            if fi["parameters"]:
                param_parts = []
                for p in fi["parameters"]:
                    ptype = p["type"].lower()
                    if "int" in ptype or "decimal" in ptype:
                        param_parts.append(f"{p['name']}=1")
                    elif "bool" in ptype:
                        param_parts.append(f"{p['name']}=true")
                    else:
                        param_parts.append(f"{p['name']}='test'")
                params_str = "?" + "&".join(param_parts)

            lines.append(f"# FunctionImport: {fi_name} ({method})")
            if method == "GET":
                lines.append(
                    f'curl -sk "$SERVICE_ROOT/{fi_name}{params_str}&$format=json"{extra_str}'
                )
            else:
                lines.append(
                    f'curl -sk -X {method} "$SERVICE_ROOT/{fi_name}{params_str}"{extra_str}'
                )
            lines.append("")

    return "\n".join(lines)


def _find_entity_type(parsed, type_name):
    """Find an EntityType dict by full or short name."""
    for et in parsed["entity_types"]:
        if et["full_name"] == type_name or et["name"] == type_name:
            return et
        # Handle namespace-qualified names (e.g., "NAMESPACE.TypeName")
        if type_name.endswith("." + et["name"]):
            return et
    return None

# ---------------------------------------------------------------------------
# Pretty-print summary
# ---------------------------------------------------------------------------

def print_summary(parsed, security):
    """Print a human-readable summary to stdout."""
    hr = "=" * 74

    print()
    print(hr)
    print("  OData $metadata Security Analysis")
    print(hr)
    print(f"  OData version detected : {parsed['odata_version']}")
    print(f"  Schema namespaces      : {', '.join(parsed['schemas']) or 'N/A'}")
    print(f"  Entity types           : {len(parsed['entity_types'])}")
    print(f"  Entity sets            : {len(parsed['entity_sets'])}")
    print(f"  Navigation properties  : {len(parsed['navigation_properties'])}")
    print(f"  Function imports       : {len(parsed['function_imports'])}")
    print(f"  Association sets       : {len(parsed['association_sets'])}")
    print(f"  Complex types          : {len(parsed['complex_types'])}")
    print(hr)
    print()

    # --- Entity Types ---
    print("[+] ENTITY TYPES")
    print("-" * 74)
    for et in parsed["entity_types"]:
        key_str = ", ".join(et["keys"]) if et["keys"] else "(none)"
        abstract_str = " [ABSTRACT]" if et.get("abstract") else ""
        base_str = f" extends {et['base_type']}" if et.get("base_type") else ""
        print(f"\n  {et['full_name']}{abstract_str}{base_str}")
        print(f"  Keys: {key_str}")
        print(f"  {'Property':<35} {'Type':<20} {'MaxLen':<8} {'Null':<6} {'C':<4} {'U':<4}")
        print(f"  {'-'*35} {'-'*20} {'-'*8} {'-'*6} {'-'*4} {'-'*4}")
        for p in et["properties"]:
            key_marker = " *" if p["is_key"] else ""
            print(
                f"  {(p['name'] + key_marker):<35} "
                f"{p['type']:<20} "
                f"{p['max_length']:<8} "
                f"{p['nullable']:<6} "
                f"{p['creatable']:<4} "
                f"{p['updatable']:<4}"
            )
    print()

    # --- Entity Sets ---
    print("[+] ENTITY SETS")
    print("-" * 74)
    print(f"  {'EntitySet':<35} {'EntityType':<35}")
    print(f"  {'-'*35} {'-'*35}")
    for es in parsed["entity_sets"]:
        sap_flags = []
        if es.get("creatable"):
            sap_flags.append(f"C={es['creatable']}")
        if es.get("updatable"):
            sap_flags.append(f"U={es['updatable']}")
        if es.get("deletable"):
            sap_flags.append(f"D={es['deletable']}")
        flag_str = f" [{', '.join(sap_flags)}]" if sap_flags else ""
        print(f"  {es['name']:<35} {es['entity_type']:<35}{flag_str}")
    print()

    # --- Navigation Properties ---
    if parsed["navigation_properties"]:
        print("[+] NAVIGATION PROPERTIES")
        print("-" * 74)
        for nav in parsed["navigation_properties"]:
            target = nav.get("type") or nav.get("to_role") or "?"
            print(f"  {nav['entity_type']}.{nav['name']} -> {target}")
        print()

    # --- Function Imports ---
    if parsed["function_imports"]:
        print("[+] FUNCTION IMPORTS")
        print("-" * 74)
        for fi in parsed["function_imports"]:
            params = ", ".join(
                f"{p['name']}:{p['type']}" for p in fi["parameters"]
            )
            ret = fi.get("return_type", "") or fi.get("entity_set", "") or "void"
            method = fi.get("http_method", "") or "?"
            print(f"  {fi['name']}({params}) -> {ret}  [{method}]")
        print()

    # --- Association Sets ---
    if parsed["association_sets"]:
        print("[+] ASSOCIATION SETS")
        print("-" * 74)
        for aset in parsed["association_sets"]:
            ends_str = " <-> ".join(
                f"{e.get('entity_set', '?')} ({e.get('role', '?')})"
                for e in aset["ends"]
            )
            print(f"  {aset['name']}: {ends_str}")
        print()

    # --- Security analysis ---
    sec = security
    print(hr)
    print("  SECURITY ANALYSIS")
    print(hr)

    # XSS candidates
    print(f"\n[!] XSS INJECTION CANDIDATES ({sec['summary']['xss_candidate_count']} writable text fields)")
    print("-" * 74)
    if sec["xss_candidates"]:
        for xss in sec["xss_candidates"]:
            ml = f" (maxLen={xss['max_length']})" if xss["max_length"] else ""
            print(f"  {xss['entity_type']}.{xss['property']}{ml}")
    else:
        print("  (none found)")

    # IDOR candidates
    print(f"\n[!] IDOR CANDIDATES ({sec['summary']['idor_candidate_count']} entity types with keys)")
    print("-" * 74)
    if sec["idor_candidates"]:
        for idor in sec["idor_candidates"]:
            keys = ", ".join(f"{k['name']} ({k['type']})" for k in idor["keys"])
            sets = ", ".join(idor["entity_sets"]) if idor["entity_sets"] else "(no set)"
            print(f"  {idor['entity_type']}  keys=[{keys}]  sets=[{sets}]")
    else:
        print("  (none found)")

    # PII fields
    print(f"\n[!] PII FIELDS ({sec['summary']['pii_field_count']} matches)")
    print("-" * 74)
    if sec["pii_fields"]:
        for pii in sec["pii_fields"]:
            print(f"  {pii['entity_type']}.{pii['property']}  ({pii['type']})")
    else:
        print("  (none found)")

    # Sensitive fields
    print(f"\n[!] SENSITIVE FIELDS ({sec['summary']['sensitive_field_count']} matches)")
    print("-" * 74)
    if sec["sensitive_fields"]:
        for sf in sec["sensitive_fields"]:
            print(f"  {sf['entity_type']}.{sf['property']}  ({sf['type']})")
    else:
        print("  (none found)")

    print()
    print(hr)

# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def save_json(output_dir, parsed, security, source):
    """Save detailed JSON analysis."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "odata-analysis.json")
    result = {
        "meta": {
            "source": source,
            "analyzed_at": datetime.now().isoformat(),
            "tool": "odata_analyzer.py",
        },
        "metadata": parsed,
        "security": security,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=str)
    print(f"[+] JSON analysis saved to: {out_path}")
    return out_path


def save_test_commands(output_dir, commands_text):
    """Save test commands shell script."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, "odata-test-commands.sh")
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(commands_text)
    # Try to make executable on Unix-like systems
    try:
        os.chmod(out_path, 0o755)
    except OSError:
        pass
    print(f"[+] Test commands saved to: {out_path}")
    return out_path

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="OData $metadata Security Analyzer - "
                    "Parse OData metadata and generate security test artifacts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python odata_analyzer.py https://example.com/odata/$metadata
  python odata_analyzer.py metadata.xml ./output
  python odata_analyzer.py https://sap.example.com/sap/opu/odata/sap/API_SVC/$metadata \\
      --cookies cookies.txt --header "X-CSRF-Token: Fetch"
        """,
    )
    parser.add_argument(
        "source",
        help="URL to OData $metadata endpoint or path to local XML file",
    )
    parser.add_argument(
        "output_dir",
        nargs="?",
        default=".",
        help="Directory for output files (default: current directory)",
    )
    parser.add_argument(
        "--cookies",
        metavar="FILE",
        help="Path to cookie file for authenticated requests",
    )
    parser.add_argument(
        "--header",
        action="append",
        metavar='"Name: Value"',
        dest="headers",
        help="Custom HTTP header (can be specified multiple times)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    source = args.source
    output_dir = args.output_dir

    # 1. Fetch / read metadata
    print(f"[*] Loading metadata from: {source}")
    xml_text = fetch_metadata(source, args.cookies, args.headers)
    print(f"[+] Received {len(xml_text)} bytes of XML")

    # 2. Parse metadata
    print("[*] Parsing OData metadata...")
    try:
        odata_parser = ODataMetadataParser(xml_text)
        odata_parser.parse()
    except ET.ParseError as exc:
        print(f"[!] XML parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    parsed = odata_parser.get_results()
    print(f"[+] Parsed {len(parsed['entity_types'])} entity types, "
          f"{len(parsed['entity_sets'])} entity sets, "
          f"{len(parsed['function_imports'])} function imports")

    # 3. Security analysis
    print("[*] Running security analysis...")
    analyzer = SecurityAnalyzer(parsed)
    analyzer.analyze()
    security = analyzer.get_results()

    # 4. Print human-readable summary
    print_summary(parsed, security)

    # 5. Generate test commands
    test_commands = generate_test_commands(
        source, parsed, security, args.cookies, args.headers
    )

    # 6. Save outputs
    print("[*] Saving output files...")
    save_json(output_dir, parsed, security, source)
    save_test_commands(output_dir, test_commands)

    print()
    print("[+] Analysis complete.")


if __name__ == "__main__":
    main()
