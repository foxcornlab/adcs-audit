#!/usr/bin/env python3
"""adcs-audit — Active Directory Certificate Services (AD CS) auditor.

Audits an LDAP export of AD CS PKI objects for known template
misconfiguration classes (ESC1-ESC8 style findings) and reports the
attack paths each one enables. Works fully offline from an LDIF or JSON
export, so it can run against a dump without touching the CA.

Usage:
    adcsaudit.py --offline <path> [--json]
    adcsaudit.py --help
    adcsaudit.py --version

Exit codes:
    0  no findings
    1  findings reported
    2  usage or input error
"""

import argparse
import base64
import json
import re
import sys
import textwrap
from pathlib import Path

__version__ = "1.0.0"

# ---------------------------------------------------------------- constants

LOW_PRIV_NAMES = [
    "Domain Users",
    "Authenticated Users",
    "Everyone",
    "Users",
    "Domain Computers",
]

EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"           # Client Authentication
EKU_ANY_PURPOSE = "2.5.29.37.0"                 # Any Purpose
EKU_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"    # Certificate Request Agent

NAME_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
NAME_FLAG_ENROLLEE_SUPPLIES_NAME = 0x100000
ENROLL_FLAG_MANAGER_APPROVAL = 0x2

# well-known SDDL account abbreviations -> readable names
SDDL_SID_NAMES = {
    "WD": "Everyone",
    "AU": "Authenticated Users",
    "BA": "Administrators",
    "DA": "Domain Admins",
    "EA": "Enterprise Admins",
    "ED": "Enterprise Domain Controllers",
    "BU": "Users",
    "SY": "SYSTEM",
    "CO": "CREATOR OWNER",
}

# domain-relative RIDs inside S-x-y-...-<rid>
RID_NAMES = {
    512: "Domain Admins",
    513: "Domain Users",
    516: "Domain Controllers",
    518: "Schema Admins",
    519: "Enterprise Admins",
}

# extended-right GUIDs plus named tokens accepted in the SDDL object field
GUID_RIGHTS = {
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",
    "a05b8cc2-17bc-4802-a710-e7c15ab858a6": "AutoEnroll",
    "ManageCA": "ManageCA",
    "ManageCertificates": "ManageCertificates",
    "Enroll": "Enroll",
    "AutoEnroll": "AutoEnroll",
}

FINDINGS = []


def find(level, tag, title, detail):
    FINDINGS.append({
        "id": tag,
        "level": level,
        "target": title,
        "detail": " ".join(detail.split()),
    })


class InputError(Exception):
    """Raised for malformed input files."""


# ---------------------------------------------------------------- LDIF parser

def parse_ldif(text):
    """Parse a minimal LDIF stream into a list of entry dicts.

    Each entry is {"dn": str, "attrs": {name: [values]}}. Base64 (::)
    values are decoded; URL (:) values are skipped. Attribute names are
    lower-cased.
    """
    entries = []
    cur = None
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not line:
            if cur:
                entries.append(cur)
                cur = None
            continue
        if line.startswith("#") or line.startswith("version:"):
            continue
        if line.startswith(" ") and cur is not None and cur["attrs"]:
            # continuation of the previous logical line
            last_key = list(cur["attrs"].keys())[-1]
            cur["attrs"][last_key][-1] += line[1:]
            continue
        if line.startswith("dn:") or line.startswith("dn::"):
            cur = {"dn": "", "attrs": {}}
            val = line.split(":", 1)[1]
            if line.startswith("dn::"):
                val = base64.b64decode(val.strip())
            else:
                val = val.strip()
            cur["dn"] = val.decode() if isinstance(val, bytes) else val
            continue
        if cur is None:
            raise InputError("LDIF line outside of an entry: %r" % line)
        if "::" in line and not line.split("::")[0].endswith(":"):
            key, _, val = line.partition("::")
            val = base64.b64decode(val.strip())
        elif "::" in line:
            key, _, val = line.partition("::")
            val = base64.b64decode(val.strip())
        elif ":" in line:
            key, _, val = line.partition(":")
            val = val.strip()
            if val.startswith("<"):
                continue
        else:
            raise InputError("malformed LDIF line: %r" % line)
        key = key.strip().lower()
        if isinstance(val, bytes):
            decoded = None
            for enc in ("utf-8", "utf-16-le"):
                try:
                    decoded = val.decode(enc)
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue
            val = decoded if decoded is not None else val.hex()
        cur["attrs"].setdefault(key, []).append(val)
    if cur:
        entries.append(cur)
    return entries


def parse_json_export(path):
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise InputError("invalid JSON: %s" % exc)
    if isinstance(data, dict) and "entries" in data:
        data = data["entries"]
    if not isinstance(data, list):
        raise InputError("JSON must be an array of objects")
    return data


# ---------------------------------------------------------------- SDDL / ACL

ACE_RE = re.compile(r"\((A|D);([^;]*);([^;]*);([^;]*);([^;]*);([^)]*)\)")

GENERIC_WRITE_BITS = {"GA", "GW", "WD", "WO"}


def sid_to_name(sid):
    """Map a SID (SDDL token or full string) to a readable name."""
    if sid in SDDL_SID_NAMES:
        return SDDL_SID_NAMES[sid]
    if sid.startswith("S-"):
        parts = sid.split("-")
        try:
            rid = int(parts[-1])
        except ValueError:
            return None
        # S-1-5-<auth>-<rid> vs S-1-5-21-<domain>-<rid>
        if len(parts) == 5 and parts[3] == "32":
            return RID_NAMES.get(rid)  # builtin domain RIDs
        if len(parts) >= 5 and parts[3] != "32":
            return RID_NAMES.get(rid)
    return None


def parse_acl(raw):
    """Parse an SDDL string into ACE dicts with a normalized right set."""
    if not isinstance(raw, str) or "(" not in raw:
        return []
    aces = []
    for m in ACE_RE.finditer(raw):
        ace_type, _flags, rights, obj, _inh, account = [g.strip() for g in m.groups()]
        tokens = set(re.findall(r"[A-Z]{2}", rights))
        if not account:
            continue
        aces.append({
            "type": ace_type,
            "rights": tokens,
            "object": obj,
            "account": account,
        })
    return aces


def _ace_rights(ace):
    """Return the set of named rights an ACE actually grants."""
    rights = set()
    tokens = ace["rights"]
    obj = GUID_RIGHTS.get(ace["object"])
    if obj:
        rights.add(obj)
    if "CR" in tokens:
        if obj:
            rights.add(obj)
        else:
            # control access without a specific object GUID: every extended
            # right (Enroll, ManageCA, …) is included
            rights.update(("AllExtended", "Enroll", "ManageCA",
                           "ManageCertificates"))
    if "GA" in tokens:
        # generic all implies write and every extended right
        rights.update(("Write", "Enroll", "ManageCA", "ManageCertificates"))
    if "GW" in tokens or "WD" in tokens or "WO" in tokens:
        rights.add("Write")
    return rights


def _low_priv_grants(entry, right_name):
    """Return low-priv principals granted `right_name` on this entry."""
    sd = _attr(entry, "nTSecurityDescriptor")
    if not sd:
        return []
    granted = []
    for ace in parse_acl(sd[0]):
        if ace["type"] != "A":
            continue
        if right_name not in _ace_rights(ace):
            continue
        name = sid_to_name(ace["account"])
        if name and name in LOW_PRIV_NAMES:
            granted.append(name)
    return sorted(set(granted))


# ---------------------------------------------------------------- attribute helpers

def _attr(entry, name):
    """Case-insensitive attribute lookup; scalars are wrapped in a list."""
    attrs = entry.get("attrs", {})
    want = name.lower()
    for key, vals in attrs.items():
        if key.lower() == want:
            if isinstance(vals, list):
                return vals
            return [vals]
    return []


def _attr_flag(entry, name):
    """Read a flag attribute; accepts ints, hex strings, or flag names."""
    vals = _attr(entry, name)
    if not vals:
        return 0
    val = vals[0]
    if isinstance(val, int):
        return val
    val = str(val).strip()
    if val.lower().startswith("0x"):
        try:
            return int(val, 16)
        except ValueError:
            return 0
    if val.isdigit():
        return int(val)
    flags = 0
    token_map = {
        "ENROLLEE_SUPPLIES_SUBJECT": NAME_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
        "ENROLLEE_SUPPLIES_NAME": NAME_FLAG_ENROLLEE_SUPPLIES_NAME,
        "MANAGER_APPROVAL": ENROLL_FLAG_MANAGER_APPROVAL,
    }
    for token in re.split(r"[|,\s]+", val):
        flags |= token_map.get(token.upper().strip(), 0)
    return flags


def _ekus(entry):
    vals = _attr(entry, "pKIExtendedKeyUsage")
    out = []
    for val in vals:
        if isinstance(val, str):
            out.extend([v.strip() for v in val.split(",") if v.strip()])
    return out


# ---------------------------------------------------------------- checks

def _check_template(entry):
    names = _attr(entry, "name")
    name = names[0] if names else entry.get("dn", "<unknown>")

    name_flag = _attr_flag(entry, "msPKI-Certificate-Name-Flag")
    enroll_flag = _attr_flag(entry, "msPKI-Enrollment-Flag")
    ekus = _ekus(entry)

    subject_supplied = bool(name_flag & (NAME_FLAG_ENROLLEE_SUPPLIES_SUBJECT |
                                         NAME_FLAG_ENROLLEE_SUPPLIES_NAME))
    manager_approval = bool(enroll_flag & ENROLL_FLAG_MANAGER_APPROVAL)
    enroll_grants = _low_priv_grants(entry, "Enroll")

    # ESC1: enrollee-supplied subject + client-auth EKU + enroll rights
    if subject_supplied and EKU_CLIENT_AUTH in ekus:
        if enroll_grants and not manager_approval:
            find("high", "ESC1", "template '%s'" % name,
                 "enrollee-supplied subject with client-auth EKU and enroll "
                 "rights for %s, no manager approval — lets the grantee "
                 "request a cert as any principal, including DA" %
                 ", ".join(enroll_grants))
        elif enroll_grants and manager_approval:
            find("medium", "ESC1", "template '%s'" % name,
                 "enrollee-supplied subject with client-auth EKU but manager "
                 "approval is required — abuse needs an approval bypass")

    # ESC2: Any Purpose EKU with enroll rights
    if enroll_grants and EKU_ANY_PURPOSE in ekus:
        find("high", "ESC2", "template '%s'" % name,
             "Any Purpose EKU with enroll rights for %s — a cert from this "
             "template is valid for any application" % ", ".join(enroll_grants))

    # ESC3: certificate request agent EKU
    if enroll_grants and EKU_REQUEST_AGENT in ekus:
        find("medium", "ESC3", "template '%s'" % name,
             "certificate request agent EKU with enroll rights for %s — "
             "enables on-behalf-of enrollment for other principals" %
             ", ".join(enroll_grants))

    # ESC4: write access to the template object for low-priv principals
    write_grants = _low_priv_grants(entry, "Write")
    if write_grants:
        find("high", "ESC4", "template '%s'" % name,
             "template object ACL grants write access to %s — they can edit "
             "the template to issue themselves arbitrary certs" %
             ", ".join(write_grants))


def _check_ca(entry):
    names = _attr(entry, "name")
    name = names[0] if names else entry.get("dn", "<unknown>")

    # ESC8: non-TLS enrollment endpoints
    for server in _attr(entry, "msPKI-Enrollment-Servers"):
        text = str(server)
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("http://"):
                find("high", "ESC8", "CA '%s'" % name,
                     "non-TLS enrollment endpoint: %s — NTLM relay to the "
                     "HTTP enrollment service is possible (ntlmrelayx style)" %
                     line)
                break

    # ESC7: CA-level management rights for low-priv principals
    manage_grants = _low_priv_grants(entry, "ManageCA") + \
        _low_priv_grants(entry, "ManageCertificates")
    manage_grants = sorted(set(manage_grants))
    if manage_grants:
        find("medium", "ESC7", "CA '%s'" % name,
             "CA management rights (ManageCA/ManageCertificates) granted to "
             "%s — they can approve pending requests or issue arbitrary "
             "certificates" % ", ".join(manage_grants))


def _entry_classes(entry):
    oc = _attr(entry, "objectClass")
    if not oc:
        return []
    classes = []
    for val in oc:
        if isinstance(val, str):
            classes.extend(v.strip().lower() for v in val.split(",") if v.strip())
        elif isinstance(val, list):
            classes.extend(str(v).lower() for v in val)
    return classes


def audit(entries):
    for entry in entries:
        classes = _entry_classes(entry)
        if "pkicertificatetemplate" in classes:
            _check_template(entry)
        elif "pkienrollmentservice" in classes:
            _check_ca(entry)
    return FINDINGS


# ---------------------------------------------------------------- output

def _format(findings):
    if not findings:
        return ["no findings — templates look clean (from this export)"]
    out = []
    for f in findings:
        out.append("[%s] %s: %s" % (f["level"].upper(), f["id"], f["target"]))
        out.append(textwrap.fill(f["detail"], width=78,
                                 initial_indent="    ",
                                 subsequent_indent="    ",
                                 break_on_hyphens=False,
                                 break_long_words=False))
        out.append("")
    return out


def load_entries(path):
    text = path.read_text(errors="replace")
    if path.suffix.lower() == ".json":
        return parse_json_export(path)
    entries = parse_ldif(text)
    if not entries:
        raise InputError("no LDIF entries found in %s" % path)
    return entries


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="adcsaudit.py",
        description="Audit an AD CS LDAP export for certificate template "
                    "misconfigurations (ESC1-ESC8 style findings).",
        epilog="Authorized testing only. Use against systems you own or are "
               "permitted to test.",
    )
    ap.add_argument("--offline", metavar="PATH",
                    help="audit a local LDIF or JSON export instead of a live CA")
    ap.add_argument("--json", action="store_true",
                    help="output findings as JSON")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    if not args.offline:
        ap.error("no target given: pass --offline <path> "
                 "(live LDAP collection is planned but not yet implemented)")
    path = Path(args.offline)
    if not path.is_file():
        ap.error("input file not found: %s" % path)

    try:
        entries = load_entries(path)
    except InputError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    del FINDINGS[:]
    findings = audit(entries)

    if args.json:
        print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
    else:
        for line in _format(findings):
            print(line)
        print("%d finding(s) across %d entries" % (len(findings), len(entries)))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
