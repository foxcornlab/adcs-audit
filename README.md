# adcs-audit

Offline auditor for Active Directory Certificate Services (AD CS)
misconfigurations. Feed it an LDAP export (LDIF or JSON) of your
Certificate Templates and Enrollment Services objects and it reports the
ESC1,ESC8 style attack paths a low-privileged user could take.

## What it checks

- **ESC1**, enrollee-supplied subject + client-authentication EKU +
  enroll rights for a low-privileged group, no manager approval: anyone
  in that group can request a certificate as any principal, including
  Domain Admin.
- **ESC2**, Any Purpose EKU combined with low-privilege enroll rights.
- **ESC3**, Certificate Request Agent EKU with low-privilege enroll
  rights (enables on-behalf-of enrollment).
- **ESC4**, low-privileged principals hold write access on the template
  object itself.
- **ESC7**, low-privileged principals hold CA management rights
  (ManageCA / ManageCertificates).
- **ESC8**, enrollment endpoints published over plain `http://`.

Security descriptors are read from the `nTSecurityDescriptor` SDDL text
in the export; trustees are mapped from well-known SIDs and SDDL tokens
(Everyone, Authenticated Users, Domain Users, Domain Computers, Users).
Domain-specific SIDs that can't be resolved are skipped rather than
guessed.

## Install

```sh
chmod +x adcsaudit.py
./adcsaudit.py --help
```

Python 3.8+, standard library only. No dependencies.

## Usage

```sh
# audit a JSON export (see tests/fixtures for the expected shape)
./adcsaudit.py --offline export.json

# audit an LDIF from ldapsearch
ldapsearch -H ldap://dc01.corp.local -b \
  "CN=Configuration,DC=corp,DC=local" \
  "(objectClass=pKICertificateTemplate)" > dump.ldif
./adcsaudit.py --offline dump.ldif

# machine-readable output
./adcsaudit.py --offline export.json --json
```

Exit codes: `0` clean, `1` findings, `2` usage or input error.

## Example

```
$ ./adcsaudit.py --offline tests/fixtures/esc1_esc8.json
[HIGH] ESC1: template 'UserAuth'
    enrollee-supplied subject with client-auth EKU and enroll rights for
    Authenticated Users, no manager approval, lets the grantee request a cert
    as any principal, including DA

[HIGH] ESC4: template 'UserAuth'
    template object ACL grants write access to Authenticated Users, they can
    edit the template to issue themselves arbitrary certs

[HIGH] ESC8: CA 'CorpCA'
    non-TLS enrollment endpoint: http://corp-ca.corp.local/certsrv/certfnsh.asp ,
    NTLM relay to the HTTP enrollment service is possible (ntlmrelayx style)

3 finding(s) across 2 entries
```

## Export format

Any entry with `objectClass: pKICertificateTemplate` is checked as a
template; `pKIEnrollmentService` as a CA. Attributes read:

| attribute | use |
| --- | --- |
| `name` | object label in findings |
| `msPKI-Certificate-Name-Flag` | subject-supply flags (int, hex, or name) |
| `msPKI-Enrollment-Flag` | manager-approval flag |
| `pKIExtendedKeyUsage` | OIDs |
| `nTSecurityDescriptor` | SDDL string |
| `msPKI-Enrollment-Servers` | enrollment URLs |

## Scope

Audits exported data only, it never talks to a domain controller.
Authorized testing only. Use against systems you own or are permitted
to test.

## Tests

```sh
python3 -m unittest discover -s tests
```
