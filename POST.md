# adcs-audit, offline AD CS misconfiguration auditor

Every AD environment I audit has a certificate template someone
"temporarily" opened up years ago. AD CS misconfigurations are still one
of the most reliable paths from a regular user to domain admin, no
exploits, just enrollment rights pointing at the wrong groups.

So I wrote a small offline auditor. Point it at an LDAP export (LDIF or
JSON) of your Certificate Templates and Enrollment Services objects and
it flags:

- ESC1: enrollee-supplied subject + client-auth EKU + enroll rights for
  low-priv groups, no manager approval
- ESC2/ESC3: Any Purpose and Request Agent EKUs with open enroll rights
- ESC4: write access on the template object itself
- ESC7: ManageCA/ManageCertificates grants on the CA
- ESC8: enrollment endpoints published over plain http://

```
$ ./adcsaudit.py --offline export.json
[HIGH] ESC1: template 'UserAuth'
    enrollee-supplied subject with client-auth EKU and enroll rights for
    Authenticated Users, no manager approval, lets the grantee request a cert
    as any principal, including DA
```

Single Python file, standard library only, runs fully offline, export
your PKI objects with ldapsearch and audit them anywhere, no domain
credentials or PowerShell needed. 24 tests green. Exit codes play nice
with CI: 0 clean, 1 findings, 2 input errors.

Repo: https://github.com/foxcornlab/adcs-audit

#redteam #activedirectory #adcs #pentesting #informationsecurity
