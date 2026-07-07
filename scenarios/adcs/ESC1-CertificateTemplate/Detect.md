# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc1`. The scenario does not automate certificate requests or PFX export. The main traces are Certificate Template, Enterprise OID, and CA publication-list changes.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5137, 5141 | `pKICertificateTemplate` and enterprise OID create/delete |
| Security | 5136 | `msPKI-Certificate-Name-Flag`, `pKIExtendedKeyUsage`, `nTSecurityDescriptor`, CA `certificateTemplates` |
| Security | 4662 | Directory access to template / CA objects when a SACL exists |
| Security | 4688 | PowerShell running `setup.ps1`, `New-ADObject`, `Set-ADObject`, `Add-CATemplate` |
| Security | 4898, 4899 | Certificate Services reading or updating a template |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC1LabUser`, `Domain Users`, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` |

Look at `CN=ESC1LabUser,CN=Certificate Templates,...` for marker `windows-ad-lab:ESC1-CertificateTemplate` and enrollee-supplies-subject plus Client Authentication EKU `1.3.6.1.5.5.7.3.2`.
