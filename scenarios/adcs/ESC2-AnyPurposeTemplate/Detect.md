# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc2`. The scenario does not automate certificate requests or PFX export. The main traces are Certificate Template, Enterprise OID, and CA publication-list changes.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5137, 5141 | `pKICertificateTemplate` and enterprise OID create/delete |
| Security | 5136 | `pKIExtendedKeyUsage`, `msPKI-Certificate-Application-Policy`, `nTSecurityDescriptor`, CA `certificateTemplates` |
| Security | 4662 | Directory access to template / CA objects when a SACL exists |
| Security | 4688 | PowerShell running `setup.ps1`, `New-ADObject`, `Set-ADObject`, `Add-CATemplate` |
| Security | 4898, 4899 | Certificate Services reading or updating a template |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC2LabAnyPurpose`, `Domain Users`, `2.5.29.37.0` |

Look at `CN=ESC2LabAnyPurpose,CN=Certificate Templates,...` for marker `windows-ad-lab:ESC2-AnyPurposeTemplate` and Any Purpose EKU `2.5.29.37.0` without Client Authentication or enrollee-supplies-subject.
