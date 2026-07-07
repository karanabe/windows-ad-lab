# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc15`. The scenario does not automate certificate requests, Application Policy injection, or PFX export. The main traces are Certificate Template, Enterprise OID, and CA publication-list changes.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5137, 5141 | `pKICertificateTemplate` and enterprise OID create/delete |
| Security | 5136 | `msPKI-Template-Schema-Version`, `msPKI-Certificate-Name-Flag`, `pKIExtendedKeyUsage`, `nTSecurityDescriptor`, CA `certificateTemplates` |
| Security | 4662 | Directory access to template / CA objects when a SACL exists |
| Security | 4688 | PowerShell running `setup.ps1`, `New-ADObject`, `Set-ADObject`, `Add-CATemplate` |
| Security | 4898, 4899 | Certificate Services reading or updating a template |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC15LabWeb`, `Domain Users`, `msPKI-Template-Schema-Version`, `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` |

Look at `CN=ESC15LabWeb,CN=Certificate Templates,...` for marker `windows-ad-lab:ESC15-SchemaV1Template`, schema version 1, empty Application Policy, Server Authentication EKU `1.3.6.1.5.5.7.3.1`, and enrollee-supplies-subject.
