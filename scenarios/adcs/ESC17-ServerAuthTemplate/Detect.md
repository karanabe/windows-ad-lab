# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc17`. The scenario does not automate certificate requests or PFX export. The main traces are Certificate Template, Enterprise OID, and CA publication-list changes.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5137, 5141 | `pKICertificateTemplate` and enterprise OID create/delete |
| Security | 5136 | `pKIExtendedKeyUsage`, `msPKI-Certificate-Name-Flag`, CA `certificateTemplates` |
| Security | 4688 | PowerShell running `setup.ps1`, `New-ADObject`, `Set-ADObject`, `Add-CATemplate` |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC17LabServerAuth`, `Domain Users`, `1.3.6.1.5.5.7.3.1` |

Look at `CN=ESC17LabServerAuth,CN=Certificate Templates,...` for marker `windows-ad-lab:ESC17-ServerAuthTemplate`, Server Authentication EKU, enrollee-supplies-subject, and no Client Authentication.
