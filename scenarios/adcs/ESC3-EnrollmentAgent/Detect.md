# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc3`. The scenario does not automate certificate requests, on-behalf enrollment, or PFX export. The main traces are two Certificate Templates, their Enterprise OIDs, and CA publication-list changes.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5137, 5141 | `pKICertificateTemplate` and enterprise OID create/delete |
| Security | 5136 | `pKIExtendedKeyUsage`, `msPKI-RA-Signature`, `msPKI-RA-Application-Policies`, `nTSecurityDescriptor`, CA `certificateTemplates` |
| Security | 4662 | Directory access to template / CA objects when a SACL exists |
| Security | 4688 | PowerShell running `setup.ps1`, `New-ADObject`, `Set-ADObject`, `Add-CATemplate` |
| Security | 4898, 4899 | Certificate Services reading or updating a template |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC3LabAgent`, `ESC3LabOnBehalf`, `1.3.6.1.4.1.311.20.2.1` |

Look at `CN=ESC3LabAgent` for Certificate Request Agent EKU `1.3.6.1.4.1.311.20.2.1`, and at `CN=ESC3LabOnBehalf` for Client Authentication plus `msPKI-RA-Signature=1`.
