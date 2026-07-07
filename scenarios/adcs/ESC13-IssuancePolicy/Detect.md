# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc13`. The scenario does not automate certificate requests or PFX export. The main traces are the AMA group, issuance-policy OID, template, and `CLIENT01` ACL.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5137, 5141 | group, `msPKI-Enterprise-Oid`, `pKICertificateTemplate` create/delete |
| Security | 5136 | `msDS-OIDToGroupLink`, `msPKI-Certificate-Policy`, `nTSecurityDescriptor` |
| Security | 4688 | PowerShell running `setup.ps1`, `New-ADGroup`, `New-ADObject` |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC13LabAma`, `UG_ESC13_AMA`, `msDS-OIDToGroupLink` |

Look at the issuance-policy OID for `msDS-OIDToGroupLink` to `UG_ESC13_AMA`, and `ESC13LabAma` for Client Authentication plus that policy. Enrollee-supplied subject should stay off.
