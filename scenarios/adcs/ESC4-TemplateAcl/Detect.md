# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc4`. The scenario does not automate template rewriting, certificate requests, or PFX export. The main traces are Certificate Template, Enterprise OID, template ACL, and CA publication-list changes.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5137, 5141 | `pKICertificateTemplate` and enterprise OID create/delete |
| Security | 5136 | `nTSecurityDescriptor`, CA `certificateTemplates` |
| Security | 4670 | Template permission changes |
| Security | 4662 | Directory access to the template when a SACL exists |
| Security | 4688 | PowerShell running `setup.ps1`, `New-ADObject`, `Set-Acl`, `Add-CATemplate` |
| Security | 4898, 4899 | Certificate Services reading or updating a template |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC4LabUser`, `alice.brown`, `GenericAll` |

Look at `CN=ESC4LabUser,CN=Certificate Templates,...` for marker `windows-ad-lab:ESC4-TemplateAcl` and a non-inherited GenericAll ACE for `alice.brown`.
