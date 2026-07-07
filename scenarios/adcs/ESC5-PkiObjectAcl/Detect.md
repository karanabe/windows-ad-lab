# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc5`. The scenario does not write `cACertificate` values or create a rogue CA. The main trace is a GenericAll ACE on `CN=NTAuthCertificates`.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5136 | `nTSecurityDescriptor` on `CN=NTAuthCertificates` |
| Security | 4670 | Permission changes on the NTAuth object |
| Security | 4662 | Directory access to NTAuthCertificates when a SACL exists |
| Security | 4688 | PowerShell running `setup.ps1` or `Set-Acl` |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `NTAuthCertificates`, `bob.taylor`, `GenericAll` |

Look at `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,...` for a non-inherited GenericAll ACE for `bob.taylor`. Do not treat Manage CA on the CA object as this scenario; that is ESC7.
