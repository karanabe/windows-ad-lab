# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc14`. The scenario does not automate certificate requests or PFX export. The main traces are `altSecurityIdentities` and the target user ACL.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5136 | `altSecurityIdentities`, `nTSecurityDescriptor` on `operator01` |
| Security | 4670 | Permissions on `operator01` |
| Security | 4688 | PowerShell running `setup.ps1`, `Set-ADUser`, `Set-Acl` |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `alice.brown`, `operator01`, `X509:<RFC822>` |

Look at `operator01` for a non-inherited WriteProperty ACE for `alice.brown` on `altSecurityIdentities`, and a weak `X509:<RFC822>` value. Do not treat template SID-extension flags as this scenario; that is ESC9.
