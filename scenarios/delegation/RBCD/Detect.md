# Detect

[日本語](Detect.ja.md)

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5136 | `msDS-AllowedToActOnBehalfOfOtherIdentity` on FILE01 |
| Security | 4662 | Writes to the computer object by `svc_web` |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | Marker `windows-ad-lab:RBCD` |

Kerberos service-ticket requests for S4U2Self/S4U2Proxy are out of scope for this fixture.
