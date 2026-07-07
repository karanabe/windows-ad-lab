# Detect

[日本語](Detect.ja.md)

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5136 | GPO object ACL, OU link, group membership |
| Security | 4662 | Directory access on the GPO |
| Security | 5145 / SYSVOL file audits | SYSVOL write attempts when enabled |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | Marker `ADACL-GPOAbuse` |

Correlate directory changes with SYSVOL file changes. A tool-reported GenericAll edge is not the same as a GPO that actually applies.
