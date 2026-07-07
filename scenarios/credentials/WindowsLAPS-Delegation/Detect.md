# Detect

[日本語](Detect.ja.md)

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5136 | LAPS attribute and ACL changes on the Computers OU or FILE01 |
| Security | 4662 | Reads of Windows LAPS password attributes |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `Windows LAPS`, `FILE01`, delegated group names |

This scenario compares read rights. It does not rotate a real LAPS password on a joined host unless that host exists and policy applies.
