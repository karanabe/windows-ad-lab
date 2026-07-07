# Detect

[日本語](Detect.ja.md)

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 4720, 4726 | Observation user create/delete |
| Security | 5136 | `msDS-KeyCredentialLink` if later written manually |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | Scenario marker `KeyCredentialLink-Observation` |

This fixture only prepares the user. A later write to `msDS-KeyCredentialLink` is a separate action.
