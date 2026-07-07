# Detect

[日本語](Detect.ja.md)

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5136, 5137 | gMSA object and `PrincipalsAllowedToRetrieveManagedPassword` |
| Security | 4662 | Reads of `msDS-ManagedPassword` |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | gMSA name and reader group |

The scenario compares retrieval policy. It does not extract a managed password for attack use.
