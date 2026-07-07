# Detect

[日本語](Detect.ja.md)

Traces for issuing and removing a PKINIT KDC certificate.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 4886, 4887 | Certificate request / issuance |
| Security | 5136, 5137 | Lab KDC template and OID |
| Security | 4688 | `certreq`, `certutil`, PowerShell enrollment |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | Template name `LAB-PKINIT-KDCAuthentication` |

Confirm a Local Machine certificate with KDC Authentication EKU `1.3.6.1.5.2.3.5` after setup.
