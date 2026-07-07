# Detect

[日本語](Detect.ja.md)

Configuration and IIS traces for `/CertSrv`. This scenario does not generate relay traffic.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 4688 | `appcmd`, PowerShell IIS configuration |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `tokenChecking`, `Negotiate:Kerberos`, Require SSL |

Compare current IIS authentication, SSL flags, and EPA against the expected stage. `/CertEnroll` is the CDP/AIA path and is not the ESC8 endpoint.
