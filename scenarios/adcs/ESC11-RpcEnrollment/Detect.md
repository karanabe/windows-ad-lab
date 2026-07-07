# Detect

[日本語](Detect.ja.md)

Traces for CA `InterfaceFlags` changes.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 4880, 4896 | CA service / configuration |
| Security | 4688 | `certutil`, PowerShell |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `IF_ENFORCEENCRYPTICERTREQUEST` |

Read `CA\InterfaceFlags` on the active CA. This scenario does not request certificates.
