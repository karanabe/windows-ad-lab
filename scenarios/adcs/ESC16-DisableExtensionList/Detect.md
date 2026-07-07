# Detect

[日本語](Detect.ja.md)

Traces for CA `policy\DisableExtensionList` changes.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 4657 | `DisableExtensionList` |
| Security | 4688 | `certutil`, PowerShell |
| Security | 4891, 4892 | Certificate Services configuration |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `1.3.6.1.4.1.311.25.2`, `DisableExtensionList` |

Read the active CA policy module `DisableExtensionList`. This scenario does not request certificates.
