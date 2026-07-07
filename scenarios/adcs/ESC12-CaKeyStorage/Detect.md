# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc12`. The scenario does not export CA keys or forge certificates. The main traces are CertSvc status and CA CSP registry reads.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 4657, 4663 | `CertSvc\Configuration\<CA>\CSP` |
| Security | 4688 | PowerShell reading CA CSP |
| Security | 4891, 4892 | Certificate Services property changes; this scenario should not change CSP |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC12-CaKeyStorage`, `YubiHSM Key Storage Provider`, `KeyContainer` |

Look at `HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\CSP` for `Provider` and `KeyContainer`. Confirm YubiHSM software is absent.
