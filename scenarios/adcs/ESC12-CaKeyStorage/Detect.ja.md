# Detect

[English](Detect.md)


この文書は `ESC12-CaKeyStorage` の痕跡を探すための調査メモです。シナリオは CA 秘密鍵の export や証明書偽造を自動化しません。主な痕跡は CertSvc の状態確認と CA CSP レジストリの読み取りです。

## 前提

- Baseline 06 では `Process Creation` と `Certification Services` 監査が有効です。
- このシナリオは CA の暗号プロバイダを変更しません。
- 公開 ESC12 の YubiHSM は導入されていません。

## Event log

| Log | Event ID | 見る痕跡 |
|---|---:|---|
| Security | 4657, 4663 | `CertSvc\Configuration\<CA>\CSP` |
| Security | 4688 | CA CSP を読む PowerShell |
| Security | 4891, 4892 | Certificate Services のプロパティ変更。このシナリオでは CSP は変わらない |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `ESC12-CaKeyStorage`、`YubiHSM Key Storage Provider`、`KeyContainer` |
| Microsoft-Windows-Sysmon/Operational | 1, 13 | Sysmon がある場合の process / registry |

## 現在状態

- `HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\CSP`
  - `Provider` が Microsoft software CSP/KSP
  - `YubiHSM Key Storage Provider` ではない
- `HKLM:\SOFTWARE\Yubico\YubiHSM` が無い
- `C:\ProgramData\YubiHSM` が無い

## Audit script

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc12' `
    -Action Audit `
    -ScriptParameters @{ StartTime = (Get-Date).AddHours(-6) }
```
