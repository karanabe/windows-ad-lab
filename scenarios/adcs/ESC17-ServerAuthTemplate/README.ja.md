# ESC17 Server Authentication Template 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、ESC1 の Client Authentication テンプレートと、ESC17 が成立する Server Authentication テンプレートの差分を理解するための教材である。既定テンプレートは変更せず、`User` から複製した `ESC17LabServerAuth` だけを追加する。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。証明書要求、PFX 保存、WSUS なりすまし、証明書による認証は自動化しない。このラボは WSUS を動かさない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc17' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc17' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc17' `
    -Action Cleanup
```

## ESC17 成立条件

ESC17 は ESC1 と同じく要求者指定 Subject が中心だが、EKU が Server Authentication である。

- 低権限ユーザーまたは広いグループが Enroll できる。
- EKU が Server Authentication `1.3.6.1.5.5.7.3.1`、Any Purpose、または空である。
- `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効である。
- CA manager approval が不要で、authorized signatures が 0 である。
- Enterprise CA がそのテンプレートを公開している。

発行された証明書は、任意の DNS 名を SAN に持てる。公開 ESC17 はこれを内部 WSUS の HTTPS なりすましへつなげる。この教材はテンプレート条件だけを残し、WSUS や TLS 中間者は実行しない。

ESC1 との差分は Client Authentication が無いことである。schema v1 で Application Policy が空なのは ESC15 であり、この教材は schema v2 で Server Authentication を明示する。

参考資料:

- Certipy wiki: ESC17 Enrollee-Supplied Subject for Server Authentication
  https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation
- TrustedSec: WSUS Is SUS
  https://trustedsec.com/blog/wsus-is-sus-ntlm-relay-attacks-in-plain-sight
