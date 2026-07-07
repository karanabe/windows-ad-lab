# ESC14 Weak Explicit Mapping 設計書

[English](README.md)

このシナリオは、隔離された Windows Server 2025 Active Directory / AD CS ラボで、明示的な証明書マッピング `altSecurityIdentities` が弱い ESC14 を理解するための教材である。`alice.brown` に `operator01` の `altSecurityIdentities` への WriteProperty を付与し、弱い `X509:<RFC822>` マッピングを書き込む。

この文書は設計説明であり、GUI手順や攻撃手順は扱わない。証明書要求、PFX 保存、証明書による認証は自動化しない。

## 使い方

Hyper-V ホスト上のリポジトリ clone をカレントにして実行します。`Invoke-Scenario.ps1` はこの clone から guest の `C:\LabBootstrap\scenarios` へ同期します。

```powershell
.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc14' `
    -AcknowledgeIsolatedLabRisk

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc14' `
    -Action Validate `
    -ScriptParameters @{ FailOnValidationError = $true }

.\scenarios\Invoke-Scenario.ps1 `
    -ScenarioName 'esc14' `
    -Action Cleanup
```

## ESC14 成立条件

ESC14 はテンプレート ACL ではなく、アカウントの明示的マッピングである。

- 低権限主体が対象アカウントの `altSecurityIdentities` を書ける。
- または、弱い明示的マッピング（`X509:<RFC822>`、`X509:<S>` など）が既に存在する。
- 強いマッピングは `X509:<SKI>`、`X509:<SHA1-PUKEY>`、Issuer と serial の組み合わせである。

この教材はテンプレートの `CT_FLAG_NO_SECURITY_EXTENSION` を変更しない。それは ESC9 である。KDC の `StrongCertificateBindingEnforcement` も変更しない。それは ESC10 の範囲である。

参考資料:

- BloodHound: WriteAltSecurityIdentities
  https://bloodhound.specterops.io/resources/edges/write-alt-security-identities
- Microsoft Learn: KB5014754 certificate-based authentication changes
  https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
