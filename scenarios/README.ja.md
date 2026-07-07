# シナリオ一覧

[English](README.md)

ラボを構築したHyper-Vホストの同じcloneから実行します。各シナリオは `06-ADCS-HTTP-CDP` を起点とし、実行順序の前提はありません。runnerは `-SkipSync` を指定しない限り、対象ディレクトリをゲストへコピーします。UNC上のcloneから直接転送できない場合だけ、ホストのローカル一時コピーから再試行します。検証用入力ファイルも同様です。動作と制限は個別READMEに記載し、必要なシナリオには `Detect.md` と `Audit.ps1` があります。

| ID | シナリオ |
|---|---|
| `esc1` | [ESC1証明書テンプレート](adcs/ESC1-CertificateTemplate/README.ja.md) |
| `esc2` | [ESC2 Any Purposeテンプレート](adcs/ESC2-AnyPurposeTemplate/README.ja.md) |
| `esc3` | [ESC3 Enrollment Agent](adcs/ESC3-EnrollmentAgent/README.ja.md) |
| `esc4` | [ESC4テンプレートACL](adcs/ESC4-TemplateAcl/README.ja.md) |
| `esc5` | [ESC5 PKIオブジェクトACL](adcs/ESC5-PkiObjectAcl/README.ja.md) |
| `esc7` | [ESC7 Manage CA](adcs/ESC7-ManageCA/README.ja.md) |
| `esc8` | [ESC8 Web Enrollment hardening](adcs/ESC8-Hardening/README.ja.md) |
| `esc11` | [ESC11 RPC enrollment](adcs/ESC11-RpcEnrollment/README.ja.md) |
| `esc12` | [ESC12 CA鍵保管の観察](adcs/ESC12-CaKeyStorage/README.ja.md) |
| `esc13` | [ESC13 issuance policy](adcs/ESC13-IssuancePolicy/README.ja.md) |
| `esc14` | [ESC14弱い明示的マッピング](adcs/ESC14-WeakExplicitMapping/README.ja.md) |
| `esc15` | [ESC15 schema v1テンプレート](adcs/ESC15-SchemaV1Template/README.ja.md) |
| `esc16` | [ESC16 SID extension list](adcs/ESC16-DisableExtensionList/README.ja.md) |
| `esc17` | [ESC17 Server Authenticationテンプレート](adcs/ESC17-ServerAuthTemplate/README.ja.md) |
| `pkinit` | [PKINIT KDC証明書](adcs/PKINIT-KDCCertificate/README.ja.md) |
| `key-credential-link` | [KeyCredentialLink観察](credentials/KeyCredentialLink-Observation/README.ja.md) |
| `laps-delegation` | [Windows LAPS委任](credentials/WindowsLAPS-Delegation/README.ja.md) |
| `gmsa-password` | [gMSAパスワード取得](credentials/gMSA-PasswordRetrieval/README.ja.md) |
| `rbcd` | [リソースベースの制約付き委任](delegation/RBCD/README.ja.md) |
| `gpo-abuse` | [GPO ACL経路](acl/ADACL-GPOAbuse/README.ja.md) |
| `dcsync` | [ディレクトリ複製権限](acl/DCSync-ReplicationRights/README.ja.md) |
| `adminsdholder` | [AdminSDHolder伝播](acl/AdminSDHolder/README.ja.md) |

VMの変更を破棄する前に復元対象を確認し、シナリオを実行します。

```powershell
.\scenarios\Restore-LabBaseline.ps1 -WhatIf
.\scenarios\Restore-LabBaseline.ps1 -AcknowledgeDataLoss -StartVM
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -AcknowledgeIsolatedLabRisk
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -Action Validate
.\scenarios\Invoke-Scenario.ps1 -ScenarioName 'esc1' -Action Cleanup
```

runnerはID、番号のないカテゴリ相対パス、シナリオ名も受け付けます。従来の番号付きシナリオ名は使用できません。旧名で適用済みのシナリオは、状態保存先も変わるため、新しいスクリプトを使う前に `06-ADCS-HTTP-CDP` へ復元してください。`Audit.ps1` があれば `-Action Audit` を使用できます。`-ScriptParameters` は選択したゲスト用スクリプトへhashtableを渡します。単一シナリオの `Validate` では `-ValidationInputFiles` にpath引数名とホストファイルを指定できます。相対ファイル名は `artifacts/scenario-validation/<シナリオのパス>` から解決し、サイズとSHA-256を確認して転送します。

`Invoke-Scenario.ps1 -WhatIf` はVMへ接続せず、実行対象と同期先を表示します。復元すると以後のゲスト状態とログは失われます。シナリオ実行中もVMを隔離してください。
