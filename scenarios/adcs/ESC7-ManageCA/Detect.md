# Detect

[日本語](Detect.ja.md)

Investigation notes for `esc7`. The scenario does not enable `EDITF_ATTRIBUTESUBJECTALTNAME2`, approve requests, or enroll. The main traces are the CA security descriptor in the registry and the CA enrollment-service AD object ACL.

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5136 | `nTSecurityDescriptor` on the `pKIEnrollmentService` object |
| Security | 4670 | Permission changes on the CA AD object |
| Security | 4688 | PowerShell running `setup.ps1`, registry writes, or `Restart-Service CertSvc` |
| Security | 4891, 4892 | Certificate Services configuration or property changes |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | `operator01`, `ManageCA`, `CA\Security` |

Look at `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA>\Security` for an Allow ACE with access mask `0x1` for `operator01`. That is Manage CA, not GenericAll on NTAuthCertificates (ESC5).
