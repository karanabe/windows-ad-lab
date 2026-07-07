# Detect

[日本語](Detect.ja.md)

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5136 | AdminSDHolder `nTSecurityDescriptor` and protected-account ACL |
| Security | 4780 | ACL set on admin accounts by SDProp |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | Marker `AdminSDHolder` |

Expect the AdminSDHolder ACE to appear on the protected account after SDProp, not only on the container itself.
