# Detect

[日本語](Detect.ja.md)

| Log | Event ID | What to look for |
|---|---:|---|
| Security | 5136 | ACL on the domain object for replication rights |
| Security | 4662 | Control access for DS-Replication-Get-Changes |
| Security | 4928, 4932 | Replication after a later DCSync attempt |
| Microsoft-Windows-PowerShell/Operational | 4103, 4104 | Marker `DCSync-ReplicationRights` |

This fixture only creates the rights path. Replication traffic is not generated here.
