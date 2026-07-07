# Windows LAPS delegation concepts

[日本語](concepts.ja.md)

This note explains what `laps-delegation` validates and what it does not.

The scenario compares two permission shapes:

- An OU-scoped Windows LAPS password-read delegation
- A FILE01 computer object ACL that is too broad (`GenericAll` or equivalent)

A synthetic stored value is enough to compare who can read the LAPS attribute. That is not the same as recovering a live local administrator password from a domain-joined host after policy application and rotation.

The scenario does not:

- Prove that LAPS is deployed to every prestaged computer
- Exercise DSRM password backup
- Treat a readable attribute value as an automatic host compromise

Operation steps are in [README.md](README.md).
