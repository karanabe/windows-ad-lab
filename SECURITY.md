# Security

This repository builds an isolated Active Directory lab. It is not a production AD, PKI, or security-baseline project.

## Lab assumptions

- Keep the lab VM on a private Hyper-V switch. Do not connect it to an external network.
- The default lab colocates a domain controller and an Enterprise Root CA, uses shared initial passwords, and creates weak permissions for validation.
- Do not reuse these settings outside an isolated lab.

## Reporting

This project does not accept production vulnerability reports against the lab configuration. The weak permissions and misconfigurations are intentional fixtures.

If you find a defect in the host-side automation that could affect a system outside the isolated VM, open a GitHub issue without including passwords, tokens, or full execution logs.
