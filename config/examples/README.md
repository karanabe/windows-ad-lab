# Example lab configs

[日本語](README.ja.md)

`Test-LabConfig.ps1` validates the schema of any isolated-lab config: required sections, names, referential integrity, private switch, and no default gateway. It does not require `ad.lab.exceeds.test`.

| File | Role |
|---|---|
| [../LabConfig.psd1](../LabConfig.psd1) | Shipped instance used by this repository's scenarios |
| [generic-lab.psd1](generic-lab.psd1) | Example instance (`ad.lab.example.test`) that passes schema validation |

`generic-lab.psd1` shows a schema-valid file. It is not a supported lab. Copying it over `config/LabConfig.psd1` makes `Invoke-StaticValidation.ps1` and `Invoke-ValidatedLabSetup.ps1` fail, and the scenarios in this repository check the shipped domain `ad.lab.exceeds.test`. Build and validate the shipped file.
