# Scenario agent notes

The host runner may be launched from a UNC clone such as `\\wsl.localhost\...`. A scenario's source directory, and a file supplied through `-ValidationInputFiles`, may therefore be UNC paths. `Copy-Item -ToSession` can fail on those sources even when reading the files locally works.

When adding a scenario, keep its setup, validation, cleanup, and audit scripts runnable from the guest-local copy placed by `Invoke-Scenario.ps1`. Do not make guest scripts read a host UNC path. If new host-to-guest file transfers are needed, use the runner's transfer pattern: try the direct transfer first; only after a UNC source transfer fails, copy that source to a local temporary directory on the Hyper-V host, retry from there, and remove the temporary copy. Preserve validation input size and SHA-256 checks.

Scenario transfers are outside the `01-Updated` through `06-ADCS-HTTP-CDP` setup workflow. Keep UNC handling for new scenario behavior under `scenarios/`.
