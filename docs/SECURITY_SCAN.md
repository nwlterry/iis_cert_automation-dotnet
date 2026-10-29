# Security scan — 2026-10-29

Scanner: `tools/static_scan.py` (iis-cert-static-scan 1.0.0), same rules as the PowerShell repository.
SARIF: [security-scan.sarif.json](security-scan.sarif.json).
Open regression hits: **0**.
Tests: 17 passed on `net8.0`, 17 passed on `net10.0`.

This repository was recreated from the deployed PowerShell set only:

- CCS: export, primary setup, extra-node check
- File share: drive map, UNC check with IIS reset, SYSTEM task registration

| PowerShell finding | How this port avoids it |
|---|---|
| PS-001 password in a generated script | `setup` prompts, DPAPI-protects a blob, and the SYSTEM task reads that blob. The password is never an argument. |
| PS-002 partial password in the log | `SecretLog` does not write the secret. Tests reject any substring of it. |
| PS-003 command injection | Paths go through `PathGuard` and `ProcessStartInfo.ArgumentList`, not a concatenated shell string. |
| PS-004 lab host names | `config.example.json` uses `fileserver.example`. |
| PS-005 `curl -k` | TLS validation is disabled only when `allowInsecureHealthCheck` is true, and a warning is written. |
| PS-006 unpinned nupkg | This program does not install CredentialManager. `PackagePin` still records the PowerShell module hash. |
| PS-007 loose ACL | `icacls /inheritance:r` is used on the DPAPI blob. |
| PS-008 persisted private key | Verify uses `EphemeralKeySet`. `net10.0` uses `X509CertificateLoader`. |
| PS-009 ExecutionPolicy Bypass | There is no PowerShell host. |
| PS-012 lab host in `Setup_CCS_Node.ps1` | `setup-node` takes `--ccs` and checks the registry. No host is hard-coded. |
| PS-013 wrong checker script and SYSTEM as a group | `register-share-tasks` runs `unc-check` as `S-1-5-18`. |
| PS-014 / PS-015 log file bugs | Log retention only names `UNC_Check_*.log`. Certificate export logs are not selected. |

## Accepted

LocalMachine DPAPI and a LocalMachine credential are readable by local administrators. IIS already requires that so SYSTEM can open the PFX.
