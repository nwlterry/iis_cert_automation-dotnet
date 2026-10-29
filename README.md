# IIS Certificate Automation (.NET 8 and .NET 10)

Windows console port of the deployed PowerShell set in [iis_cert_automation](https://github.com/nwlterry/iis_cert_automation). One project, two target frameworks. Prefer `net10.0`.

The PFX password is prompted by `setup`. It is not an argument, and the config file rejects a password field. This build does not install `credentialmanager.2.0.0.nupkg`. Credential Manager is written with the Windows credential API.

## CCS

| PowerShell | Command |
|---|---|
| `Setup_CCS_and_Task.ps1` | `setup --ccs \\fileserver.example\IIS_Cert_Store --config C:\Scripts\iis-cert-automation.config.json` |
| `Setup_CCS_Node.ps1` | `setup-node --ccs \\fileserver.example\IIS_Cert_Store` |
| `Export_Cert_CCS_Secure.ps1` | `export --config C:\Scripts\iis-cert-automation.config.json` |

`setup-node` checks that the CCS registry already matches the path, then deletes the Username and Password values. It does not store a password and it does not open IIS Manager.

## File share

| PowerShell | Command |
|---|---|
| `drive_mapping.ps1` | `map-drive --config C:\Scripts\iis-cert-automation.config.json` |
| `unc_connectivity_checker_w_status.ps1` | `unc-check --config C:\Scripts\iis-cert-automation.config.json` |
| `drive_mapping_schedule_task.ps1` and `unc_checker_schedule_task.ps1` | `register-share-tasks --config C:\Scripts\iis-cert-automation.config.json` |

`unc-check` remaps the UNC path when the test path is down, then runs up to 10 `iisreset` attempts and an HTTPS health check. TLS validation stays on unless `allowInsecureHealthCheck` is true.

Copy [config.example.json](config.example.json) to `iis-cert-automation.config.json` and keep that copy out of git.

## Build

```bash
dotnet test -c Release
dotnet publish src/IisCertAutomation/IisCertAutomation.csproj -c Release -f net10.0 -r win-x64 --self-contained false -o artifacts/win-x64-net10
dotnet publish src/IisCertAutomation/IisCertAutomation.csproj -c Release -f net8.0 -r win-x64 --self-contained false -o artifacts/win-x64-net8
```

Published output is framework-dependent. The IIS host needs the matching Windows Desktop/Server runtime, not a self-contained bundle.

Legacy CMD cannot replace these commands. See [docs/POWERSHELL-VS-CMD.md](docs/POWERSHELL-VS-CMD.md).

Security review: [docs/SECURITY_SCAN.md](docs/SECURITY_SCAN.md).

See [GROUP.md](GROUP.md).
