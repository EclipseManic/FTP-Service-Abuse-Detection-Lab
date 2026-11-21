# Windows Service Abuse Detection Lab

**A defensive lab for MSBuild inline-C# proxy execution hidden behind a Windows service.**

[![Validate](https://github.com/EclipseManic/service-abuse-detection-lab/actions/workflows/validate.yml/badge.svg)](https://github.com/EclipseManic/service-abuse-detection-lab/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

This repository walks through one attack chain end to end — a Windows service
that launches signed `msbuild.exe`, which compiles and runs inline C# — and
focuses on what a SOC actually needs: the telemetry the chain leaves, the
events that separate it from normal build activity, and detection rules you can
adapt.

> **Simulation only.** This repository contains no payload, no credential
> harvester, and no execution path. The walkthrough prints what would happen; it
> does not create files, services, processes, or connections.

## What is here

| Path | Purpose |
|---|---|
| `simulation/Invoke-ServiceAbuseWalkthrough.ps1` | Print-only walkthrough of the chain with SOC notes |
| `tools/FTP-Utility.ps1` | Parameterized FTP client for moving lab files |
| `detection/sigma/` | Sigma rules for service-install and Wi-Fi key-dump indicators |
| `detection/kql/` | Microsoft Defender / Sentinel queries for the same behaviour |
| `docs/attack-chain.md` | Phase-by-phase detail, MITRE ATT&CK mapping, event IDs |

## The chain

1. **Staging.** A project file containing an inline C# task is written to a
   temporary directory. The task is compiled by MSBuild's `CodeTaskFactory` at
   build time, so no separate compiler is dropped.
2. **Service creation.** A service is installed with a binary path that launches
   `msbuild.exe` through `cmd.exe`. The service name is chosen to look benign.
3. **Proxy execution.** `services.exe` starts `cmd.exe`, which starts the
   signed `msbuild.exe`. The C# task runs inside MSBuild, outside PowerShell
   and its AMSI/script-block telemetry.
4. **Post-exploitation.** In the original exercise, the task downloaded a
   payload, collected local credentials, and uploaded the result over FTP. That
   working code is deliberately **not** included here; the walkthrough
   describes the actions and the evidence they leave.
5. **Cleanup.** The service and staged files are removed. Service installation
   records, process creation, prefetch, and the USN journal remain.

## Why it matters

- **Signed binary proxy execution.** `msbuild.exe` is a legitimate Microsoft
  binary, so allow-listing based on signer alone does not stop it.
- **No PowerShell.** The chain never needs `powershell.exe`, so Script Block
  Logging and AMSI provide little coverage.
- **Unusual parentage.** A service binary path that starts `cmd.exe` to launch
  `msbuild.exe` is rare in normal operations.
- **Collection leaves a fingerprint.** `netsh wlan ... key=clear` is a strong
  credential-access indicator when it appears in process creation telemetry.
- **Egress is observable.** Plain FTP to an external host on port 21 is easy to
  spot from a workstation that has no business using it.

## Telemetry map

| Source | Event | Look for |
|---|---|---|
| System | 7045 | Service installed; `ImagePath` contains `msbuild.exe` or `cmd.exe /c start` |
| Security | 4697 | Service installed (if audit policy enabled) |
| Security | 4688 | `services.exe → cmd.exe → msbuild.exe`; `netsh.exe` with `key=clear` |
| Sysmon | 1 | Process creation chain and command lines |
| Sysmon | 3 | Outbound connection to an FTP server, especially port 21 |
| Sysmon | 11 | `runner.proj` or similar project file created in `%TEMP%` |
| Sysmon | 22 | DNS query for the FTP host from the workstation |
| Defender | `DeviceProcessEvents` | `msbuild.exe` with `cmd.exe` parent, `netsh` key dump |
| Defender | `DeviceNetworkEvents` | FTP egress from a non-server endpoint |

## Detection content

### Sigma

- `detection/sigma/msbuild-service-install.yml` — service installed with an
  MSBuild binary path.
- `detection/sigma/netsh-wifi-key-dump.yml` — `netsh wlan` invoked with
  `key=clear`.

Both rules are intentionally narrow. Add your own allow-lists for build servers
before promoting them.

### KQL

`detection/kql/msbuild-service-abuse.kql` contains queries for service
installation, the process chain, Wi-Fi key access, and FTP egress. They target
the `Device*` and `SecurityEvent` tables used by Defender XDR and Sentinel.

## Using the lab

Use an isolated Windows virtual machine that you own. Do not run this on a
production host or a shared network.

1. Enable process creation auditing (4688) and, preferably, Sysmon with
   process, network, file-create, and DNS events.
2. Run the walkthrough:

   ```powershell
   .\simulation\Invoke-ServiceAbuseWalkthrough.ps1 -Pause
   ```

   It prints each phase, the telemetry to expect, and the detection notes. It
   makes no changes to the system.
3. Open your SIEM or Event Viewer and compare the described events with what
   your environment collects.
4. Adapt the Sigma and KQL rules, then test them against your own baseline.

## FTP lab client

`tools/FTP-Utility.ps1` is a small dependency-free client for moving files
between lab machines. It has no built-in host or credentials.

```powershell
$env:FTP_LAB_USER = "labuser"
$env:FTP_LAB_PASSWORD = "labpassword"

.\tools\FTP-Utility.ps1 list -Server 10.10.10.20
.\tools\FTP-Utility.ps1 download -Server 10.10.10.20 -FileName sample.txt -LocalPath .\sample.txt
.\tools\FTP-Utility.ps1 upload -Server 10.10.10.20 -FileName .\sample.txt -LocalPath sample.txt
```

Plain FTP sends credentials and content in clear text. Use it only on an
isolated lab network. Prefer SFTP or FTPS everywhere else.

## What was intentionally left out

The original exercise included a working credential harvester, an FTP
exfiltration payload, and a `-Execute` path that created the service. None of
that is published here. The goal of this repository is detection and
understanding, not a reusable attack tool.

## Limitations

- The event IDs and field names are Windows- and Sysmon-specific. Defender
  XDR table and column names can change.
- Service installation telemetry depends on audit policy. Without 4688 and
  Sysmon, the chain is much harder to see.
- The rules are starting points, not a complete detection program. Validate
  them against your own build infrastructure and baseline.

## Ethical use

Use this material only on systems you own or are explicitly authorised to test.
The walkthrough is documentation. Do not use it to access credentials or data
that are not yours. If you find a real exposure, report it and rotate the
credential.

## License

MIT. Copyright (c) 2026 Eclipsemanic. See [LICENSE](LICENSE).
