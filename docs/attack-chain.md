# Attack chain reference

This document describes the chain for defenders. It is intentionally
descriptive: it contains no working runner, payload, or credential harvester.

## Phase 1 — Stage an MSBuild project

A project file is written to a user-writable directory such as `%TEMP%`. The
file contains an inline C# task compiled by `CodeTaskFactory`. The task is
executed when MSBuild builds the project, so the technique needs only a signed
Microsoft binary and a text file.

**Telemetry**

- Sysmon Event 11: file create for a `.proj` file in a temp path.
- Sysmon Event 1: `msbuild.exe` with a project path under `%TEMP%`.
- File-system auditing, if enabled: create event and the writing process.

**Hunting idea**

Look for `msbuild.exe` on endpoints that do not build software, especially with
a project file outside a repository or build directory.

## Phase 2 — Install a service

A service is created with an image path that runs `cmd.exe` and launches
`msbuild.exe` with the project file. The service name is chosen to resemble a
system component. The `start /b` pattern detaches MSBuild so `cmd.exe` can exit.

**Telemetry**

- System Event 7045: service installed; `ImagePath` contains `msbuild.exe`.
- Security Event 4697: service installed (requires audit policy).
- Security Event 4688: `services.exe` spawning `cmd.exe`.
- Sysmon Event 1: the parent chain.

**False positives**

- Build servers that install a build agent as a service. Allow-list known
  agents by name, path, and signer rather than excluding MSBuild globally.

## Phase 3 — Proxy execution

The service manager starts `cmd.exe`, which starts `msbuild.exe`. MSBuild
compiles the inline C# and runs it in-process. There is no `powershell.exe`,
so PowerShell logging and AMSI have no visibility into the task.

**Telemetry**

- Sysmon Event 1: `cmd.exe` then `msbuild.exe`; command line includes the
  project path.
- Sysmon Event 11: project file read and temp artifacts.
- Event 4688 with command-line auditing.

**Detection logic**

Correlate the service-install event with the process chain on the same host
within a short window. The KQL file includes an example join with a
ten-minute window.

## Phase 4 — Collection and egress

In the original exercise, the inline task ran a hidden PowerShell payload,
collected Wi-Fi profiles with `netsh ... key=clear`, and uploaded the result to
a plain FTP server. The working code is not part of this repository.

**Telemetry**

- Security Event 4688 / Sysmon Event 1: `netsh.exe` with `wlan` and
  `key=clear`.
- Sysmon Event 3: outbound TCP 21 or another unexpected destination.
- Sysmon Event 22: DNS query for the FTP host.
- Proxy or firewall logs: FTP control and data channels.

**Why `key=clear` matters**

The parameter asks Windows to print the stored wireless key. It is a rare
operation outside manual recovery and is a strong credential-access signal.

## Phase 5 — Cleanup

The service is stopped and deleted, and staged files are removed. The following
usually remain:

- Event 7045/4697 (install) and 7036 (state change);
- process creation records;
- prefetch entries for `MSBUILD.EXE` and `CMD.EXE`;
- USN journal entries for the project file and payload;
- a runner log, if the task wrote one and did not delete it;
- the remote FTP server's copy of the uploaded file.

## MITRE ATT&CK

| Technique | ID | Use |
|---|---|---|
| Windows Service | T1543.003 | Persistence and execution through the SCM |
| MSBuild | T1127.001 | Proxy execution through a signed build tool |
| PowerShell | T1059.001 | Payload execution in the original exercise |
| Wi-Fi discovery | T1016 | Enumerating wireless profiles |
| Credentials from password stores | T1555 | Reading stored Wi-Fi keys |
| Exfiltration over alternative protocol | T1048 | FTP upload |

## Detection engineering notes

- **Do not key on MSBuild alone.** Build servers and developer laptops run it
  legitimately. Key on the service install, the parent chain, and the project
  path together.
- **Correlate across sources.** The service install is in the System log; the
  process chain is in Security/Sysmon; egress is in network telemetry.
- **Baseline first.** Record which hosts run MSBuild, which services are
  installed by your management tooling, and which hosts may use FTP.
- **Test the rule both ways.** Confirm it fires on the lab chain and stays quiet
  on a normal build.

## Safety

Run any lab reproduction only on an isolated Windows VM you own. Do not collect
credentials that are not yours, and do not upload data to a third-party service.
