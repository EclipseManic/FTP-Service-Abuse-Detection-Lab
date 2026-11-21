<#
.SYNOPSIS
    Print-only walkthrough of MSBuild inline-C# proxy execution behind a service.
.DESCRIPTION
    Explains each phase of the chain and the telemetry it leaves. This script
    does not create files, services, processes, or network connections. No
    payload or credential-harvesting code is included.

    Run it on an isolated lab workstation to brief a team, or read the output
    alongside the detection rules in ../detection.
.PARAMETER Pause
    Wait for ENTER between phases. Useful when presenting.
.EXAMPLE
    .\Invoke-ServiceAbuseWalkthrough.ps1 -Pause
#>

[CmdletBinding()]
param(
    [switch]$Pause
)

$SEP = "=" * 72
$THIN = "-" * 72

function Show-Phase {
    param([string]$Title)
    Write-Host ""
    Write-Host $SEP -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $SEP -ForegroundColor Cyan
}

function Show-Item {
    param([string]$Label, [string]$Text)
    Write-Host ("  {0,-12} {1}" -f $Label, $Text) -ForegroundColor Gray
}

function Show-Detection {
    param([string]$Text)
    Write-Host "  [DETECT]     $Text" -ForegroundColor Magenta
}

function Pause-Phase {
    param([string]$Next)
    if ($Pause) {
        Write-Host ""
        Write-Host "  Press ENTER to continue to: $Next" -ForegroundColor DarkGray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

Write-Host ""
Write-Host "  Windows Service Abuse Detection Lab" -ForegroundColor White
Write-Host "  Simulation only - no system changes are made." -ForegroundColor Yellow
Write-Host "  No payload, harvester, or execution routine is present." -ForegroundColor Yellow
Write-Host $THIN -ForegroundColor DarkGray

Show-Phase "Phase 1 - Staging the MSBuild project"
Show-Item "What" "A .proj file containing an inline C# task is written to a temp directory."
Show-Item "Why" "MSBuild compiles the task at build time through CodeTaskFactory. No compiler binary is dropped."
Show-Item "Artifact" "A project file in %TEMP%, often named runner.proj or similar."
Show-Detection "Sysmon Event 11 (FileCreate) for a .proj file in a user temp path."
Show-Detection "Unexpected msbuild.exe activity on a workstation that does not build software."
Pause-Phase "Phase 2"

Show-Phase "Phase 2 - Creating the service"
Show-Item "What" "A service is installed whose binary path starts cmd.exe, then msbuild.exe with the project file."
Show-Item "Why" "The SCM launches a signed Microsoft binary, and cmd.exe exits immediately while MSBuild keeps running."
Show-Item "Tell" "The service name imitates a system component; the image path contains msbuild.exe."
Show-Detection "System Event 7045 and Security Event 4697: service install with msbuild in ImagePath."
Show-Detection "Security Event 4688: services.exe -> cmd.exe -> msbuild.exe."
Pause-Phase "Phase 3"

Show-Phase "Phase 3 - Proxy execution"
Show-Item "What" "msbuild.exe compiles and runs the inline C# task outside PowerShell."
Show-Item "Why" "There is no powershell.exe, so AMSI and Script Block Logging do not see the task."
Show-Item "Tell" "msbuild.exe with a parent of cmd.exe or services.exe, and a project file in temp."
Show-Detection "Sysmon Event 1: unusual parent chain and command line."
Show-Detection "Correlate with Event 7045 on the same host within seconds."
Pause-Phase "Phase 4"

Show-Phase "Phase 4 - Post-exploitation (described, not shipped)"
Show-Item "Collection" "The original exercise collected local Wi-Fi profiles with netsh and the key=clear parameter."
Show-Item "Egress" "It uploaded the result to a plain FTP server on port 21."
Show-Item "Omitted" "The working harvester and upload routine are intentionally not part of this repository."
Show-Detection "Security Event 4688 / Sysmon 1: netsh.exe with wlan and key=clear."
Show-Detection "Sysmon 3 / DeviceNetworkEvents: outbound TCP 21 from a workstation."
Show-Detection "Sysmon 22: DNS query for an unexpected FTP host."
Pause-Phase "Phase 5"

Show-Phase "Phase 5 - Cleanup and residual evidence"
Show-Item "What" "The service and staged files are removed."
Show-Item "Limit" "Service install records, process creation events, prefetch, and the USN journal remain."
Show-Item "Gap" "A runner log left in temp can outlive the cleanup and preserve the timeline."
Show-Detection "Event 7045/4697 and 7036 remain after the service is deleted."
Show-Detection "Prefetch: MSBUILD.EXE-*.pf and CMD.EXE-*.pf."
Show-Detection "USN journal entries for the project file create and delete."

Write-Host ""
Write-Host $SEP -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor White
Write-Host $THIN -ForegroundColor DarkGray
Write-Host "  Chain     : services.exe -> cmd.exe -> msbuild.exe -> inline C#" -ForegroundColor Gray
Write-Host "  ATT&CK    : T1543.003 (Windows Service), T1127 (MSBuild), T1005, T1048" -ForegroundColor Gray
Write-Host "  Best signal: 7045/4697 with msbuild in ImagePath, plus the process chain." -ForegroundColor Gray
Write-Host "  Next      : adapt detection/sigma and detection/kql to your environment." -ForegroundColor Gray
Write-Host $SEP -ForegroundColor Cyan
Write-Host ""
