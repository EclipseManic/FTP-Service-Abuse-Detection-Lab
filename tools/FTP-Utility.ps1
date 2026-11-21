<#
.SYNOPSIS
    Minimal FTP client for an isolated, authorised lab.
.DESCRIPTION
    Lists, downloads, and uploads files over plain FTP. There is no built-in
    host or credential: pass -Server and either -User/-Password or the
    FTP_LAB_USER / FTP_LAB_PASSWORD environment variables.

    Plain FTP sends credentials and data in clear text. Use it only on an
    isolated lab network that you own or are authorised to test.
.PARAMETER Command
    list, download, or upload.
.PARAMETER Server
    FTP server host name or IP address.
.PARAMETER Port
    FTP control port. Default: 21.
.PARAMETER User
    FTP user. Falls back to FTP_LAB_USER.
.PARAMETER Password
    FTP password. Falls back to FTP_LAB_PASSWORD.
.PARAMETER FileName
    Remote file for download, or local file for upload.
.PARAMETER LocalPath
    Local output path for download, or remote name for upload.
.EXAMPLE
    $env:FTP_LAB_USER = "labuser"
    $env:FTP_LAB_PASSWORD = "labpassword"
    .\FTP-Utility.ps1 list -Server 10.10.10.20
.EXAMPLE
    .\FTP-Utility.ps1 download -Server 10.10.10.20 -FileName sample.txt -LocalPath .\sample.txt
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("list", "download", "upload")]
    [string]$Command,

    [Parameter(Mandatory = $true)]
    [string]$Server,

    [int]$Port = 21,

    [string]$User = $env:FTP_LAB_USER,
    [string]$Password = $env:FTP_LAB_PASSWORD,

    [Parameter(Position = 1)]
    [string]$FileName,

    [Parameter(Position = 2)]
    [string]$LocalPath
)

if (-not $User -or -not $Password) {
    throw "Set FTP_LAB_USER and FTP_LAB_PASSWORD, or pass -User and -Password."
}

$script:FtpHost = $Server
$script:FtpPort = $Port

function Connect-FtpControl {
    $socket = New-Object System.Net.Sockets.TcpClient
    $socket.Connect($script:FtpHost, $script:FtpPort)
    $socket.ReceiveTimeout = 10000
    $stream = $socket.GetStream()
    $stream.ReadTimeout = 10000
    $reader = New-Object System.IO.StreamReader($stream)
    $writer = New-Object System.IO.StreamWriter($stream)
    $reader.ReadLine() | Out-Null
    return @{ Socket = $socket; Reader = $reader; Writer = $writer }
}

function Send-Ftp {
    param($Control, [string]$Cmd)
    $Control.Writer.WriteLine($Cmd)
    $Control.Writer.Flush()
}

function Read-Ftp {
    param($Control)
    try { return $Control.Reader.ReadLine() }
    catch { return $null }
}

function Get-FtpPassivePort {
    param($Control)
    Send-Ftp $Control "EPSV"
    $resp = Read-Ftp $Control
    if ($resp -match '\(\|\|\|(\d+)\|\)') {
        return @{ Host = $script:FtpHost; Port = [int]$Matches[1] }
    }

    Send-Ftp $Control "PASV"
    $resp = Read-Ftp $Control
    $m = [regex]::Match($resp, '\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)')
    if ($m.Success) {
        $ip = "$($m.Groups[1]).$($m.Groups[2]).$($m.Groups[3]).$($m.Groups[4])"
        return @{ Host = $ip; Port = [int]$m.Groups[5] * 256 + [int]$m.Groups[6] }
    }

    throw "Cannot negotiate a passive data port: $resp"
}

function Connect-FtpData {
    param($Control, [int]$MaxRetries = 3)
    $err = $null
    for ($i = 0; $i -lt $MaxRetries; $i++) {
        $p = Get-FtpPassivePort $Control
        Write-Verbose "Data connection: $($p.Host):$($p.Port)"
        try {
            $data = New-Object System.Net.Sockets.TcpClient
            $data.Connect($p.Host, $p.Port)
            return @{ Socket = $data; Port = $p }
        }
        catch {
            $err = $_.Exception.Message
            if ($i -lt $MaxRetries - 1) { Start-Sleep -Milliseconds 250 }
        }
    }
    throw "Data connection failed: $err"
}

function Open-FtpSession {
    $c = Connect-FtpControl
    Send-Ftp $c "USER $User"; Read-Ftp $c | Out-Null
    Send-Ftp $c "PASS $Password"; Read-Ftp $c | Out-Null
    return $c
}

function Close-FtpSession {
    param($Control, $Data)
    if ($Data) { $Data.Socket.Close() }
    $Control.Reader.Close()
    $Control.Writer.Close()
    $Control.Socket.Close()
}

function Invoke-FtpList {
    Write-Host "  [FTP] Listing $script:FtpHost`:$script:FtpPort..." -ForegroundColor Cyan
    try {
        $c = Open-FtpSession
        $d = Connect-FtpData $c
        Send-Ftp $c "LIST"
        $pre = Read-Ftp $c
        if ($pre -match "^[45]") { throw "LIST failed: $pre" }

        $dr = New-Object System.IO.StreamReader($d.Socket.GetStream())
        $listing = $dr.ReadToEnd()
        $dr.Close()
        Read-Ftp $c | Out-Null
        Close-FtpSession $c $d

        $lines = ($listing -split "`r?`n") | Where-Object { $_.Trim() -ne "" }
        Write-Host "`n  Files ($($lines.Count)):" -ForegroundColor Green
        $lines | ForEach-Object { Write-Host "    $_" }
    }
    catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Yellow }
}

function Invoke-FtpDownload {
    param([string]$RemoteFile, [string]$OutputPath)
    if (-not $RemoteFile) { Write-Host "  [!] Specify a file to download" -ForegroundColor Yellow; return }
    if (-not $OutputPath) { $OutputPath = Split-Path $RemoteFile -Leaf }

    Write-Host "  [FTP] Downloading '$RemoteFile'..." -ForegroundColor Cyan
    try {
        $c = Open-FtpSession
        $d = Connect-FtpData $c
        Send-Ftp $c "RETR $RemoteFile"
        $pre = Read-Ftp $c
        if ($pre -match "^[45]") { throw "RETR failed: $pre" }

        $ds = $d.Socket.GetStream()
        $buffer = New-Object byte[] 4096
        $fs = [System.IO.File]::OpenWrite($OutputPath)
        while (($read = $ds.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fs.Write($buffer, 0, $read)
        }
        $fs.Close()
        $ds.Close()
        Read-Ftp $c | Out-Null
        Close-FtpSession $c $d

        $size = (Get-Item $OutputPath -ErrorAction SilentlyContinue).Length
        Write-Host "  [OK] $size bytes -> '$OutputPath'" -ForegroundColor Green
    }
    catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Yellow }
}

function Invoke-FtpUpload {
    param([string]$SourcePath, [string]$RemoteName)
    if (-not $SourcePath) { Write-Host "  [!] Specify a file to upload" -ForegroundColor Yellow; return }
    if (-not (Test-Path $SourcePath)) { Write-Host "  [!] Not found: $SourcePath" -ForegroundColor Yellow; return }
    if (-not $RemoteName) { $RemoteName = Split-Path $SourcePath -Leaf }

    Write-Host "  [FTP] Uploading '$RemoteName'..." -ForegroundColor Cyan
    try {
        $c = Open-FtpSession
        $d = Connect-FtpData $c
        Send-Ftp $c "STOR $RemoteName"
        $pre = Read-Ftp $c
        if ($pre -match "^[45]") { throw "STOR failed: $pre" }

        $ds = $d.Socket.GetStream()
        $buffer = New-Object byte[] 4096
        $fs = [System.IO.File]::OpenRead($SourcePath)
        while (($read = $fs.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $ds.Write($buffer, 0, $read)
        }
        $fs.Close()
        $ds.Close()
        Read-Ftp $c | Out-Null
        Close-FtpSession $c $d

        Write-Host "  [OK] Uploaded '$RemoteName'" -ForegroundColor Green
    }
    catch { Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Yellow }
}

Write-Warning "Plain FTP sends credentials and content in clear text. Use an isolated lab network only."

switch ($Command) {
    "list"     { Invoke-FtpList }
    "download" { Invoke-FtpDownload -RemoteFile $FileName -OutputPath $LocalPath }
    "upload"   { Invoke-FtpUpload -SourcePath $FileName -RemoteName $LocalPath }
}
