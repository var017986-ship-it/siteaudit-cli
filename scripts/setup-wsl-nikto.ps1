param()

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$wsl = Get-Command "wsl.exe" -ErrorAction SilentlyContinue
if (-not $wsl) {
    throw "wsl.exe was not found. Install WSL2 and the Debian distribution first."
}

$distribution = "Debian"
$installRoot = "/opt/siteaudit/nikto-2.6.1"
$releaseTag = "2.6.1"
$pinnedCommitPrefix = "d201dac"
$sourceUrl = "https://github.com/sullo/nikto.git"

function Invoke-Wsl {
    param(
        [Parameter(Mandatory = $true)][string[]]$LinuxArguments,
        [string]$User
    )

    $arguments = @("--distribution", $distribution)
    if ($User) { $arguments += @("--user", $User) }
    $arguments += @("--exec") + $LinuxArguments
    & $wsl.Source @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed with exit code ${LASTEXITCODE}: $($LinuxArguments -join ' ')"
    }
}

$installedDistros = & $wsl.Source --list --quiet 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Could not list WSL distributions. Start WSL and retry."
}
$installedDistroText = (($installedDistros -join "`n") -replace "`0", "" -replace "`r", "")
if ($installedDistroText -notmatch "(?m)^\s*Debian\s*$") {
    throw "The WSL Debian distribution is not installed. Install it with 'wsl --install -d Debian', then rerun this script."
}

Write-Host "Installing upstream Nikto $releaseTag in WSL $distribution. No website will be scanned."
Write-Host "Source will remain outside the project repository at $installRoot."

Invoke-Wsl -User "root" -LinuxArguments @("apt-get", "update")
Invoke-Wsl -User "root" -LinuxArguments @(
    "apt-get", "install", "-y",
    "perl", "perl-modules-5.40", "libjson-pp-perl", "libnet-ssleay-perl", "libxml-writer-perl",
    "git", "ca-certificates", "iproute2", "coreutils"
)

$existingCommit = ""
& $wsl.Source --distribution $distribution --user root --exec git -C $installRoot rev-parse HEAD *> $null
$checkoutExists = ($LASTEXITCODE -eq 0)
if ($checkoutExists) {
    $existingCommit = (& $wsl.Source --distribution $distribution --user root --exec git -C $installRoot rev-parse HEAD 2>$null | Out-String).Trim()
    if ($existingCommit -notmatch "^$pinnedCommitPrefix[0-9a-f]{33}$") {
        throw "An existing Nikto checkout at $installRoot is not the pinned upstream commit $pinnedCommitPrefix. Move it aside before installing."
    }
} else {
    Invoke-Wsl -User "root" -LinuxArguments @("mkdir", "-p", "/opt/siteaudit")
    Invoke-Wsl -User "root" -LinuxArguments @(
        "git", "clone", "--depth", "1", "--branch", $releaseTag, $sourceUrl, $installRoot
    )
    $existingCommit = (& $wsl.Source --distribution $distribution --user root --exec git -C $installRoot rev-parse HEAD 2>$null | Out-String).Trim()
    if ($existingCommit -notmatch "^$pinnedCommitPrefix[0-9a-f]{33}$") {
        throw "The upstream tag did not resolve to the pinned commit $pinnedCommitPrefix. The checkout was left in place for inspection."
    }
}

Invoke-Wsl -LinuxArguments @(
    "perl", "-e", "use JSON::PP; use Net::SSLeay; use XML::Writer; use Time::Seconds;"
)
Invoke-Wsl -LinuxArguments @("test", "-x", "/usr/bin/timeout")
Invoke-Wsl -LinuxArguments @("test", "-x", "/usr/bin/wslpath")
Invoke-Wsl -LinuxArguments @("ip", "-4", "route", "show", "default")

Write-Host "Nikto $releaseTag is ready in WSL $distribution at $installRoot."
Write-Host "Verified upstream commit: $existingCommit"
