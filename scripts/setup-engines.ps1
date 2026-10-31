param(
    [switch]$SkipNuclei,
    [switch]$SkipWapiti,
    [switch]$SkipDocker
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$engineHome = if ($env:SITEAUDIT_ENGINE_HOME) {
    [Environment]::ExpandEnvironmentVariables($env:SITEAUDIT_ENGINE_HOME)
} else {
    Join-Path $env:LOCALAPPDATA "SiteAudit\engines"
}
$binHome = Join-Path $engineHome "bin"
$manifest = [ordered]@{
    generated_at = [DateTime]::UtcNow.ToString("o")
    engine_home = $engineHome
    installed = @{}
    skipped = @{}
    failed = @{}
}

New-Item -ItemType Directory -Force -Path $binHome | Out-Null
Write-Host "SiteAudit engine setup"
Write-Host "Managed tool directory: $engineHome"
Write-Host "This installs tools for the current Windows user; it does not scan a website."

if (-not $SkipNuclei) {
    Write-Host "`n[1/3] Installing Nuclei v3.11.1 and its official template pack..."
    try {
    $tag = "v3.11.1"
    $release = Invoke-RestMethod -Headers @{ "User-Agent" = "SiteAudit-engine-setup" } `
        -Uri "https://api.github.com/repos/projectdiscovery/nuclei/releases/tags/$tag"
    $assetName = if ([Environment]::Is64BitOperatingSystem) { "nuclei_3.11.1_windows_amd64.zip" } else { "nuclei_3.11.1_windows_386.zip" }
    $asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
    if (-not $asset) { throw "Official Nuclei release asset $assetName was not found." }
    if ($asset.digest -notmatch "^sha256:([0-9a-fA-F]{64})$") {
        throw "GitHub did not provide a SHA-256 digest for $assetName; refusing to install an unverified archive."
    }

    $tempRoot = Join-Path $env:TEMP "siteaudit-nuclei-$PID"
    $archive = Join-Path $tempRoot $assetName
    $extract = Join-Path $tempRoot "extracted"
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
    try {
        Invoke-WebRequest -UseBasicParsing -Headers @{ "User-Agent" = "SiteAudit-engine-setup" } -Uri $asset.browser_download_url -OutFile $archive
        $actualDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
        $expectedDigest = $asset.digest.Substring(7).ToLowerInvariant()
        if ($actualDigest -ne $expectedDigest) { throw "Nuclei archive SHA-256 did not match GitHub release metadata." }
        Expand-Archive -LiteralPath $archive -DestinationPath $extract -Force
        $nucleiExe = Get-ChildItem -LiteralPath $extract -Filter "nuclei.exe" -File -Recurse | Select-Object -First 1
        if (-not $nucleiExe) { throw "The verified Nuclei archive did not contain nuclei.exe." }
        Copy-Item -LiteralPath $nucleiExe.FullName -Destination (Join-Path $binHome "nuclei.exe") -Force
        $license = Get-ChildItem -LiteralPath $extract -File -Recurse | Where-Object { $_.Name -match "^LICENSE(\..*)?$" } | Select-Object -First 1
        if ($license) {
            $licenseHome = Join-Path $engineHome "licenses\nuclei"
            New-Item -ItemType Directory -Force -Path $licenseHome | Out-Null
            Copy-Item -LiteralPath $license.FullName -Destination (Join-Path $licenseHome $license.Name) -Force
        }
    } finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    $templateHome = Join-Path $engineHome "nuclei-templates"
    & (Join-Path $binHome "nuclei.exe") -update-templates -update-template-dir $templateHome
    if ($LASTEXITCODE -ne 0) { throw "Nuclei failed to install its signed template pack (exit code $LASTEXITCODE)." }
    $manifest.installed.nuclei = @{
        version = $tag
        executable = Join-Path $binHome "nuclei.exe"
        templates = $templateHome
        source = "https://github.com/projectdiscovery/nuclei/releases/tag/$tag"
    }
    } catch {
        $manifest.failed.nuclei = $_.Exception.Message
        Write-Warning "Nuclei setup failed: $($_.Exception.Message)"
    }
} else {
    $manifest.skipped.nuclei = "requested by command line"
}

if (-not $SkipWapiti) {
    Write-Host "`n[2/3] Installing Wapiti into an isolated Python 3.12+ environment..."
    try {
    $pyLauncher = Get-Command "py.exe" -ErrorAction SilentlyContinue
    $pythonExecutable = $null
    if ($pyLauncher) {
        $installedRuntimes = @(& $pyLauncher.Source -0p 2>$null)
        foreach ($minor in @("3.14", "3.13", "3.12")) {
            foreach ($runtimeLine in $installedRuntimes) {
                if ("$runtimeLine" -match "^\s*-V:$([regex]::Escape($minor))\s+\*?\s*(.+python(?:\.exe)?)\s*$") {
                    $candidate = $Matches[1].Trim()
                    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                        $pythonExecutable = $candidate
                        break
                    }
                }
            }
            if ($pythonExecutable) { break }
        }
    }
    if (-not $pythonExecutable) {
        $manifest.skipped.wapiti = "Python 3.12, 3.13, or 3.14 was not found with the Windows py launcher."
        Write-Warning $manifest.skipped.wapiti
    } else {
        $wapitiHome = Join-Path $engineHome "wapiti"
        $wapitiPython = Join-Path $wapitiHome "Scripts\python.exe"
        if (-not (Test-Path -LiteralPath $wapitiPython -PathType Leaf)) {
            & $pythonExecutable -m venv $wapitiHome
            if ($LASTEXITCODE -ne 0) { throw "Could not create Wapiti's isolated virtual environment." }
        }
        & $wapitiPython -m pip install --disable-pip-version-check "wapiti3==3.3.2"
        if ($LASTEXITCODE -ne 0) { throw "Wapiti installation failed." }
        $wapitiVersion = & $wapitiPython -c "import importlib.metadata; print(importlib.metadata.version('wapiti3'))"
        if ($LASTEXITCODE -ne 0) { throw "Could not read the installed Wapiti version." }
        $manifest.installed.wapiti = @{
            version = ("$wapitiVersion").Trim()
            executable = Join-Path $wapitiHome "Scripts\wapiti.exe"
            source = "https://pypi.org/project/wapiti3/3.3.2/"
        }
    }
    } catch {
        $manifest.failed.wapiti = $_.Exception.Message
        Write-Warning "Wapiti setup failed: $($_.Exception.Message)"
    }
} else {
    $manifest.skipped.wapiti = "requested by command line"
}

if (-not $SkipDocker) {
    Write-Host "`n[3/3] Checking Docker and pulling the official Nikto and ZAP images..."
    try {
    $docker = Get-Command "docker.exe" -ErrorAction SilentlyContinue
    if (-not $docker) { $docker = Get-Command "docker" -ErrorAction SilentlyContinue }
    if (-not $docker) {
        $manifest.skipped.docker = "Docker Desktop/CLI was not found. Install Docker Desktop, start it, and rerun setup-engines.bat."
        Write-Warning $manifest.skipped.docker
    } else {
        & $docker.Source info --format "{{.ServerVersion}}" *> $null
        if ($LASTEXITCODE -ne 0) {
            $manifest.skipped.docker = "Docker is installed but its daemon is not running. Start Docker Desktop and rerun setup-engines.bat."
            Write-Warning $manifest.skipped.docker
        } else {
            $containerOs = & $docker.Source info --format "{{.OSType}}" 2>$null
            if ("$containerOs".Trim() -ne "linux") {
                $manifest.skipped.docker = "Docker Desktop is not using Linux containers. Switch to Linux containers and rerun setup-engines.bat."
                Write-Warning $manifest.skipped.docker
            } else {
            foreach ($image in @("ghcr.io/sullo/nikto:2.6.1", "ghcr.io/zaproxy/zaproxy:stable")) {
                & $docker.Source pull $image
                if ($LASTEXITCODE -ne 0) {
                    $manifest.failed.docker = "Docker could not pull $image."
                    Write-Warning $manifest.failed.docker
                    break
                }
                $imageName = $image.Split(":")[0]
                $manifest.installed[$imageName] = @{ image = $image }
            }
            }
        }
    }
    } catch {
        $manifest.failed.docker = $_.Exception.Message
        Write-Warning "Docker engine setup failed: $($_.Exception.Message)"
    }
} else {
    $manifest.skipped.docker = "requested by command line"
}

$manifest.skipped.w3af = "W3AF is a legacy Linux/macOS scanner and is not installed or run by this Windows setup script."
$manifestPath = Join-Path $engineHome "setup-engines-last-run.json"
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Host "`nSetup finished. Read-only readiness check: .venv\Scripts\python.exe -m siteaudit --doctor"
Write-Host "W3AF remains unavailable in native Windows mode. See README.md for its platform limits."
Write-Host "This manifest records only this setup run; engine readiness is shown by --doctor."
Write-Host "Manifest: $manifestPath"
if ($manifest.failed.Count -gt 0) { exit 1 }
