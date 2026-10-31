param()

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$wsl = Get-Command "wsl.exe" -ErrorAction SilentlyContinue
if (-not $wsl) { throw "wsl.exe was not found. Install WSL2 and Debian first." }

$distribution = "Debian"
$version = "2.17.0"
$installRoot = "/opt/siteaudit/zap-$version"
$archiveUrl = "https://github.com/zaproxy/zaproxy/releases/download/v$version/ZAP_$($version)_Linux.tar.gz"
$versionsXmlUrl = "https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions.xml"
$expectedSha256 = "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a"

function Invoke-Wsl {
    param([Parameter(Mandatory = $true)][string[]]$LinuxArguments, [string]$User)
    $arguments = @("--distribution", $distribution)
    if ($User) { $arguments += @("--user", $User) }
    $arguments += @("--exec") + $LinuxArguments
    & $wsl.Source @arguments
    if ($LASTEXITCODE -ne 0) { throw "WSL command failed ($LASTEXITCODE): $($LinuxArguments -join ' ')" }
}

$distroOutput = & $wsl.Source --list --verbose 2>$null
if ($LASTEXITCODE -ne 0) { throw "Could not list WSL distributions." }
$distroText = (($distroOutput -join "`n") -replace "`0", "" -replace "`r", "")
if ($distroText -notmatch "(?m)^\s*\*?\s*Debian\s+\S+\s+2\s*$") {
    throw "WSL Debian version 2 was not found. Install with 'wsl --install -d Debian'."
}

Write-Host "Installing OWASP ZAP $version in WSL Debian. This setup does not scan a website."
Write-Host "The official Linux archive is about 233 MiB; its SHA-256 is pinned from $versionsXmlUrl."
Write-Host "Installation path: $installRoot (outside the project repository)."
$dependencyCheck = @'
for package in curl ca-certificates iproute2 coreutils findutils gawk; do
    dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed' || exit 1
done
'@
& $wsl.Source --distribution $distribution --user root --exec bash -lc $dependencyCheck *> $null
$dependenciesReady = ($LASTEXITCODE -eq 0)
$javaVersionCheck = @'
version=$(java -version 2>&1 | sed -n '1s/.*version "\([^"]*\)".*/\1/p' || true)
major=${version%%.*}
if [[ "$version" == 1.* ]]; then major=${version#1.}; major=${major%%.*}; fi
[ "${major:-0}" -ge 17 ]
'@
& $wsl.Source --distribution $distribution --exec bash -lc $javaVersionCheck *> $null
$javaReady = ($LASTEXITCODE -eq 0)
$javaPackage = $null
if (-not $javaReady) {
    $javaPackageProbe = @'
if apt-cache show openjdk-21-jre-headless >/dev/null 2>&1; then
  printf '%s\n' openjdk-21-jre-headless
elif apt-cache show openjdk-17-jre-headless >/dev/null 2>&1; then
  printf '%s\n' openjdk-17-jre-headless
else
  printf 'No Java 17+ runtime package is available in the configured Debian repositories.\n' >&2
  exit 1
fi
'@
    $javaPackage = (Invoke-Wsl -User "root" -LinuxArguments @("bash", "-lc", $javaPackageProbe) | Select-Object -Last 1).Trim()
    if ($javaPackage -notin @("openjdk-21-jre-headless", "openjdk-17-jre-headless")) {
        throw "Could not select a supported Java 17+ package for ZAP."
    }
}
if (-not $dependenciesReady -or -not $javaReady) {
    Invoke-Wsl -User "root" -LinuxArguments @("apt-get", "update")
    $packages = @("curl", "ca-certificates", "iproute2", "coreutils", "findutils", "gawk")
    if ($javaPackage) { $packages += $javaPackage }
    Invoke-Wsl -User "root" -LinuxArguments (@("apt-get", "install", "-y") + $packages)
}
Invoke-Wsl -LinuxArguments @("test", "-x", "/usr/bin/timeout")
Invoke-Wsl -LinuxArguments @("test", "-x", "/usr/bin/wslpath")
Invoke-Wsl -LinuxArguments @("bash", "-lc", "java --version 2>&1 | head -n 1")

$installScript = @'
set -euo pipefail
version='2.17.0'
expected='efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a'
url='https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz'
install='/opt/siteaudit/zap-2.17.0'
stage='/opt/siteaudit/.zap-stage-2.17.0'

if [ -d "$install" ]; then
  if [ -x "$install/zap.sh" ] && [ "$(cat "$install/.siteaudit-sha256" 2>/dev/null || true)" = "$expected" ]; then
    version_output=$("$install/zap.sh" -version)
    printf '%s\n' "$version_output" | grep -Fx "$version" >/dev/null
    printf 'Pinned ZAP %s is already installed at %s\n' "$version" "$install"
    exit 0
  fi
  printf 'Existing install is not the pinned ZAP build; refusing to replace it.\n' >&2
  exit 12
fi
mkdir -p /opt/siteaudit
if [ -e "$stage" ]; then
  printf 'Staging path already exists; inspect it before retrying.\n' >&2
  exit 13
fi
download_dir='/opt/siteaudit/.downloads'
install -d -m 700 "$download_dir"
archive="$download_dir/ZAP_2.17.0_Linux.tar.gz"
actual=''
if [ -f "$archive" ]; then
  actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
fi
if [ "$actual" != "$expected" ]; then
  curl --fail --location --retry 2 --connect-timeout 15 --max-time 1800 --continue-at - "$url" --output "$archive"
  actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
fi
if [ "$actual" != "$expected" ]; then
  printf 'ZAP archive SHA-256 mismatch; refusing extraction.\n' >&2
  rm -f -- "$archive"
  exit 14
fi
tar -tzf "$archive" | awk '$0 !~ /^ZAP_2\.17\.0(\/|$)/ || $0 ~ /(^|\/)\.\.(\/|$)|^\// { bad=1 } END { if (bad) exit 1 }'
mkdir "$stage"
tar -xzf "$archive" --strip-components=1 --no-same-owner -C "$stage"
test -x "$stage/zap.sh"
version_output=$("$stage/zap.sh" -version)
printf '%s\n' "$version_output" | grep -Fx "$version" >/dev/null
for prefix in automation- spider- pscanrules- reports-; do
  find "$stage/plugin" -maxdepth 1 -type f -name "$prefix*.zap" -print -quit | grep -q .
done
printf '%s\n' "$expected" > "$stage/.siteaudit-sha256"
chmod -R a+rX "$stage"
mv "$stage" "$install"
rm -f -- "$archive"
printf 'Pinned ZAP %s ready at %s (SHA-256 %s).\n' "$version" "$install" "$expected"
'@
Invoke-Wsl -User "root" -LinuxArguments @("bash", "-lc", $installScript)

Write-Host "Pinned OWASP ZAP setup completed (version $version, SHA-256 $expectedSha256)."
