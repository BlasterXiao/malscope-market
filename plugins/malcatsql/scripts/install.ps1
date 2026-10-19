<#
.SYNOPSIS
    Install the malcatsql engine on this machine so the `malcatsql` command works.

.DESCRIPTION
    Idempotent; safe to run again to upgrade. Steps:
      1. check CPython 3.13 (Malcat's malcat.pyd is built for 3.13 only)
      2. make `import malcat` work: write malcat.pth (= <Malcat>\bin) into 3.13's user site-packages,
         which is what Malcat's install_api.py does (license activation is NOT done here)
      3. pip install the engine with its server extras
      4. add the folder holding malcatsql.exe to the USER PATH (skip with -NoPath)
    The last line printed is `MALCATSQL_EXE=<full path>`: use it in the current shell, new shells
    find `malcatsql` on PATH.

.PARAMETER MalcatDir
    Malcat install folder (the one containing bin\malcat.pyd). Auto-detected when omitted.
.PARAMETER Source
    pip source of the engine. Default: tools/malcatsql of the public malscope-market repository.
    A local folder (e.g. a checkout's tools\malcatsql) also works.
.PARAMETER Editable
    With a local -Source: install in editable (development) mode.
.PARAMETER NoPath
    Do not touch the user PATH.

.EXAMPLE
    pwsh -NoProfile -File install.ps1
.EXAMPLE
    pwsh -NoProfile -File install.ps1 -MalcatDir D:\Tools\malcat -Source C:\src\malscope-market\tools\malcatsql -Editable
#>
param(
    [string]$MalcatDir,
    [string]$Source = 'git+https://github.com/BlasterXiao/malscope-market.git#subdirectory=tools/malcatsql',
    [switch]$Editable,
    [switch]$NoPath
)

$ErrorActionPreference = 'Stop'

function Step([string]$text) { Write-Host "==> $text" }
function Fail([string]$text) { Write-Host "ERROR: $text"; exit 1 }

function Py313([string[]]$pyArgs) {
    # returns stdout lines; $LASTEXITCODE tells success
    & py -3.13 @pyArgs 2>&1
}

# 1. CPython 3.13 ---------------------------------------------------------------------------------
Step 'checking CPython 3.13'
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    Fail 'the Python launcher `py` is missing. Install CPython 3.13 from python.org (or: winget install Python.Python.3.13), then run this script again.'
}
$ver = Py313 @('-c', 'import sys; print(sys.version.split()[0])')
if ($LASTEXITCODE -ne 0) {
    Fail 'CPython 3.13 is not installed (py -3.13 fails). Install it from python.org (or: winget install Python.Python.3.13), then run this script again.'
}
Write-Host "    Python $ver"

# 2. Malcat API -----------------------------------------------------------------------------------
Step 'checking that Python 3.13 can import malcat'
$null = Py313 @('-c', 'import malcat')
if ($LASTEXITCODE -ne 0) {
    if (-not $MalcatDir) {
        $candidates = @()
        $exe = Get-Command malcat.exe -ErrorAction SilentlyContinue
        if ($exe) { $candidates += (Split-Path (Split-Path $exe.Source)) }
        $candidates += @("$env:ProgramFiles\Malcat", "$env:LOCALAPPDATA\Programs\Malcat")
        foreach ($drive in (Get-PSDrive -PSProvider FileSystem).Root) {
            $candidates += (Get-ChildItem -Path $drive -Directory -Filter 'malcat*' -ErrorAction SilentlyContinue).FullName
        }
        $MalcatDir = $candidates | Where-Object { $_ -and (Test-Path (Join-Path $_ 'bin\malcat.pyd')) } |
            Select-Object -First 1
    }
    if (-not $MalcatDir -or -not (Test-Path (Join-Path $MalcatDir 'bin\malcat.pyd'))) {
        Fail 'Malcat was not found. Run again with -MalcatDir <folder that contains bin\malcat.pyd>.'
    }
    $userSite = (Py313 @('-c', 'import site; print(site.getusersitepackages())') | Select-Object -Last 1).Trim()
    New-Item -ItemType Directory -Force -Path $userSite | Out-Null
    $bin = Join-Path (Resolve-Path $MalcatDir).Path 'bin'
    [System.IO.File]::WriteAllText((Join-Path $userSite 'malcat.pth'), "$bin`n")
    Write-Host "    wrote $userSite\malcat.pth -> $bin"
    $err = Py313 @('-c', 'import malcat')
    if ($LASTEXITCODE -ne 0) {
        Fail "import malcat still fails: $($err | Select-Object -Last 1). Check that this Malcat is 0.9.x and its license allows the Python API (activate the license in Malcat yourself)."
    }
}
Write-Host '    import malcat: ok'

# 3. engine ----------------------------------------------------------------------------------------
Step "installing malcatsql from $Source"
$isLocal = Test-Path $Source
if ($Editable -and -not $isLocal) { Fail '-Editable needs a local -Source folder.' }
$spec = if ($isLocal) { "$((Resolve-Path $Source).Path)[server]" } else { "malcatsql[server] @ $Source" }
$pipArgs = @('-m', 'pip', 'install', '--upgrade', '--disable-pip-version-check')
if ($Editable) { $pipArgs += '-e' }
$pipArgs += $spec
& py -3.13 @pipArgs
if ($LASTEXITCODE -ne 0) { Fail 'pip install failed (see the output above).' }

# 4. launcher on PATH -----------------------------------------------------------------------------
Step 'locating malcatsql.exe'
$dirs = Py313 @('-c', 'import sysconfig; print(sysconfig.get_path("scripts", "nt_user")); print(sysconfig.get_path("scripts"))')
$launcher = $dirs | ForEach-Object { Join-Path $_.Trim() 'malcatsql.exe' } | Where-Object { Test-Path $_ } |
    Select-Object -First 1
if (-not $launcher) { Fail 'malcatsql.exe was not created by pip.' }
$scriptsDir = Split-Path $launcher
Write-Host "    $launcher"

if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $known = (($userPath, $machinePath) -join ';').Split(';') | ForEach-Object { $_.Trim().TrimEnd('\') }
    if ($known -notcontains $scriptsDir.TrimEnd('\')) {
        $newPath = if ($userPath) { "$($userPath.TrimEnd(';'));$scriptsDir" } else { $scriptsDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "    added to the user PATH: $scriptsDir (new terminals pick it up)"
    } else {
        Write-Host '    already on PATH'
    }
}

$version = & $launcher --version
if ($LASTEXITCODE -ne 0) { Fail 'malcatsql --version failed.' }
Write-Host "    $version"
Write-Host "MALCATSQL_EXE=$launcher"
