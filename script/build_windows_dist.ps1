param(
    [switch]$SkipTests,
    [switch]$StopRunning,
    [switch]$ReuseBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BinaryName = "windows-app-autologin"
$DistName = "WindowsAppAutoLogin-windows-x86_64"
$ExeName = "WindowsAppAutoLogin.exe"

$DistRoot = Join-Path $RootDir "dist"
$DistDir = Join-Path $DistRoot $DistName
$TargetExe = Join-Path $RootDir "target\release\$BinaryName.exe"
$DistExe = Join-Path $DistDir $ExeName

function Normalize-Path {
    param([string]$Path)

    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/').ToLowerInvariant()
}

function Require-Command {
    param([string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    $fallback = Join-Path $cargoBin "$Name.exe"
    if (Test-Path -LiteralPath $fallback) {
        $env:PATH = "$cargoBin;$env:PATH"
        return $fallback
    }

    throw "Required command not found: $Name"
}

function Invoke-Checked {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $FilePath @Arguments 2>&1 | ForEach-Object {
            Write-Host $_
        }
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Reset-DistDirectory {
    New-Item -ItemType Directory -Force -Path $DistRoot | Out-Null

    $resolvedDistRoot = (Resolve-Path $DistRoot).Path
    $distParent = Split-Path -Parent $DistDir
    $distLeaf = Split-Path -Leaf $DistDir
    $resolvedParent = (Resolve-Path $distParent).Path

    if ($resolvedParent -ne $resolvedDistRoot -or $distLeaf -ne $DistName) {
        throw "Refusing to remove unexpected dist path: $DistDir"
    }

    if (Test-Path -LiteralPath $DistDir) {
        try {
            Remove-Item -LiteralPath $DistDir -Recurse -Force
        }
        catch {
            throw "Unable to remove $DistDir. Close any running WindowsAppAutoLogin.exe from that folder, or rerun this script with -StopRunning. Original error: $($_.Exception.Message)"
        }
    }

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
}

function Stop-DistProcesses {
    $normalizedDistDir = Normalize-Path $DistDir
    $processes = Get-CimInstance Win32_Process -Filter "Name = 'WindowsAppAutoLogin.exe' OR Name = 'windows-app-autologin.exe'" |
        Where-Object {
            if (-not $_.ExecutablePath) {
                return $false
            }

            $processPath = Normalize-Path $_.ExecutablePath
            return $processPath -eq (Normalize-Path $DistExe) -or $processPath.StartsWith("$normalizedDistDir\")
        }

    foreach ($process in $processes) {
        Write-Host "Stopping running dist process $($process.ProcessId): $($process.ExecutablePath)"
        Stop-Process -Id $process.ProcessId -Force
    }

    if ($processes) {
        Start-Sleep -Milliseconds 500
    }
}

$Cargo = Require-Command "cargo"

Push-Location $RootDir
try {
    if (-not $SkipTests) {
        Write-Host "Running tests..."
        Invoke-Checked $Cargo @("test", "--locked", "--all-targets", "--all-features")
    }

    if (-not $ReuseBuild) {
        Write-Host "Cleaning release artifacts..."
        Invoke-Checked $Cargo @("clean", "--locked", "--package", "windows-app-autologin", "--release")
    }

    Write-Host "Building release executable..."
    Invoke-Checked $Cargo @("build", "--locked", "--release", "--bin", $BinaryName)

    if (-not (Test-Path -LiteralPath $TargetExe)) {
        throw "Release build did not produce expected executable: $TargetExe"
    }

    if ($StopRunning) {
        Stop-DistProcesses
    }

    Reset-DistDirectory

    Write-Host "Copying dist files..."
    Copy-Item -LiteralPath $TargetExe -Destination $DistExe
    Copy-Item -LiteralPath (Join-Path $RootDir "README.md") -Destination $DistDir
    Copy-Item -LiteralPath (Join-Path $RootDir "LICENSE") -Destination $DistDir
    Copy-Item -LiteralPath (Join-Path $RootDir "config.example.json") -Destination $DistDir

    Write-Host "Windows dist build complete:"
    Write-Host "  $DistDir"
    Write-Host "  $(Join-Path $DistDir $ExeName)"
}
finally {
    Pop-Location
}
