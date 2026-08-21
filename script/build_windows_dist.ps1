#Requires -Version 5.1

param(
    [switch]$SkipTests,
    [switch]$StopRunning,
    [switch]$ReuseBuild,
    [switch]$Development,
    [string]$SigningCertificateThumbprint = "",
    [string]$TimestampUrl = "",
    [string]$InternalCleanShellNonce = ""
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Profiles and ambient aliases/functions must not participate in provenance,
# hashing, Authenticode verification, or cleanup. Re-enter once through the
# exact current PowerShell engine with profiles disabled and only the engine's
# built-in module path. The nonce is necessary but not sufficient: accepting
# the internal branch also requires the exact child argument vector and trusted
# module path, so a caller-controlled parameter/environment pair cannot bypass
# clean-shell creation.
$enginePath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$enginePath = [IO.Path]::GetFullPath($enginePath)
$engineLeaf = [IO.Path]::GetFileName($enginePath)
$engineParent = [IO.Path]::GetDirectoryName($enginePath).TrimEnd('\', '/')
$trustedEngineParent = [IO.Path]::GetFullPath($PSHOME).TrimEnd('\', '/')
if (-not [Environment]::Is64BitProcess) {
    throw "The x86_64 Windows release must run in a 64-bit PowerShell process."
}
if (($engineLeaf -ine "powershell.exe" -and $engineLeaf -ine "pwsh.exe") -or
    -not [StringComparer]::OrdinalIgnoreCase.Equals($engineParent, $trustedEngineParent)) {
    throw "Windows release packaging must run from the physical PowerShell console engine."
}
$trustedModulePath = [IO.Path]::Combine($trustedEngineParent, "Modules")
if (-not [IO.Directory]::Exists($trustedModulePath)) {
    throw "The trusted PowerShell built-in module directory is unavailable."
}

function Assert-PhysicalBootstrapPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$ExpectDirectory
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $root = [IO.Path]::GetPathRoot($fullPath)
    if (-not $root -or $root -cnotmatch '^[A-Za-z]:[\\/]$') {
        throw "The PowerShell bootstrap path must be on an explicit local drive: $Path"
    }
    $current = $root
    $remainder = $fullPath.Substring($root.Length).Trim('\', '/')
    foreach ($segment in ($remainder -split '[\\/]')) {
        if (-not $segment) { continue }
        $current = [IO.Path]::Combine($current, $segment)
        $attributes = [IO.File]::GetAttributes($current)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The PowerShell bootstrap path contains a symlink or reparse point: $current"
        }
    }
    $finalAttributes = [IO.File]::GetAttributes($fullPath)
    $isDirectory = ($finalAttributes -band [IO.FileAttributes]::Directory) -ne 0
    if ($isDirectory -ne $ExpectDirectory) {
        throw "The PowerShell bootstrap path has an unexpected object kind: $Path"
    }
}

Assert-PhysicalBootstrapPath -Path $enginePath -ExpectDirectory $false
Assert-PhysicalBootstrapPath -Path $trustedModulePath -ExpectDirectory $true

function New-CleanShellArguments {
    param([Parameter(Mandatory = $true)][string]$Nonce)

    $arguments = @(
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath
    )
    if ($SkipTests) { $arguments += "-SkipTests" }
    if ($StopRunning) { $arguments += "-StopRunning" }
    if ($ReuseBuild) { $arguments += "-ReuseBuild" }
    if ($Development) { $arguments += "-Development" }
    if ($SigningCertificateThumbprint) {
        $arguments += @("-SigningCertificateThumbprint", $SigningCertificateThumbprint)
    }
    if ($TimestampUrl) { $arguments += @("-TimestampUrl", $TimestampUrl) }
    $arguments += @("-InternalCleanShellNonce", $Nonce)
    return $arguments
}

function Test-OrdinalArgumentVector {
    param(
        [Parameter(Mandatory = $true)][string[]]$Actual,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )

    if ($Actual.Count -ne $Expected.Count) {
        return $false
    }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if (-not [StringComparer]::Ordinal.Equals($Actual[$index], $Expected[$index])) {
            return $false
        }
    }
    return $true
}

$cleanShellMarkerName = "WAAL_INTERNAL_CLEAN_SHELL_NONCE"
$cleanShellMarker = [Environment]::GetEnvironmentVariable($cleanShellMarkerName, "Process")
$currentProcessArguments = [Environment]::GetCommandLineArgs()
$currentInvocationArguments = @()
if ($currentProcessArguments.Count -gt 1) {
    $currentInvocationArguments = @($currentProcessArguments[1..($currentProcessArguments.Count - 1)])
}
$expectedInvocationArguments = @()
if ($InternalCleanShellNonce) {
    $expectedInvocationArguments = @(New-CleanShellArguments -Nonce $InternalCleanShellNonce)
}
$currentModulePath = [Environment]::GetEnvironmentVariable("PSModulePath", "Process")
$modulePathIsTrusted = $false
if ($currentModulePath) {
    try {
        $normalizedModulePath = [IO.Path]::GetFullPath($currentModulePath.TrimEnd('\', '/'))
        $modulePathIsTrusted = [StringComparer]::OrdinalIgnoreCase.Equals(
            $normalizedModulePath,
            $trustedModulePath
        )
    }
    catch {
        $modulePathIsTrusted = $false
    }
}
$cleanShellVerified = [bool](
    $InternalCleanShellNonce -and
    $cleanShellMarker -ceq $InternalCleanShellNonce -and
    $modulePathIsTrusted -and
    (Test-OrdinalArgumentVector -Actual $currentInvocationArguments -Expected $expectedInvocationArguments)
)

if (-not $cleanShellVerified) {
    $nonce = [Guid]::NewGuid().ToString("N")
    $childArguments = @(New-CleanShellArguments -Nonce $nonce)

    $ambientModulePath = [Environment]::GetEnvironmentVariable("PSModulePath", "Process")
    $ambientMarker = $cleanShellMarker
    $childExitCode = $null
    try {
        [Environment]::SetEnvironmentVariable("PSModulePath", $trustedModulePath, "Process")
        [Environment]::SetEnvironmentVariable($cleanShellMarkerName, $nonce, "Process")
        & $enginePath @childArguments
        $childExitCode = $LASTEXITCODE
    }
    finally {
        [Environment]::SetEnvironmentVariable("PSModulePath", $ambientModulePath, "Process")
        [Environment]::SetEnvironmentVariable($cleanShellMarkerName, $ambientMarker, "Process")
    }
    if ($childExitCode -ne 0) {
        throw "The clean PowerShell release subprocess failed with exit code $childExitCode."
    }
    return
}

# Do not leak the one-shot bootstrap capability into release tools or their
# subprocesses after the exact clean invocation has been established.
[Environment]::SetEnvironmentVariable($cleanShellMarkerName, $null, "Process")
$InternalCleanShellNonce = ""

$RootDir = (Microsoft.PowerShell.Management\Resolve-Path (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot "..")).ProviderPath
$BinaryName = "windows-app-autologin"
$ExeName = "WindowsAppAutoLogin.exe"
$TargetTriple = "x86_64-pc-windows-msvc"
$ProductionDistName = "WindowsAppAutoLogin-windows-x86_64"
$DevelopmentDistName = "WindowsAppAutoLogin-windows-x86_64-development"
$DistName = if ($Development) { $DevelopmentDistName } else { $ProductionDistName }
$DistRoot = Microsoft.PowerShell.Management\Join-Path $RootDir "dist"
$DistDir = $null
$ReleaseRoot = $null
$ReleaseRootHandle = $null
$ReleaseSourceDir = $null
$BuildTargetDir = $null
$BuildHome = $null
$GitHome = $null
$CargoHome = $null
$CargoWorkingDir = $null
$BuildTempDir = $null
$Cargo = $null
$Rustc = $null
$RustSysroot = $null
$Git = $null
$GitRoot = $null
$Tar = $null
$Linker = $null
$Compiler = $null
$Librarian = $null
$CompilerBin = $null
$ResourceCompiler = $null
$SdkBin = $null
$SignTool = $null
$CargoVersion = $null
$RustcVersion = $null
$CargoSha256 = $null
$RustcSha256 = $null
$RustSysrootSha256 = $null
$GitSha256 = $null
$GitRootSha256 = $null
$TarSha256 = $null
$LinkerSha256 = $null
$CompilerSha256 = $null
$LibrarianSha256 = $null
$CompilerBinSha256 = $null
$ResourceCompilerSha256 = $null
$SdkBinSha256 = $null
$SignToolSha256 = ""
$NativeToolchainSha256 = $null
$ReleaseMaterialsSha256 = ""
$TrustedLib = ""
$TrustedInclude = ""
$TrustedLibPath = ""
$TrustedLibSha256 = $null
$TrustedIncludeSha256 = $null
$TrustedLibPathSha256 = $null
$WindowsDirectory = $null
$WindowsSystemDirectory = $null
$ReleaseTreeEntries = @()
$ReleaseGitCommit = $null
$ReleaseGitTree = $null
$SigningCertificate = $null
$WindowsPublisher = ""
$WindowsSignerCertSha256 = ""
$PublicationCandidateDir = $null
$PublicationFinalActivated = $false
$PublicationComplete = $false
$AmbientLib = [Environment]::GetEnvironmentVariable("LIB", "Process")
$AmbientInclude = [Environment]::GetEnvironmentVariable("INCLUDE", "Process")
$AmbientLibPath = [Environment]::GetEnvironmentVariable("LIBPATH", "Process")
$AmbientSystemRoot = [Environment]::GetEnvironmentVariable("SYSTEMROOT", "Process")
$AmbientWinDir = [Environment]::GetEnvironmentVariable("WINDIR", "Process")

if (-not $SigningCertificateThumbprint -and $env:WAAL_WINDOWS_SIGN_CERT_THUMBPRINT) {
    $SigningCertificateThumbprint = $env:WAAL_WINDOWS_SIGN_CERT_THUMBPRINT
}
if (-not $TimestampUrl) {
    $TimestampUrl = if ($env:WAAL_WINDOWS_TIMESTAMP_URL) {
        $env:WAAL_WINDOWS_TIMESTAMP_URL
    }
    else {
        "http://timestamp.digicert.com"
    }
}
if ($ReuseBuild) {
    throw "-ReuseBuild is incompatible with provenance-safe distribution builds. Every dist artifact is rebuilt from a fresh Git snapshot."
}

function Normalize-Path {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/').ToLowerInvariant()
}

function Require-Command {
    param([Parameter(Mandatory = $true)][string]$Name)

    $command = Microsoft.PowerShell.Core\Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1
    if ($command) {
        return $command.Path
    }
    throw "Required command not found: $Name"
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $FilePath @Arguments 2>&1 | Microsoft.PowerShell.Core\ForEach-Object { Microsoft.PowerShell.Utility\Write-Host $_ }
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Invoke-Captured {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $output = & $FilePath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | Microsoft.PowerShell.Core\ForEach-Object { Microsoft.PowerShell.Utility\Write-Host $_ }
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
    return (($output | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString() }) -join [Environment]::NewLine).Trim()
}

function Invoke-SanitizedGit {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    if (-not $Git -or -not $ReleaseRoot) {
        throw "Pinned Git and the private release root must be initialized before provenance inspection."
    }
    if (-not $WindowsDirectory -or -not $WindowsSystemDirectory) {
        throw "Trusted Windows directories must be resolved before invoking Git."
    }
    if (-not $GitHome) {
        $script:GitHome = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot "git-home"
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $GitHome)) {
            Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $GitHome | Microsoft.PowerShell.Core\Out-Null
        }
        Assert-RealDirectory $GitHome
    }

    $existingEnvironment = [Environment]::GetEnvironmentVariables("Process")
    $managedNames = @()
    foreach ($entry in $existingEnvironment.GetEnumerator()) {
        if ($entry.Key -match '^(GIT_|HOME$|USERPROFILE$|XDG_CONFIG_HOME$|PATH$|SYSTEMROOT$|WINDIR$|LC_ALL$|LANG$)') {
            $managedNames += [string]$entry.Key
        }
    }
    $managedNames = @($managedNames | Microsoft.PowerShell.Utility\Sort-Object -Unique)
    $original = @{}
    foreach ($name in $managedNames) {
        if ($existingEnvironment.Contains($name)) {
            $original[$name] = [string]$existingEnvironment[$name]
        }
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }

    $controlled = @{
        HOME = $GitHome
        USERPROFILE = $GitHome
        XDG_CONFIG_HOME = $GitHome
        PATH = "$WindowsSystemDirectory;$WindowsDirectory"
        SYSTEMROOT = $WindowsDirectory
        WINDIR = $WindowsDirectory
        GIT_CONFIG_NOSYSTEM = "1"
        GIT_CONFIG_SYSTEM = "NUL"
        GIT_CONFIG_GLOBAL = "NUL"
        GIT_CONFIG_COUNT = "0"
        GIT_TERMINAL_PROMPT = "0"
        GIT_OPTIONAL_LOCKS = "0"
        GIT_NO_REPLACE_OBJECTS = "1"
        GIT_PAGER = ""
        LC_ALL = "C"
        LANG = "C"
    }
    foreach ($name in $controlled.Keys) {
        if ($name -notin $managedNames) {
            if ($existingEnvironment.Contains($name)) {
                $original[$name] = [string]$existingEnvironment[$name]
            }
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
            $managedNames += [string]$name
        }
    }
    $safeArguments = @(
        "--no-pager",
        "--no-replace-objects",
        "--literal-pathspecs",
        "-c", "core.quotePath=true",
        "-c", "core.fsmonitor=false",
        "-c", "core.untrackedCache=false",
        "-c", "core.hooksPath=NUL",
        "-c", "core.attributesFile=NUL"
    ) + $Arguments

    try {
        foreach ($entry in $controlled.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, "Process")
        }
        return Invoke-Captured $Git $safeArguments
    }
    finally {
        foreach ($name in $managedNames) {
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
        }
        foreach ($entry in $original.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, "Process")
        }
    }
}

function Test-LowerHex {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][int]$Length
    )

    return $Value.Length -eq $Length -and $Value -cmatch "^[0-9a-f]{$Length}$"
}

function Get-EnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    return [Environment]::GetEnvironmentVariable($Name, "Process")
}

function Get-RequiredEnvironmentValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    $value = Get-EnvironmentValue $Name
    if ([string]::IsNullOrWhiteSpace($value) -or $value -cne $value.Trim()) {
        throw "$Name must be set to a non-empty value without surrounding whitespace."
    }
    return $value
}

function Get-RequiredExpectedSha256 {
    param([Parameter(Mandatory = $true)][string]$Name)

    $value = Get-RequiredEnvironmentValue $Name
    if (-not (Test-LowerHex $value 64)) {
        throw "$Name must be an exact lowercase SHA-256 digest."
    }
    return $value
}

function Assert-AbsoluteLocalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -cnotmatch '^[A-Za-z]:[\\/]') {
        throw "Release inputs must use explicit absolute local drive paths: $Path"
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($Path -match '(^|[\\/])\.\.?([\\/]|$)' -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals(
            $fullPath.TrimEnd('\', '/'),
            $Path.TrimEnd('\', '/')
        )) {
        throw "Release input is not already a canonical absolute path: $Path"
    }
}

function Assert-NoReparsePointComponents {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-AbsoluteLocalPath $Path
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $root = [IO.Path]::GetPathRoot($fullPath)
    $current = $root.TrimEnd('\', '/') + '\'
    $remainder = $fullPath.Substring($root.Length).Trim('\', '/')
    if (-not $remainder) { return }
    foreach ($segment in ($remainder -split '[\\/]')) {
        $current = Microsoft.PowerShell.Management\Join-Path $current $segment
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $current)) {
            throw "Release input path component does not exist: $current"
        }
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release input path contains a symlink or reparse point: $current"
        }
    }
}

function Resolve-TrustedWindowsDirectories {
    $reportedSystemDirectory = [Environment]::SystemDirectory
    if ([string]::IsNullOrWhiteSpace($reportedSystemDirectory)) {
        throw "The Windows system directory could not be resolved independently of ambient environment variables."
    }
    Assert-NoReparsePointComponents $reportedSystemDirectory
    $systemItem = Microsoft.PowerShell.Management\Get-Item -LiteralPath $reportedSystemDirectory -Force
    if (-not $systemItem.PSIsContainer -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals($systemItem.Name, "System32")) {
        throw "The resolved Windows system path is not a directory."
    }
    $reportedWindowsDirectory = Microsoft.PowerShell.Management\Split-Path -Parent $systemItem.FullName
    Assert-NoReparsePointComponents $reportedWindowsDirectory
    $windowsItem = Microsoft.PowerShell.Management\Get-Item -LiteralPath $reportedWindowsDirectory -Force
    if (-not $windowsItem.PSIsContainer -or
        (Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $systemItem.FullName)) -ne (Normalize-Path $windowsItem.FullName)) {
        throw "The resolved Windows system directory is not a direct child of the trusted Windows directory."
    }
    $script:WindowsDirectory = $windowsItem.FullName
    $script:WindowsSystemDirectory = $systemItem.FullName
    [Environment]::SetEnvironmentVariable("SYSTEMROOT", $script:WindowsDirectory, "Process")
    [Environment]::SetEnvironmentVariable("WINDIR", $script:WindowsDirectory, "Process")
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-ExplicitPinnedExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$PathEnvironmentName,
        [Parameter(Mandatory = $true)][string]$HashEnvironmentName,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $path = Get-RequiredEnvironmentValue $PathEnvironmentName
    $expectedHash = Get-RequiredExpectedSha256 $HashEnvironmentName
    Assert-NoReparsePointComponents $path
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer) { throw "$PathEnvironmentName must identify a regular executable file." }
    $actualHash = Get-Sha256 $path
    if ($actualHash -cne $expectedHash) {
        throw "$Description SHA-256 does not match $HashEnvironmentName."
    }
    return [PSCustomObject]@{ Path = $item.FullName; Hash = $expectedHash }
}

function Resolve-DiscoveredExecutable {
    param([Parameter(Mandatory = $true)][string]$Name)

    $path = (Microsoft.PowerShell.Management\Resolve-Path (Require-Command $Name)).ProviderPath
    Assert-NoReparsePointComponents $path
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer) { throw "Expected an executable file: $path" }
    return [PSCustomObject]@{ Path = $item.FullName; Hash = (Get-Sha256 $item.FullName) }
}

function Resolve-ExplicitPinnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$PathEnvironmentName,
        [Parameter(Mandatory = $true)][string]$HashEnvironmentName,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $path = Get-RequiredEnvironmentValue $PathEnvironmentName
    $expectedHash = Get-RequiredExpectedSha256 $HashEnvironmentName
    Assert-NoReparsePointComponents $path
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force
    if (-not $item.PSIsContainer) { throw "$PathEnvironmentName must identify a real directory." }
    $actualHash = Get-DirectoryTreeSha256 $item.FullName
    if ($actualHash -cne $expectedHash) {
        throw "$Description SHA-256 does not match $HashEnvironmentName."
    }
    return [PSCustomObject]@{ Path = $item.FullName; Hash = $expectedHash }
}

function Assert-PathWithinPinnedDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Assert-NoReparsePointComponents $Path
    Assert-NoReparsePointComponents $Directory
    $normalizedPath = Normalize-Path $Path
    $normalizedDirectory = Normalize-Path $Directory
    if ($normalizedPath -eq $normalizedDirectory -or
        -not $normalizedPath.StartsWith("$normalizedDirectory\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description must be contained by its pinned directory tree."
    }
}

function Get-DirectoryTreeSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-NoReparsePointComponents $Path
    $rootItem = Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force
    if (-not $rootItem.PSIsContainer) { throw "Tree hash input is not a directory: $Path" }
    $root = $rootItem.FullName.TrimEnd('\', '/')
    $relativePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($item in Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $root -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Tree hash input contains a symlink or reparse point: $($item.FullName)"
        }
        if ($item.PSIsContainer) { continue }
        $relative = $item.FullName.Substring($root.Length + 1).Replace('\', '/')
        $null = $relativePaths.Add($relative)
    }
    $ordered = $relativePaths.ToArray()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    $aggregate = [Security.Cryptography.SHA256]::Create()
    $utf8 = Microsoft.PowerShell.Utility\New-Object Text.UTF8Encoding($false)
    $nul = [byte[]]@(0)
    try {
        foreach ($relative in $ordered) {
            $filePath = Microsoft.PowerShell.Management\Join-Path $root ($relative.Replace('/', '\'))
            $before = Microsoft.PowerShell.Management\Get-Item -LiteralPath $filePath -Force
            if ($before.PSIsContainer -or
                (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw "Tree hash input changed type while hashing: $filePath"
            }
            $fileHash = Get-Sha256 $filePath
            $after = Microsoft.PowerShell.Management\Get-Item -LiteralPath $filePath -Force
            if ($before.Length -ne $after.Length -or
                $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks) {
                throw "Tree hash input changed while hashing: $filePath"
            }
            foreach ($bytes in @($utf8.GetBytes($relative), $nul, $utf8.GetBytes($fileHash), $nul)) {
                if ($bytes.Length -gt 0) {
                    $null = $aggregate.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)
                }
            }
        }
        $null = $aggregate.TransformFinalBlock([byte[]]@(), 0, 0)
        return (($aggregate.Hash | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
        $aggregate.Dispose()
    }
}

function Get-OrderedHashAggregate {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Hashes)

    $aggregate = [Security.Cryptography.SHA256]::Create()
    $ascii = [Text.Encoding]::ASCII
    $nul = [byte[]]@(0)
    try {
        foreach ($hash in $Hashes) {
            if (-not (Test-LowerHex $hash 64)) { throw "Native tool hash aggregate received an invalid component." }
            $bytes = $ascii.GetBytes($hash)
            $null = $aggregate.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)
            $null = $aggregate.TransformBlock($nul, 0, 1, $nul, 0)
        }
        $null = $aggregate.TransformFinalBlock([byte[]]@(), 0, 0)
        return (($aggregate.Hash | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
        $aggregate.Dispose()
    }
}

function Get-ReleaseSourceState {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    if ((Normalize-Path $GitPath) -ne (Normalize-Path $Git)) {
        throw "Release provenance must use the pinned Git executable."
    }
    $gitRoot = Invoke-SanitizedGit @("-C", $RootDir, "rev-parse", "--show-toplevel")
    if ((Normalize-Path $gitRoot) -ne (Normalize-Path $RootDir)) {
        throw "Release source must be the root of its Git checkout."
    }
    $commit = Invoke-SanitizedGit @("-C", $RootDir, "rev-parse", "--verify", "HEAD^{commit}")
    # Derive the tree from the captured immutable commit, never from a second
    # moving HEAD read. This keeps embedded commit/tree provenance relationally
    # sound even if another process advances the branch concurrently.
    $tree = Invoke-SanitizedGit @("-C", $RootDir, "rev-parse", "--verify", "${commit}^{tree}")
    if (-not (Test-LowerHex $commit 40) -or -not (Test-LowerHex $tree 40)) {
        throw "Release source commit and tree must be exact lowercase 40-hex Git object IDs."
    }
    $verifiedTree = Invoke-SanitizedGit @("-C", $RootDir, "rev-parse", "--verify", "${commit}^{tree}")
    if ($verifiedTree -cne $tree) {
        throw "Release source tree is not the tree owned by the captured commit."
    }
    $status = Invoke-SanitizedGit @(
        "-C", $RootDir,
        "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"
    )
    if ($status) {
        throw "Release source must have no tracked or untracked worktree changes."
    }
    $indexFlags = Invoke-SanitizedGit @("-C", $RootDir, "ls-files", "-v")
    if (($indexFlags -split "`r?`n" | Microsoft.PowerShell.Core\Where-Object { $_ -cmatch '^[a-zS] ' })) {
        throw "Release source contains assume-unchanged or skip-worktree index entries."
    }

    return [PSCustomObject]@{ Commit = $commit; Tree = $tree }
}

function Assert-ReleaseSourceUnchanged {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    Assert-ReleaseToolchainIntegrity
    $state = Get-ReleaseSourceState $GitPath
    if ($state.Commit -cne $ReleaseGitCommit -or $state.Tree -cne $ReleaseGitTree) {
        throw "Release source HEAD or tree changed during packaging."
    }
    Assert-ReleaseToolchainIntegrity
}

function Assert-RealDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Create
    )

    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path)) {
        if (-not $Create) {
            throw "Required directory does not exist: $Path"
        }
        Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $Path | Microsoft.PowerShell.Core\Out-Null
    }
    Assert-NoReparsePointComponents $Path
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) {
        throw "Expected a directory: $Path"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to use a symlinked or reparse-point directory: $Path"
    }
    if ((Normalize-Path $item.FullName) -ne (Normalize-Path $Path)) {
        throw "Directory resolved outside its expected physical path: $Path"
    }
}

function Prepare-DistRoot {
    Assert-RealDirectory $DistRoot -Create
}

function Assert-SafePublicationPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedLeafPattern
    )

    Prepare-DistRoot
    $resolvedDistRoot = (Microsoft.PowerShell.Management\Resolve-Path $DistRoot).ProviderPath
    $parent = Microsoft.PowerShell.Management\Split-Path -Parent $Path
    $leaf = Microsoft.PowerShell.Management\Split-Path -Leaf $Path
    if ((Normalize-Path $parent) -ne (Normalize-Path $resolvedDistRoot) -or
        $leaf -cnotmatch $ExpectedLeafPattern) {
        throw "Refusing to mutate an unexpected distribution path: $Path"
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path) {
        Assert-NoReparsePointComponents $Path
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer) { throw "Distribution path is not a directory: $Path" }
    }
}

function New-PublicationCandidate {
    Prepare-DistRoot
    if (-not $DistDir -or -not $ReleaseGitCommit) {
        throw "Versioned distribution destination must be initialized before publication."
    }
    $suffix = [Guid]::NewGuid().ToString("N")
    $script:PublicationCandidateDir = Microsoft.PowerShell.Management\Join-Path $DistRoot ".$DistName.candidate-$suffix"
    Assert-SafePublicationPath $PublicationCandidateDir ('^\.' + [regex]::Escape($DistName) + '\.candidate-[0-9a-f]{32}$')
    Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $PublicationCandidateDir | Microsoft.PowerShell.Core\Out-Null
    Assert-RealDirectory $PublicationCandidateDir
    return $PublicationCandidateDir
}

function Activate-PublicationCandidate {
    Assert-SafePublicationPath $DistDir ('^' + [regex]::Escape($DistName) + '-[0-9a-f]{40}$')
    Assert-SafePublicationPath $PublicationCandidateDir ('^\.' + [regex]::Escape($DistName) + '\.candidate-[0-9a-f]{32}$')
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $PublicationCandidateDir -PathType Container)) {
        throw "Verified publication candidate is missing."
    }
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $DistDir) {
        throw "The immutable distribution for commit $ReleaseGitCommit already exists: $DistDir"
    }
    # One same-volume directory rename publishes an immutable commit-addressed
    # package. Older committed packages are never renamed or deleted, so a
    # crash cannot create a missing-package window.
    # Directory.Move has atomic no-replace semantics for a same-volume rename.
    # Microsoft.PowerShell.Management\Move-Item would instead move the candidate *inside* a destination
    # directory created by a concurrent publisher between the check and move.
    [IO.Directory]::Move($PublicationCandidateDir, $DistDir)
    $script:PublicationFinalActivated = $true
}

function Move-PublicationAside {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet("failed", "abandoned")][string]$Kind,
        [Parameter(Mandatory = $true)][string]$ExpectedLeafPattern
    )

    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Path)) { return }
    Assert-SafePublicationPath $Path $ExpectedLeafPattern
    $quarantine = Microsoft.PowerShell.Management\Join-Path $DistRoot (".$DistName.$Kind-" + [Guid]::NewGuid().ToString("N"))
    Assert-SafePublicationPath $quarantine ('^\.' + [regex]::Escape($DistName) + '\.(?:failed|abandoned)-[0-9a-f]{32}$')
    # Never recursively delete publication trees. A nested reparse point can
    # therefore neither redirect cleanup nor put an external target at risk.
    [IO.Directory]::Move($Path, $quarantine)
}

function Restore-PublicationAfterFailure {
    if ($PublicationComplete) { return }
    if ($PublicationFinalActivated -and $DistDir -and (Microsoft.PowerShell.Management\Test-Path -LiteralPath $DistDir)) {
        Move-PublicationAside $DistDir "failed" ('^' + [regex]::Escape($DistName) + '-[0-9a-f]{40}$')
        $script:PublicationFinalActivated = $false
    }
    if ($PublicationCandidateDir -and (Microsoft.PowerShell.Management\Test-Path -LiteralPath $PublicationCandidateDir)) {
        Move-PublicationAside $PublicationCandidateDir "abandoned" ('^\.' + [regex]::Escape($DistName) + '\.candidate-[0-9a-f]{32}$')
    }
}

function Complete-Publication {
    $script:PublicationComplete = $true
}

function Stop-DistProcesses {
    Prepare-DistRoot
    $normalizedDistRoot = Normalize-Path (Microsoft.PowerShell.Management\Resolve-Path $DistRoot).ProviderPath
    $productionPattern = '^' + [regex]::Escape($ProductionDistName) + '-[0-9a-f]{40}$'
    $developmentPattern = '^' + [regex]::Escape($DevelopmentDistName) + '-[0-9a-f]{40}$'
    $processes = CimCmdlets\Get-CimInstance Win32_Process -Filter "Name = 'WindowsAppAutoLogin.exe' OR Name = 'windows-app-autologin.exe'" |
        Microsoft.PowerShell.Core\Where-Object {
            if (-not $_.ExecutablePath) { return $false }
            try {
                $physicalProcessPath = [IO.Path]::GetFullPath($_.ExecutablePath)
                $processLeaf = Microsoft.PowerShell.Management\Split-Path -Leaf $physicalProcessPath
                if ($processLeaf -ine $ExeName -and $processLeaf -ine "$BinaryName.exe") {
                    return $false
                }
                $processDirectory = Microsoft.PowerShell.Management\Split-Path -Parent $physicalProcessPath
                $processDirectoryLeaf = Microsoft.PowerShell.Management\Split-Path -Leaf $processDirectory
                $processDirectoryParent = Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $processDirectory)
                if ($processDirectoryParent -ne $normalizedDistRoot -or
                    ($processDirectoryLeaf -cnotmatch $productionPattern -and
                     $processDirectoryLeaf -cnotmatch $developmentPattern)) {
                    return $false
                }
                Assert-NoReparsePointComponents $physicalProcessPath
                return (Normalize-Path $physicalProcessPath) -eq
                    (Normalize-Path (Microsoft.PowerShell.Management\Join-Path $processDirectory $processLeaf))
            }
            catch {
                return $false
            }
        }
    foreach ($process in $processes) {
        Microsoft.PowerShell.Utility\Write-Host "Stopping running dist process $($process.ProcessId): $($process.ExecutablePath)"
        Microsoft.PowerShell.Management\Stop-Process -Id $process.ProcessId -Force
    }
}

function Initialize-ReleaseTreeCleanup {
    param([Parameter(Mandatory = $true)][string]$PrivateCompilerTemp)

    Assert-RealDirectory $PrivateCompilerTemp
    if ("Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner" -as [type]) {
        return
    }

    # PowerShell's recursive provider deletion performs a path-based traversal
    # after any caller-side reparse-point check, leaving a check/use race. This
    # helper keeps the exact root object open from creation through cleanup and
    # performs both enumeration and deletion through native handles. Children
    # are opened relative to an already-open parent with FILE_OPEN_REPARSE_POINT;
    # a junction or symlink is consequently deleted as a leaf and never followed.
    $typeDefinition = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Obcardinal.WindowsAppAutoLogin
{
    public static class ReleaseTreeCleaner
    {
        private const uint DeleteAccess = 0x00010000;
        private const uint FileListDirectory = 0x00000001;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileWriteAttributes = 0x00000100;
        private const uint Synchronize = 0x00100000;

        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;

        private const uint OpenExisting = 3;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileOpenForBackupIntent = 0x00004000;
        private const uint FileOpenReparsePoint = 0x00200000;
        private const uint FileSynchronousIoNonAlert = 0x00000020;

        private const uint FileAttributeReadOnly = 0x00000001;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeNormal = 0x00000080;
        private const uint FileAttributeReparsePoint = 0x00000400;

        private const int FileBasicInfoClass = 0;
        private const int FileDispositionInfoClass = 4;
        private const int FileIdBothDirectoryInfoClass = 10;
        private const int FileIdBothDirectoryRestartInfoClass = 11;
        private const int ErrorNoMoreFiles = 18;

        private const int DirectoryRecordHeaderLength = 104;
        private const int DirectoryRecordFileAttributesOffset = 56;
        private const int DirectoryRecordFileNameLengthOffset = 60;
        private const int DirectoryRecordFileIdOffset = 96;
        private const int DirectoryRecordFileNameOffset = 104;
        private const int DirectoryBufferLength = 65536;
        private const int MaximumDepth = 256;
        private const int MaximumEntries = 1000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime
        {
            internal uint LowDateTime;
            internal uint HighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            internal uint FileAttributes;
            internal FileTime CreationTime;
            internal FileTime LastAccessTime;
            internal FileTime LastWriteTime;
            internal uint VolumeSerialNumber;
            internal uint FileSizeHigh;
            internal uint FileSizeLow;
            internal uint NumberOfLinks;
            internal uint FileIndexHigh;
            internal uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileBasicInformation
        {
            internal long CreationTime;
            internal long LastAccessTime;
            internal long LastWriteTime;
            internal long ChangeTime;
            internal uint FileAttributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileDispositionInformation
        {
            internal byte DeleteFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            internal int Length;
            internal IntPtr RootDirectory;
            internal IntPtr ObjectName;
            internal uint Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatusBlock
        {
            internal IntPtr Status;
            internal UIntPtr Information;
        }

        private sealed class Identity
        {
            internal readonly uint VolumeSerialNumber;
            internal readonly ulong FileId;
            internal readonly ulong CreationTime;
            internal readonly uint Attributes;

            internal Identity(ByHandleFileInformation information)
            {
                VolumeSerialNumber = information.VolumeSerialNumber;
                FileId = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
                CreationTime = ((ulong)information.CreationTime.HighDateTime << 32) |
                    information.CreationTime.LowDateTime;
                Attributes = information.FileAttributes;
            }

            internal bool IsDirectory
            {
                get { return (Attributes & FileAttributeDirectory) != 0; }
            }

            internal bool IsReparsePoint
            {
                get { return (Attributes & FileAttributeReparsePoint) != 0; }
            }

            internal bool SameObjectAndKind(Identity other)
            {
                return other != null &&
                    VolumeSerialNumber == other.VolumeSerialNumber &&
                    FileId == other.FileId &&
                    CreationTime == other.CreationTime &&
                    IsDirectory == other.IsDirectory &&
                    IsReparsePoint == other.IsReparsePoint;
            }
        }

        private sealed class DirectoryEntry
        {
            internal readonly string Name;
            internal readonly ulong FileId;
            internal readonly ulong CreationTime;
            internal readonly bool IsDirectory;
            internal readonly bool IsReparsePoint;

            internal DirectoryEntry(
                string name,
                ulong fileId,
                ulong creationTime,
                uint attributes)
            {
                Name = name;
                FileId = fileId;
                CreationTime = creationTime;
                IsDirectory = (attributes & FileAttributeDirectory) != 0;
                IsReparsePoint = (attributes & FileAttributeReparsePoint) != 0;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int informationClass,
            IntPtr information,
            uint bufferSize);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileBasicInformationByHandle(
            SafeFileHandle file,
            int informationClass,
            ref FileBasicInformation information,
            uint bufferSize);

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileDispositionInformationByHandle(
            SafeFileHandle file,
            int informationClass,
            ref FileDispositionInformation information,
            uint bufferSize);

        [DllImport("ntdll.dll")]
        private static extern int NtOpenFile(
            out IntPtr fileHandle,
            uint desiredAccess,
            ref ObjectAttributes objectAttributes,
            out IoStatusBlock ioStatusBlock,
            uint shareAccess,
            uint openOptions);

        [DllImport("ntdll.dll")]
        private static extern uint RtlNtStatusToDosError(int status);

        public static SafeFileHandle TrackRoot(string path)
        {
            ValidateNativeLayouts();
            if (String.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path))
            {
                throw new ArgumentException("Cleanup root must be an absolute path.", "path");
            }

            // Retain cleanup access without FILE_SHARE_DELETE from the moment
            // the root is created. Children remain writable, while the exact
            // root object cannot be renamed, replaced, or deleted underneath
            // the build before handle-relative cleanup begins.
            SafeFileHandle handle = CreateFile(
                path,
                DeleteAccess | FileListDirectory | FileReadAttributes |
                    FileWriteAttributes | Synchronize,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            EnsureValid(handle, "open the private release root for identity tracking");
            try
            {
                Identity identity = GetIdentity(handle, "identify the private release root");
                if (!identity.IsDirectory || identity.IsReparsePoint)
                {
                    throw new IOException("The private release root is not a physical directory.");
                }
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static void DeleteTrackedTree(SafeFileHandle trackedRoot)
        {
            if (trackedRoot == null || trackedRoot.IsInvalid || trackedRoot.IsClosed)
            {
                throw new InvalidOperationException("The tracked release-root handle is unavailable.");
            }

            Identity cleanupIdentity = GetIdentity(trackedRoot, "re-identify the tracked release root");
            if (!cleanupIdentity.IsDirectory || cleanupIdentity.IsReparsePoint)
            {
                throw new IOException("The tracked cleanup root is no longer a physical directory.");
            }
            long entryCount = 0;
            DeleteNode(trackedRoot, cleanupIdentity, 0, ref entryCount);
        }

        private static void DeleteNode(
            SafeFileHandle handle,
            Identity expectedIdentity,
            int depth,
            ref long entryCount)
        {
            if (depth > MaximumDepth)
            {
                throw new IOException("The private release tree exceeds the safe cleanup depth limit.");
            }

            Identity beforeTraversal = GetIdentity(handle, "verify an entry before cleanup");
            if (!expectedIdentity.SameObjectAndKind(beforeTraversal))
            {
                throw new IOException("A release-tree entry changed identity before cleanup.");
            }

            if (beforeTraversal.IsDirectory && !beforeTraversal.IsReparsePoint)
            {
                List<DirectoryEntry> children = EnumerateChildren(handle);
                foreach (DirectoryEntry childEntry in children)
                {
                    entryCount++;
                    if (entryCount > MaximumEntries)
                    {
                        throw new IOException("The private release tree exceeds the safe cleanup entry limit.");
                    }

                    using (SafeFileHandle child = OpenChildNoFollow(handle, childEntry.Name))
                    {
                        Identity childIdentity = GetIdentity(child, "verify a child opened for cleanup");
                        if (childIdentity.VolumeSerialNumber != beforeTraversal.VolumeSerialNumber ||
                            childIdentity.FileId != childEntry.FileId ||
                            childIdentity.CreationTime != childEntry.CreationTime ||
                            childIdentity.IsDirectory != childEntry.IsDirectory ||
                            childIdentity.IsReparsePoint != childEntry.IsReparsePoint)
                        {
                            throw new IOException("A release-tree child changed identity while cleanup opened it.");
                        }
                        DeleteNode(child, childIdentity, depth + 1, ref entryCount);
                    }
                }

                if (EnumerateChildren(handle).Count != 0)
                {
                    throw new IOException("The private release directory changed while it was being cleaned.");
                }
            }

            Identity beforeDelete = GetIdentity(handle, "verify an entry immediately before deletion");
            if (!expectedIdentity.SameObjectAndKind(beforeDelete))
            {
                throw new IOException("A release-tree entry changed identity before deletion.");
            }
            ClearReadOnly(handle, beforeDelete.Attributes);
            Identity afterAttributeUpdate = GetIdentity(
                handle,
                "verify an entry after its read-only attribute update");
            if (!expectedIdentity.SameObjectAndKind(afterAttributeUpdate))
            {
                throw new IOException("A release-tree entry changed identity before disposition.");
            }
            MarkDelete(handle);
        }

        private static SafeFileHandle OpenChildNoFollow(SafeFileHandle parent, string name)
        {
            ValidateLeafName(name);
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr unicodeStringBuffer = IntPtr.Zero;
            bool parentReferenceAdded = false;
            try
            {
                int nameByteLength = checked(name.Length * 2);
                if (nameByteLength > UInt16.MaxValue - 2)
                {
                    throw new IOException("A release-tree entry name is too long for native cleanup.");
                }
                nameBuffer = Marshal.StringToHGlobalUni(name);
                UnicodeString unicodeName = new UnicodeString();
                unicodeName.Length = (ushort)nameByteLength;
                unicodeName.MaximumLength = (ushort)(nameByteLength + 2);
                unicodeName.Buffer = nameBuffer;
                unicodeStringBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(unicodeName, unicodeStringBuffer, false);

                ObjectAttributes attributes = new ObjectAttributes();
                attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
                parent.DangerousAddRef(ref parentReferenceAdded);
                attributes.RootDirectory = parent.DangerousGetHandle();
                attributes.ObjectName = unicodeStringBuffer;
                // Preserve the exact spelling returned by handle enumeration;
                // a case-sensitive directory must not redirect this open to a
                // different case-folded sibling.
                attributes.Attributes = 0;

                IoStatusBlock statusBlock;
                IntPtr rawHandle;
                int status = NtOpenFile(
                    out rawHandle,
                    DeleteAccess | FileListDirectory | FileReadAttributes |
                        FileWriteAttributes | Synchronize,
                    ref attributes,
                    out statusBlock,
                    FileShareRead,
                    FileOpenForBackupIntent | FileOpenReparsePoint | FileSynchronousIoNonAlert);
                if (status < 0)
                {
                    throw new Win32Exception(
                        unchecked((int)RtlNtStatusToDosError(status)),
                        "Unable to open a release-tree child relative to its verified parent.");
                }
                SafeFileHandle child = new SafeFileHandle(rawHandle, true);
                EnsureValid(child, "open a release-tree child relative to its verified parent");
                return child;
            }
            finally
            {
                if (parentReferenceAdded)
                {
                    parent.DangerousRelease();
                }
                if (unicodeStringBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unicodeStringBuffer);
                }
                if (nameBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(nameBuffer);
                }
            }
        }

        private static List<DirectoryEntry> EnumerateChildren(SafeFileHandle directory)
        {
            List<DirectoryEntry> entries = new List<DirectoryEntry>();
            Dictionary<string, bool> names = new Dictionary<string, bool>(StringComparer.Ordinal);
            IntPtr buffer = Marshal.AllocHGlobal(DirectoryBufferLength);
            bool restart = true;
            try
            {
                while (true)
                {
                    int informationClass = restart
                        ? FileIdBothDirectoryRestartInfoClass
                        : FileIdBothDirectoryInfoClass;
                    bool success = GetFileInformationByHandleEx(
                        directory,
                        informationClass,
                        buffer,
                        DirectoryBufferLength);
                    if (!success)
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == ErrorNoMoreFiles)
                        {
                            break;
                        }
                        throw new Win32Exception(error, "Unable to enumerate the private release directory by handle.");
                    }
                    restart = false;

                    int offset = 0;
                    while (true)
                    {
                        if (offset < 0 || offset > DirectoryBufferLength - DirectoryRecordHeaderLength)
                        {
                            throw new IOException("Windows returned an invalid release-directory record offset.");
                        }
                        IntPtr record = IntPtr.Add(buffer, offset);
                        uint nextOffset = unchecked((uint)Marshal.ReadInt32(record, 0));
                        long rawCreationTime = Marshal.ReadInt64(record, 8);
                        uint attributes = unchecked((uint)Marshal.ReadInt32(
                            record,
                            DirectoryRecordFileAttributesOffset));
                        uint fileNameLength = unchecked((uint)Marshal.ReadInt32(
                            record,
                            DirectoryRecordFileNameLengthOffset));
                        if ((fileNameLength & 1) != 0 ||
                            (long)fileNameLength >
                                (long)DirectoryBufferLength - offset - DirectoryRecordFileNameOffset)
                        {
                            throw new IOException("Windows returned an invalid release-directory entry name.");
                        }
                        if (nextOffset != 0 &&
                            (long)DirectoryRecordFileNameOffset + fileNameLength > nextOffset)
                        {
                            throw new IOException("Windows returned an overlapping release-directory entry.");
                        }
                        long rawFileId = Marshal.ReadInt64(record, DirectoryRecordFileIdOffset);
                        string name = Marshal.PtrToStringUni(
                            IntPtr.Add(record, DirectoryRecordFileNameOffset),
                            checked((int)(fileNameLength / 2)));
                        if (name != "." && name != "..")
                        {
                            ValidateLeafName(name);
                            if (names.ContainsKey(name))
                            {
                                throw new IOException("Windows returned a duplicate release-directory entry.");
                            }
                            names.Add(name, true);
                            if (entries.Count >= MaximumEntries)
                            {
                                throw new IOException("The private release directory exceeds the safe cleanup entry limit.");
                            }
                            // Attributes are intentionally read to force record
                            // bounds validation, but the opened handle is the
                            // authority for type/reparse decisions.
                            if (attributes == UInt32.MaxValue)
                            {
                                throw new IOException("Windows returned invalid release-directory attributes.");
                            }
                            entries.Add(new DirectoryEntry(
                                name,
                                unchecked((ulong)rawFileId),
                                unchecked((ulong)rawCreationTime),
                                attributes));
                        }

                        if (nextOffset == 0)
                        {
                            break;
                        }
                        if ((nextOffset & 7) != 0 || nextOffset < DirectoryRecordHeaderLength)
                        {
                            throw new IOException("Windows returned an invalid release-directory record length.");
                        }
                        offset = checked(offset + (int)nextOffset);
                    }
                }
                return entries;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static Identity GetIdentity(SafeFileHandle handle, string operation)
        {
            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to " + operation + ".");
            }
            return new Identity(information);
        }

        private static void ValidateNativeLayouts()
        {
            if (IntPtr.Size != 8 ||
                Marshal.SizeOf(typeof(ByHandleFileInformation)) != 52 ||
                Marshal.SizeOf(typeof(FileBasicInformation)) != 40 ||
                Marshal.SizeOf(typeof(FileDispositionInformation)) != 1 ||
                Marshal.SizeOf(typeof(UnicodeString)) != 16 ||
                Marshal.SizeOf(typeof(ObjectAttributes)) != 48 ||
                Marshal.SizeOf(typeof(IoStatusBlock)) != 16)
            {
                throw new PlatformNotSupportedException(
                    "The native release-tree cleanup ABI does not match 64-bit Windows.");
            }
        }

        private static void ClearReadOnly(SafeFileHandle handle, uint attributes)
        {
            if ((attributes & FileAttributeReadOnly) == 0)
            {
                return;
            }
            FileBasicInformation information = new FileBasicInformation();
            // FILE_BASIC_INFO accepts mutable DOS attributes, not the
            // intrinsic Directory/ReparsePoint bits returned by handle info.
            // NORMAL clears ReadOnly without attempting to rewrite the kind.
            information.FileAttributes = FileAttributeNormal;
            if (!SetFileBasicInformationByHandle(
                handle,
                FileBasicInfoClass,
                ref information,
                (uint)Marshal.SizeOf(typeof(FileBasicInformation))))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to clear a read-only release-tree entry.");
            }
        }

        private static void MarkDelete(SafeFileHandle handle)
        {
            FileDispositionInformation information = new FileDispositionInformation();
            information.DeleteFile = 1;
            if (!SetFileDispositionInformationByHandle(
                handle,
                FileDispositionInfoClass,
                ref information,
                (uint)Marshal.SizeOf(typeof(FileDispositionInformation))))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to delete a verified release-tree entry by handle.");
            }
        }

        private static void ValidateLeafName(string name)
        {
            if (String.IsNullOrEmpty(name) || name == "." || name == ".." ||
                name.IndexOf('\0') >= 0 || name.IndexOf('\\') >= 0 ||
                name.IndexOf('/') >= 0 || name.IndexOf(':') >= 0)
            {
                throw new IOException("Windows returned an unsafe release-tree entry name.");
            }
        }

        private static void EnsureValid(SafeFileHandle handle, string operation)
        {
            if (handle == null || handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                if (handle != null)
                {
                    handle.Dispose();
                }
                throw new Win32Exception(error, "Unable to " + operation + ".");
            }
        }
    }
}
'@

    # Add-Type/CodeDom uses TEMP/TMP for source and assembly intermediates on
    # Windows PowerShell 5.1. Compile only inside the already-created release
    # root's separately ACL-protected compiler directory; ambient temp paths
    # must not supply or race the native cleanup implementation.
    $ambientTemp = [Environment]::GetEnvironmentVariable("TEMP", "Process")
    $ambientTmp = [Environment]::GetEnvironmentVariable("TMP", "Process")
    try {
        [Environment]::SetEnvironmentVariable("TEMP", $PrivateCompilerTemp, "Process")
        [Environment]::SetEnvironmentVariable("TMP", $PrivateCompilerTemp, "Process")
        Microsoft.PowerShell.Utility\Add-Type -TypeDefinition $typeDefinition -Language CSharp
    }
    finally {
        [Environment]::SetEnvironmentVariable("TEMP", $ambientTemp, "Process")
        [Environment]::SetEnvironmentVariable("TMP", $ambientTmp, "Process")
    }
    if (-not ("Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner" -as [type])) {
        throw "The native release-tree cleanup helper did not load."
    }
}

function New-ReleaseRoot {
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $candidate = Microsoft.PowerShell.Management\Join-Path $temporaryRoot ("waal-windows-release-" + [Guid]::NewGuid().ToString("N"))
    Assert-NoReparsePointComponents $temporaryRoot
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.User) {
        throw "Unable to identify the Windows user that owns the release build."
    }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity.User)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $ownerRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity.User,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $systemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $systemRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $null = $acl.AddAccessRule($ownerRule)
    $null = $acl.AddAccessRule($systemRule)
    $created = [IO.Directory]::CreateDirectory($candidate, $acl)
    $script:ReleaseRoot = $candidate
    $createdAcl = $created.GetAccessControl(
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access
    )
    $explicitRules = @($createdAcl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ))
    if (-not $createdAcl.AreAccessRulesProtected -or
        -not $createdAcl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($identity.User) -or
        $explicitRules.Count -ne 2) {
        throw "Private release root owner or ACL protection could not be established."
    }
    foreach ($rule in $explicitRules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            (-not $rule.IdentityReference.Equals($identity.User) -and
             -not $rule.IdentityReference.Equals($systemSid))) {
            throw "Private release root contains an unexpected access-control entry."
        }
    }
    Assert-RealDirectory $candidate
    $cleanupCompilerTemp = Microsoft.PowerShell.Management\Join-Path $candidate ".cleanup-compiler"
    $cleanupCompilerDirectory = [IO.Directory]::CreateDirectory($cleanupCompilerTemp, $acl)
    Assert-RealDirectory $cleanupCompilerTemp
    $cleanupCompilerAcl = $cleanupCompilerDirectory.GetAccessControl(
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access
    )
    $cleanupCompilerRules = @($cleanupCompilerAcl.GetAccessRules(
        $true,
        $false,
        [Security.Principal.SecurityIdentifier]
    ))
    if (-not $cleanupCompilerAcl.AreAccessRulesProtected -or
        -not $cleanupCompilerAcl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($identity.User) -or
        $cleanupCompilerRules.Count -ne 2) {
        throw "Cleanup-helper compiler temp owner or ACL protection could not be established."
    }
    foreach ($rule in $cleanupCompilerRules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            (-not $rule.IdentityReference.Equals($identity.User) -and
             -not $rule.IdentityReference.Equals($systemSid))) {
            throw "Cleanup-helper compiler temp contains an unexpected access-control entry."
        }
    }
    Initialize-ReleaseTreeCleanup -PrivateCompilerTemp $cleanupCompilerTemp
    $script:ReleaseRootHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackRoot($candidate)
    return $candidate
}

function Remove-ReleaseRootSafely {
    if (-not $ReleaseRootHandle) {
        if ($ReleaseRoot) {
            Microsoft.PowerShell.Utility\Write-Warning "The private release root has no tracked cleanup handle; leaving it in place: $ReleaseRoot"
        }
        return
    }
    try {
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::DeleteTrackedTree($ReleaseRootHandle)
    }
    finally {
        if ($ReleaseRootHandle -and -not $ReleaseRootHandle.IsClosed) {
            $ReleaseRootHandle.Dispose()
        }
        $script:ReleaseRootHandle = $null
    }
}

function Assert-CommitContainsOnlyRegularFiles {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    if ((Normalize-Path $GitPath) -ne (Normalize-Path $Git)) {
        throw "Release tree inspection must use the pinned Git executable."
    }
    $listing = Invoke-SanitizedGit @(
        "-C", $RootDir, "ls-tree", "-r", "--full-tree", "--abbrev=40", $ReleaseGitCommit
    )
    if (-not $listing) {
        throw "Release source tree is empty."
    }

    $treeEntries = [System.Collections.Generic.List[object]]::new()
    $filePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pathSpellings = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pathKinds = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($listing -split "`r?`n")) {
        $match = [regex]::Match($line, '^(100644|100755) blob ([0-9a-f]{40})\t(.+)$', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
        if (-not $match.Success) {
            throw "Release source tree contains a link, gitlink, unsupported mode, quoted path, or unsafe entry."
        }
        $mode = $match.Groups[1].Value
        $blob = $match.Groups[2].Value
        $path = $match.Groups[3].Value
        Assert-SafeReleaseRelativePath $path
        if (-not $filePaths.Add($path)) {
            throw "Release source tree contains a duplicate file path: $path"
        }

        $segments = $path -split '/'
        for ($index = 0; $index -lt $segments.Count; $index++) {
            $logicalPath = ($segments[0..$index] -join '/')
            $kind = if ($index -eq $segments.Count - 1) { "file" } else { "directory" }
            if ($pathSpellings.ContainsKey($logicalPath) -and
                $pathSpellings[$logicalPath] -cne $logicalPath) {
                throw "Release source tree contains case-colliding paths: $($pathSpellings[$logicalPath]) and $logicalPath"
            }
            if ($pathKinds.ContainsKey($logicalPath) -and $pathKinds[$logicalPath] -cne $kind) {
                throw "Release source tree contains a file/directory path collision: $logicalPath"
            }
            $pathSpellings[$logicalPath] = $logicalPath
            $pathKinds[$logicalPath] = $kind
        }
        $null = $treeEntries.Add([PSCustomObject]@{ Path = $path; Mode = $mode; Blob = $blob })
    }
    $script:ReleaseTreeEntries = $treeEntries.ToArray()
}

function Assert-SafeReleaseRelativePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path.StartsWith('"') -or
        $Path -cnotmatch '^[A-Za-z0-9._ /-]+$' -or
        $Path.StartsWith('/') -or
        $Path.EndsWith('/') -or
        $Path.Contains('//') -or
        $Path.Contains('\') -or
        [IO.Path]::IsPathRooted($Path)) {
        throw "Release source tree contains a quoted, non-ASCII, rooted, or otherwise unsafe path: $Path"
    }
    foreach ($segment in ($Path -split '/')) {
        if (-not $segment -or
            $segment -in @('.', '..') -or
            $segment.EndsWith('.') -or
            $segment.EndsWith(' ') -or
            $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            throw "Release source tree contains a Windows-unsafe path segment: $Path"
        }
    }
}

function Get-GitBlobSha1 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $before = Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force
    if ($before.PSIsContainer -or (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Git blob hash input is not a regular file: $Path"
    }
    $sha1 = [Security.Cryptography.SHA1]::Create()
    $stream = $null
    try {
        $header = [Text.Encoding]::ASCII.GetBytes("blob $($before.Length)`0")
        $null = $sha1.TransformBlock($header, 0, $header.Length, $header, 0)
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $buffer = Microsoft.PowerShell.Utility\New-Object byte[] 1048576
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $null = $sha1.TransformBlock($buffer, 0, $read, $buffer, 0)
        }
        $stream.Dispose()
        $stream = $null
        $null = $sha1.TransformFinalBlock([byte[]]@(), 0, 0)
        $after = Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force
        if ($after.PSIsContainer -or
            (($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $before.Length -ne $after.Length -or
            $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks) {
            throw "Git blob hash input changed while it was being inspected: $Path"
        }
        return (($sha1.Hash | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
        if ($stream) { $stream.Dispose() }
        $sha1.Dispose()
    }
}

function Assert-MaterializedReleaseSource {
    Assert-RealDirectory $ReleaseSourceDir
    $normalizedRoot = Normalize-Path $ReleaseSourceDir
    $rootPrefix = "$normalizedRoot\"
    $expected = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($entry in $ReleaseTreeEntries) {
        $expected.Add($entry.Path, $entry)
    }
    $actual = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($item in Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $ReleaseSourceDir -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release source snapshot contains a symlink or reparse point: $($item.FullName)"
        }
        $normalizedItem = Normalize-Path $item.FullName
        if ($normalizedItem -ne $normalizedRoot -and -not $normalizedItem.StartsWith($rootPrefix)) {
            throw "Release source snapshot entry resolves outside the snapshot root."
        }
        if (-not $item.PSIsContainer) {
            $relativePath = $item.FullName.Substring($ReleaseSourceDir.TrimEnd('\', '/').Length + 1).Replace('\', '/')
            Assert-SafeReleaseRelativePath $relativePath
            if (-not $expected.ContainsKey($relativePath)) {
                throw "Release source snapshot contains a file not present in the Git tree: $relativePath"
            }
            if ($actual.ContainsKey($relativePath)) {
                throw "Release source snapshot contains a duplicate materialized path: $relativePath"
            }
            $actual.Add($relativePath, (Get-GitBlobSha1 $item.FullName))
        }
    }
    if ($actual.Count -ne $expected.Count) {
        throw "Release source snapshot file count does not exactly match the Git tree."
    }
    foreach ($entry in $ReleaseTreeEntries) {
        if (-not $actual.ContainsKey($entry.Path)) {
            throw "Release source snapshot is missing tracked Git file: $($entry.Path)"
        }
        if ($actual[$entry.Path] -cne $entry.Blob) {
            throw "Release source snapshot file does not match its exact Git blob: $($entry.Path)"
        }
    }
    foreach ($requiredFile in @("Cargo.toml", "Cargo.lock", "build.rs")) {
        $requiredPath = Microsoft.PowerShell.Management\Join-Path $ReleaseSourceDir $requiredFile
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Release source snapshot is missing a regular tracked file: $requiredFile"
        }
        if (((Microsoft.PowerShell.Management\Get-Item -LiteralPath $requiredPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release source snapshot required file is a reparse point: $requiredFile"
        }
    }
    foreach ($requiredDirectory in @("src", "assets")) {
        $requiredPath = Microsoft.PowerShell.Management\Join-Path $ReleaseSourceDir $requiredDirectory
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $requiredPath -PathType Container)) {
            throw "Release source snapshot is missing a real tracked directory: $requiredDirectory"
        }
        if (((Microsoft.PowerShell.Management\Get-Item -LiteralPath $requiredPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release source snapshot required directory is a reparse point: $requiredDirectory"
        }
    }
}

function Materialize-ReleaseSource {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$TarPath
    )

    $script:ReleaseSourceDir = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot "source"
    $archivePath = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot "source.tar"
    Assert-CommitContainsOnlyRegularFiles $GitPath
    Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $ReleaseSourceDir | Microsoft.PowerShell.Core\Out-Null
    $null = Invoke-SanitizedGit @(
        "-C", $RootDir, "archive", "--format=tar", "--output=$archivePath", $ReleaseGitCommit
    )
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $archivePath -PathType Leaf) -or
        (((Microsoft.PowerShell.Management\Get-Item -LiteralPath $archivePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Pinned Git did not create a regular source archive."
    }
    Invoke-Checked $TarPath @("-xf", $archivePath, "-C", $ReleaseSourceDir)
    Assert-MaterializedReleaseSource
}

function Resolve-RustTool {
    param([Parameter(Mandatory = $true)][string]$Name)

    $rustup = Microsoft.PowerShell.Core\Get-Command rustup.exe -CommandType Application -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object -First 1
    if ($rustup) {
        $resolved = Invoke-Captured $rustup.Path @("which", $Name)
        if ($resolved -and (Microsoft.PowerShell.Management\Test-Path -LiteralPath $resolved)) {
            return (Microsoft.PowerShell.Management\Resolve-Path $resolved).ProviderPath
        }
    }
    return (Microsoft.PowerShell.Management\Resolve-Path (Require-Command "$Name.exe")).ProviderPath
}

function Get-RustToolVersion {
    param([Parameter(Mandatory = $true)][string]$ToolPath)

    $output = Invoke-Captured $ToolPath @("--version", "--verbose")
    $match = [regex]::Match($output, '(?m)^release:\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$')
    if (-not $match.Success) { throw "Unable to determine release version for $ToolPath" }
    return $match.Groups[1].Value
}

function Resolve-TrustedDirectoryList {
    param(
        [Parameter(Mandatory = $true)][string]$EnvironmentName,
        [Parameter(Mandatory = $true)][string]$ExpectedHashEnvironmentName,
        [AllowEmptyString()][string]$DevelopmentFallback = ""
    )

    $value = Get-EnvironmentValue $EnvironmentName
    if ([string]::IsNullOrEmpty($value)) {
        if (-not $Development) {
            throw "$EnvironmentName must explicitly list trusted MSVC directories for a publishable build."
        }
        $value = $DevelopmentFallback
    }
    if ([string]::IsNullOrEmpty($value)) {
        $emptyHash = Get-OrderedHashAggregate -Hashes ([string[]]@())
        return [PSCustomObject]@{ Value = ""; Hash = $emptyHash }
    }
    $canonicalDirectories = [System.Collections.Generic.List[string]]::new()
    $seenDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in ($value -split ';')) {
        if ([string]::IsNullOrWhiteSpace($directory) -or $directory -cne $directory.Trim()) {
            throw "$EnvironmentName contains an empty directory or surrounding whitespace."
        }
        Assert-NoReparsePointComponents $directory
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $directory -Force
        if (-not $item.PSIsContainer) { throw "$EnvironmentName contains a non-directory path: $directory" }
        if (-not $seenDirectories.Add($item.FullName)) {
            throw "$EnvironmentName contains a duplicate approved directory: $($item.FullName)"
        }
        $null = $canonicalDirectories.Add($item.FullName)
    }
    $canonicalValue = $canonicalDirectories -join ';'
    $aggregateHash = Get-TrustedDirectoryListContentSha256 $canonicalValue
    if (-not $Development) {
        $expectedHash = Get-RequiredExpectedSha256 $ExpectedHashEnvironmentName
        if ($aggregateHash -cne $expectedHash) {
            throw "$EnvironmentName directory-content aggregate does not match $ExpectedHashEnvironmentName."
        }
    }
    return [PSCustomObject]@{ Value = $canonicalValue; Hash = $aggregateHash }
}

function Get-TrustedDirectoryListContentSha256 {
    param([AllowEmptyString()][string]$DirectoryList = "")

    $treeHashes = [System.Collections.Generic.List[string]]::new()
    $seenDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($DirectoryList) {
        foreach ($directory in ($DirectoryList -split ';')) {
            Assert-NoReparsePointComponents $directory
            $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $directory -Force
            if (-not $item.PSIsContainer) {
                throw "Approved MSVC path is no longer a directory: $directory"
            }
            if ((Normalize-Path $item.FullName) -ne (Normalize-Path $directory) -or
                -not $seenDirectories.Add($item.FullName)) {
                throw "Approved MSVC directory list is no longer canonical and unique."
            }
            $null = $treeHashes.Add((Get-DirectoryTreeSha256 $item.FullName))
        }
    }
    return (Get-OrderedHashAggregate ($treeHashes.ToArray()))
}

function Resolve-AndVerify-Toolchain {
    Resolve-TrustedWindowsDirectories
    if ($Development) {
        $gitInput = Resolve-DiscoveredExecutable "git.exe"
        $gitParent = Microsoft.PowerShell.Management\Split-Path -Parent $gitInput.Path
        $gitRootPath = if ((Microsoft.PowerShell.Management\Split-Path -Leaf $gitParent) -in @("cmd", "bin")) {
            Microsoft.PowerShell.Management\Split-Path -Parent $gitParent
        }
        else {
            $gitParent
        }
        $physicalGitPath = Microsoft.PowerShell.Management\Join-Path $gitRootPath "mingw64\bin\git.exe"
        if ([IO.File]::Exists($physicalGitPath)) {
            Assert-NoReparsePointComponents $physicalGitPath
            $gitInput = [PSCustomObject]@{
                Path = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $physicalGitPath -Force).FullName
                Hash = (Get-Sha256 $physicalGitPath)
            }
        }
        $gitRootInput = [PSCustomObject]@{
            Path = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $gitRootPath -Force).FullName
            Hash = (Get-DirectoryTreeSha256 $gitRootPath)
        }
        $developmentTarPath = Microsoft.PowerShell.Management\Join-Path $WindowsSystemDirectory "tar.exe"
        Assert-NoReparsePointComponents $developmentTarPath
        $developmentTarItem = Microsoft.PowerShell.Management\Get-Item -LiteralPath $developmentTarPath -Force
        if ($developmentTarItem.PSIsContainer) {
            throw "The trusted Windows System32 tar.exe path is not a regular file."
        }
        $tarInput = [PSCustomObject]@{
            Path = $developmentTarItem.FullName
            Hash = (Get-Sha256 $developmentTarItem.FullName)
        }
        $cargoPath = Resolve-RustTool "cargo"
        $rustcPath = Resolve-RustTool "rustc"
        Assert-NoReparsePointComponents $cargoPath
        Assert-NoReparsePointComponents $rustcPath
        $cargoInput = [PSCustomObject]@{ Path = $cargoPath; Hash = (Get-Sha256 $cargoPath) }
        $rustcInput = [PSCustomObject]@{ Path = $rustcPath; Hash = (Get-Sha256 $rustcPath) }
        $compilerInput = Resolve-DiscoveredExecutable "cl.exe"
        $librarianInput = Resolve-DiscoveredExecutable "lib.exe"
        $linkInput = Resolve-DiscoveredExecutable "link.exe"
        $rcInput = Resolve-DiscoveredExecutable "rc.exe"
        $sdkBinPath = (Microsoft.PowerShell.Management\Get-Item -LiteralPath (Microsoft.PowerShell.Management\Split-Path -Parent $rcInput.Path) -Force).FullName
        $sdkBinInput = [PSCustomObject]@{
            Path = $sdkBinPath
            Hash = (Get-DirectoryTreeSha256 $sdkBinPath)
        }
        $compilerBinPath = (Microsoft.PowerShell.Management\Get-Item -LiteralPath (Microsoft.PowerShell.Management\Split-Path -Parent $compilerInput.Path) -Force).FullName
        $compilerBinInput = [PSCustomObject]@{
            Path = $compilerBinPath
            Hash = (Get-DirectoryTreeSha256 $compilerBinPath)
        }
    }
    else {
        $gitInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_GIT_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_GIT_SHA256" "Git"
        $gitRootInput = Resolve-ExplicitPinnedDirectory "WAAL_WINDOWS_RELEASE_GIT_ROOT" "WAAL_WINDOWS_RELEASE_EXPECTED_GIT_ROOT_SHA256" "Git runtime tree"
        $tarInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_TAR_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_TAR_SHA256" "tar"
        $cargoInput = Resolve-ExplicitPinnedExecutable "WAAL_RELEASE_CARGO_PATH" "WAAL_RELEASE_EXPECTED_CARGO_SHA256" "Cargo"
        $rustcInput = Resolve-ExplicitPinnedExecutable "WAAL_RELEASE_RUSTC_PATH" "WAAL_RELEASE_EXPECTED_RUSTC_SHA256" "rustc"
        $compilerInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_CL_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_CL_SHA256" "cl.exe"
        $librarianInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_LIB_EXE_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_LIB_EXE_SHA256" "lib.exe"
        $linkInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_LINK_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_LINK_SHA256" "link.exe"
        $compilerBinInput = Resolve-ExplicitPinnedDirectory "WAAL_WINDOWS_RELEASE_MSVC_BIN" "WAAL_WINDOWS_RELEASE_EXPECTED_MSVC_BIN_SHA256" "MSVC compiler bin directory"
        $rcInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_RC_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_RC_SHA256" "rc.exe"
        $sdkBinInput = Resolve-ExplicitPinnedDirectory "WAAL_WINDOWS_RELEASE_SDK_BIN" "WAAL_WINDOWS_RELEASE_EXPECTED_SDK_BIN_SHA256" "Windows SDK executable tree"
        $signToolInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_SIGNTOOL_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_SIGNTOOL_SHA256" "signtool.exe"
    }

    $script:Git = $gitInput.Path
    $script:GitRoot = $gitRootInput.Path
    $script:Tar = $tarInput.Path
    $script:Cargo = $cargoInput.Path
    $script:Rustc = $rustcInput.Path
    $script:Compiler = $compilerInput.Path
    $script:Librarian = $librarianInput.Path
    $script:Linker = $linkInput.Path
    $script:CompilerBin = $compilerBinInput.Path
    $script:ResourceCompiler = $rcInput.Path
    $script:SdkBin = $sdkBinInput.Path
    $script:GitSha256 = $gitInput.Hash
    $script:GitRootSha256 = $gitRootInput.Hash
    $script:TarSha256 = $tarInput.Hash
    $script:CargoSha256 = $cargoInput.Hash
    $script:RustcSha256 = $rustcInput.Hash
    $script:CompilerSha256 = $compilerInput.Hash
    $script:LibrarianSha256 = $librarianInput.Hash
    $script:LinkerSha256 = $linkInput.Hash
    $script:CompilerBinSha256 = $compilerBinInput.Hash
    $script:ResourceCompilerSha256 = $rcInput.Hash
    $script:SdkBinSha256 = $sdkBinInput.Hash
    if (-not $Development) {
        $script:SignTool = $signToolInput.Path
        $script:SignToolSha256 = $signToolInput.Hash
    }

    $script:CargoVersion = Get-RustToolVersion $Cargo
    $script:RustcVersion = Get-RustToolVersion $Rustc
    if ($CargoVersion -cne $RustcVersion) {
        throw "Release Cargo and rustc versions must match exactly."
    }
    if ((Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $Cargo)) -ne (Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $Rustc))) {
        throw "Release Cargo and rustc must come from the same pinned toolchain directory."
    }
    foreach ($nativeTool in @($Compiler, $Librarian, $Linker)) {
        if ((Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $nativeTool)) -ne (Normalize-Path $CompilerBin)) {
            throw "cl.exe, lib.exe, and link.exe must all come from the pinned MSVC compiler bin directory."
        }
    }
    Assert-PathWithinPinnedDirectory $Git $GitRoot "Git executable"
    if (-not $Development) {
        $expectedPhysicalGit = Microsoft.PowerShell.Management\Join-Path $GitRoot "mingw64\bin\git.exe"
        if ((Normalize-Path $Git) -ne (Normalize-Path $expectedPhysicalGit)) {
            throw "WAAL_WINDOWS_RELEASE_GIT_PATH must name the physical Git-for-Windows mingw64\bin\git.exe inside WAAL_WINDOWS_RELEASE_GIT_ROOT."
        }
    }
    $expectedSystemTar = Microsoft.PowerShell.Management\Join-Path $WindowsSystemDirectory "tar.exe"
    if ((Normalize-Path $Tar) -ne (Normalize-Path $expectedSystemTar)) {
        throw "Release tar must be the physical tar.exe in the trusted Windows System32 directory."
    }
    Assert-PathWithinPinnedDirectory $ResourceCompiler $SdkBin "rc.exe"
    if ((Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $ResourceCompiler)) -ne
        (Normalize-Path $SdkBin)) {
        throw "rc.exe must be a direct child of the pinned Windows SDK x64 bin directory."
    }
    if (-not $Development) {
        Assert-PathWithinPinnedDirectory $SignTool $SdkBin "signtool.exe"
        if ((Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $SignTool)) -ne
            (Normalize-Path $SdkBin)) {
            throw "signtool.exe must be a direct child of the pinned Windows SDK x64 bin directory."
        }
    }
    $reportedGitExecPath = Invoke-SanitizedGit @("--exec-path")
    Assert-PathWithinPinnedDirectory $reportedGitExecPath $GitRoot "Git exec-path"
    $reportedSysroot = Invoke-Captured $Rustc @("--print", "sysroot")
    if ($Development) {
        Assert-NoReparsePointComponents $reportedSysroot
        $script:RustSysroot = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $reportedSysroot -Force).FullName
        $script:RustSysrootSha256 = Get-DirectoryTreeSha256 $RustSysroot
    }
    else {
        $sysrootInput = Resolve-ExplicitPinnedDirectory "WAAL_RELEASE_RUST_SYSROOT" "WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256" "Rust sysroot"
        $script:RustSysroot = $sysrootInput.Path
        $script:RustSysrootSha256 = $sysrootInput.Hash
        if ((Normalize-Path $reportedSysroot) -ne (Normalize-Path $RustSysroot)) {
            throw "WAAL_RELEASE_RUST_SYSROOT does not match the sysroot reported by the pinned rustc."
        }
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath (Microsoft.PowerShell.Management\Join-Path $RustSysroot "lib\rustlib\$TargetTriple\lib") -PathType Container)) {
        throw "Pinned Rust sysroot does not contain the $TargetTriple standard library."
    }

    $nativeHashes = if ($Development) {
        @($CompilerSha256, $LibrarianSha256, $LinkerSha256, $CompilerBinSha256, $ResourceCompilerSha256, $SdkBinSha256)
    }
    else {
        @($CompilerSha256, $LibrarianSha256, $LinkerSha256, $CompilerBinSha256, $ResourceCompilerSha256, $SdkBinSha256, $SignToolSha256)
    }
    $script:NativeToolchainSha256 = Get-OrderedHashAggregate $nativeHashes
    if (-not $Development) {
        $expectedNativeHash = Get-RequiredExpectedSha256 "WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256"
        if ($NativeToolchainSha256 -cne $expectedNativeHash) {
            throw "WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256 does not match the ordered cl.exe/lib.exe/link.exe/MSVC-bin/rc.exe/SDK-bin/signtool.exe aggregate."
        }
    }

    $libState = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_LIB" "WAAL_WINDOWS_RELEASE_EXPECTED_LIB_SHA256" $AmbientLib
    $includeState = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_INCLUDE" "WAAL_WINDOWS_RELEASE_EXPECTED_INCLUDE_SHA256" $AmbientInclude
    $libPathState = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_LIBPATH" "WAAL_WINDOWS_RELEASE_EXPECTED_LIBPATH_SHA256" $AmbientLibPath
    $script:TrustedLib = $libState.Value
    $script:TrustedInclude = $includeState.Value
    $script:TrustedLibPath = $libPathState.Value
    $script:TrustedLibSha256 = $libState.Hash
    $script:TrustedIncludeSha256 = $includeState.Hash
    $script:TrustedLibPathSha256 = $libPathState.Hash
    $script:ReleaseMaterialsSha256 = Get-OrderedHashAggregate @(
        $GitSha256,
        $GitRootSha256,
        $TarSha256,
        $CargoSha256,
        $RustcSha256,
        $RustSysrootSha256,
        $NativeToolchainSha256,
        $TrustedLibSha256,
        $TrustedIncludeSha256,
        $TrustedLibPathSha256
    )
    Assert-ReleaseToolchainIntegrity
}

function Assert-ToolchainMatchesManifest {
    $manifest = Microsoft.PowerShell.Management\Get-Content -LiteralPath (Microsoft.PowerShell.Management\Join-Path $ReleaseSourceDir "Cargo.toml") -Raw
    $expectedMatch = [regex]::Match($manifest, '(?m)^rust-version\s*=\s*"([0-9]+\.[0-9]+)"\s*$')
    if (-not $expectedMatch.Success) { throw "Release Cargo.toml must pin rust-version." }
    $expected = $expectedMatch.Groups[1].Value
    if ($RustcVersion -cne $expected -and -not $RustcVersion.StartsWith("$expected.")) {
        throw "Release toolchain $RustcVersion does not match Cargo.toml rust-version $expected."
    }
}

function Assert-ReleaseToolchainIntegrity {
    Assert-NoReparsePointComponents $WindowsDirectory
    Assert-NoReparsePointComponents $WindowsSystemDirectory
    if ((Normalize-Path ([Environment]::SystemDirectory)) -ne (Normalize-Path $WindowsSystemDirectory) -or
        (Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $WindowsSystemDirectory)) -ne (Normalize-Path $WindowsDirectory)) {
        throw "Trusted Windows directory resolution changed during packaging."
    }
    foreach ($tool in @(
        [PSCustomObject]@{ Path = $Git; Hash = $GitSha256; Name = "Git" },
        [PSCustomObject]@{ Path = $Tar; Hash = $TarSha256; Name = "tar" },
        [PSCustomObject]@{ Path = $Cargo; Hash = $CargoSha256; Name = "Cargo" },
        [PSCustomObject]@{ Path = $Rustc; Hash = $RustcSha256; Name = "rustc" },
        [PSCustomObject]@{ Path = $Compiler; Hash = $CompilerSha256; Name = "cl.exe" },
        [PSCustomObject]@{ Path = $Librarian; Hash = $LibrarianSha256; Name = "lib.exe" },
        [PSCustomObject]@{ Path = $Linker; Hash = $LinkerSha256; Name = "link.exe" },
        [PSCustomObject]@{ Path = $ResourceCompiler; Hash = $ResourceCompilerSha256; Name = "rc.exe" }
    )) {
        Assert-NoReparsePointComponents $tool.Path
        if ((Get-Sha256 $tool.Path) -cne $tool.Hash) {
            throw "$($tool.Name) changed after its release hash was pinned."
        }
    }
    $expectedSystemTar = Microsoft.PowerShell.Management\Join-Path $WindowsSystemDirectory "tar.exe"
    if ((Normalize-Path $Tar) -ne (Normalize-Path $expectedSystemTar)) {
        throw "Release tar moved outside the trusted Windows System32 directory."
    }
    if ((Get-DirectoryTreeSha256 $GitRoot) -cne $GitRootSha256) {
        throw "Git runtime tree changed after its release hash was pinned."
    }
    Assert-PathWithinPinnedDirectory $Git $GitRoot "Git executable"
    if (-not $Development) {
        $expectedPhysicalGit = Microsoft.PowerShell.Management\Join-Path $GitRoot "mingw64\bin\git.exe"
        if ((Normalize-Path $Git) -ne (Normalize-Path $expectedPhysicalGit)) {
            throw "Pinned Git executable is no longer the physical Git-for-Windows backend."
        }
    }
    $reportedGitExecPath = Invoke-SanitizedGit @("--exec-path")
    Assert-PathWithinPinnedDirectory $reportedGitExecPath $GitRoot "Git exec-path"
    if ((Get-DirectoryTreeSha256 $CompilerBin) -cne $CompilerBinSha256) {
        throw "MSVC compiler bin directory changed after its release hash was pinned."
    }
    if ((Get-DirectoryTreeSha256 $SdkBin) -cne $SdkBinSha256) {
        throw "Windows SDK executable tree changed after its release hash was pinned."
    }
    Assert-PathWithinPinnedDirectory $ResourceCompiler $SdkBin "rc.exe"
    if ((Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $ResourceCompiler)) -ne
        (Normalize-Path $SdkBin)) {
        throw "rc.exe moved outside the pinned Windows SDK x64 bin directory."
    }
    if (-not $Development) {
        Assert-NoReparsePointComponents $SignTool
        if ((Get-Sha256 $SignTool) -cne $SignToolSha256) {
            throw "signtool.exe changed after its release hash was pinned."
        }
        Assert-PathWithinPinnedDirectory $SignTool $SdkBin "signtool.exe"
        if ((Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $SignTool)) -ne
            (Normalize-Path $SdkBin)) {
            throw "signtool.exe moved outside the pinned Windows SDK x64 bin directory."
        }
    }
    $reportedSysroot = Invoke-Captured $Rustc @("--print", "sysroot")
    if ((Normalize-Path $reportedSysroot) -ne (Normalize-Path $RustSysroot)) {
        throw "rustc no longer reports the pinned Rust sysroot."
    }
    if ((Get-DirectoryTreeSha256 $RustSysroot) -cne $RustSysrootSha256) {
        throw "Rust sysroot changed after its release hash was pinned."
    }
    $nativeHashes = if ($Development) {
        @($CompilerSha256, $LibrarianSha256, $LinkerSha256, $CompilerBinSha256, $ResourceCompilerSha256, $SdkBinSha256)
    }
    else {
        @($CompilerSha256, $LibrarianSha256, $LinkerSha256, $CompilerBinSha256, $ResourceCompilerSha256, $SdkBinSha256, $SignToolSha256)
    }
    if ((Get-OrderedHashAggregate $nativeHashes) -cne $NativeToolchainSha256) {
        throw "Native toolchain aggregate changed after it was pinned."
    }
    if ((Get-TrustedDirectoryListContentSha256 $TrustedLib) -cne $TrustedLibSha256) {
        throw "Approved MSVC LIB directory content changed after it was pinned."
    }
    if ((Get-TrustedDirectoryListContentSha256 $TrustedInclude) -cne $TrustedIncludeSha256) {
        throw "Approved MSVC INCLUDE directory content changed after it was pinned."
    }
    if ((Get-TrustedDirectoryListContentSha256 $TrustedLibPath) -cne $TrustedLibPathSha256) {
        throw "Approved MSVC LIBPATH directory content changed after it was pinned."
    }
    $currentMaterialsSha256 = Get-OrderedHashAggregate @(
        $GitSha256,
        $GitRootSha256,
        $TarSha256,
        $CargoSha256,
        $RustcSha256,
        $RustSysrootSha256,
        $NativeToolchainSha256,
        $TrustedLibSha256,
        $TrustedIncludeSha256,
        $TrustedLibPathSha256
    )
    if ($currentMaterialsSha256 -cne $ReleaseMaterialsSha256) {
        throw "Release material aggregate changed after it was pinned."
    }
}

function Assert-NoCargoConfigInAncestors {
    param([Parameter(Mandatory = $true)][string]$WorkingDirectory)

    $current = [IO.DirectoryInfo](Microsoft.PowerShell.Management\Resolve-Path $WorkingDirectory).ProviderPath
    while ($current) {
        foreach ($name in @("config", "config.toml")) {
            $candidate = Microsoft.PowerShell.Management\Join-Path (Microsoft.PowerShell.Management\Join-Path $current.FullName ".cargo") $name
            if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $candidate) {
                throw "External Cargo configuration is not allowed in a distribution build: $candidate"
            }
        }
        $current = $current.Parent
    }
}

function Prepare-IsolatedBuildEnvironment {
    $script:BuildTargetDir = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot "target"
    $script:BuildHome = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot "build-home"
    $script:CargoHome = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot "cargo-home"
    $script:CargoWorkingDir = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot "cargo-work"
    $script:BuildTempDir = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot "tmp"
    foreach ($directory in @($BuildTargetDir, $BuildHome, $CargoHome, $CargoWorkingDir, $BuildTempDir)) {
        Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $directory | Microsoft.PowerShell.Core\Out-Null
        Assert-RealDirectory $directory
    }
    Assert-NoCargoConfigInAncestors $CargoWorkingDir
    foreach ($candidate in @(
        (Microsoft.PowerShell.Management\Join-Path $CargoHome "config"),
        (Microsoft.PowerShell.Management\Join-Path $CargoHome "config.toml"),
        (Microsoft.PowerShell.Management\Join-Path $ReleaseSourceDir ".cargo\config"),
        (Microsoft.PowerShell.Management\Join-Path $ReleaseSourceDir ".cargo\config.toml")
    )) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $candidate) {
            throw "Distribution builds do not accept Cargo configuration outside packager-owned flags: $candidate"
        }
    }
}

function Invoke-SanitizedCargo {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$CaptureOutput
    )

    Assert-NoCargoConfigInAncestors $CargoWorkingDir
    Assert-MaterializedReleaseSource
    Assert-ReleaseToolchainIntegrity
    $existingEnvironment = [Environment]::GetEnvironmentVariables("Process")
    $managedNames = @()
    foreach ($entry in $existingEnvironment.GetEnumerator()) {
        if ($entry.Key -match '^(CARGO_|RUST|WAAL_|CC(?:$|_)|CXX(?:$|_)|AR(?:$|_)|RANLIB(?:$|_)|CFLAGS(?:$|_)|CXXFLAGS(?:$|_)|CPPFLAGS(?:$|_)|ARFLAGS(?:$|_)|HOST_(?:CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|CPPFLAGS|ARFLAGS)$|TARGET_(?:CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|CPPFLAGS|ARFLAGS)$|CRATE_CC_NO_DEFAULTS$|CC_ENABLE_DEBUG_OUTPUT$|CC_SHELL_ESCAPED_FLAGS$|CC_KNOWN_WRAPPER_CUSTOM$|CXXSTDLIB(?:_STATIC)?$|LDFLAGS$|DYLD_|LIB$|INCLUDE$|LIBPATH$|CL$|_CL_$|LINK$|_LINK_$|RC(?:$|_)|SYSTEMROOT$|WINDIR$|VCINSTALLDIR$|VCToolsInstallDir$|VSINSTALLDIR$|WindowsSdkDir$|UniversalCRTSdkDir$|UCRTVersion$|WindowsSDKVersion$)') {
            $managedNames += [string]$entry.Key
        }
    }
    $managedNames += @("HOME", "USERPROFILE", "TEMP", "TMP", "PATH", "RUSTC", "CARGO_HOME")
    $managedNames = @($managedNames | Microsoft.PowerShell.Utility\Sort-Object -Unique)
    $original = @{}
    foreach ($name in $managedNames) {
        if ($existingEnvironment.Contains($name)) { $original[$name] = [string]$existingEnvironment[$name] }
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }

    $separator = [char]0x1f
    $rustFlags = "--remap-path-prefix=$ReleaseSourceDir=." + $separator + "--remap-path-prefix=$RootDir=."
    $pathDirectories = @(
        (Microsoft.PowerShell.Management\Split-Path -Parent $Cargo),
        $CompilerBin,
        (Microsoft.PowerShell.Management\Split-Path -Parent $ResourceCompiler),
        $WindowsSystemDirectory,
        $WindowsDirectory
    ) | Microsoft.PowerShell.Utility\Select-Object -Unique
    $controlled = @{
        HOME = $BuildHome
        USERPROFILE = $BuildHome
        TEMP = $BuildTempDir
        TMP = $BuildTempDir
        PATH = ($pathDirectories -join ";")
        SYSTEMROOT = $WindowsDirectory
        WINDIR = $WindowsDirectory
        CARGO_HOME = $CargoHome
        CARGO_TARGET_DIR = $BuildTargetDir
        CARGO_ENCODED_RUSTFLAGS = $rustFlags
        CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $Linker
        CC = $Compiler
        CXX = $Compiler
        AR = $Librarian
        RANLIB = $Librarian
        HOST_CC = $Compiler
        HOST_CXX = $Compiler
        HOST_AR = $Librarian
        HOST_RANLIB = $Librarian
        TARGET_CC = $Compiler
        TARGET_CXX = $Compiler
        TARGET_AR = $Librarian
        TARGET_RANLIB = $Librarian
        RC = $ResourceCompiler
        RC_x86_64_pc_windows_msvc = $ResourceCompiler
        RUSTC = $Rustc
        RUSTC_WRAPPER = ""
        RUSTC_WORKSPACE_WRAPPER = ""
        WAAL_RELEASE_GIT_COMMIT = $ReleaseGitCommit
        WAAL_RELEASE_GIT_TREE = $ReleaseGitTree
        WAAL_RELEASE_CARGO_VERSION = $CargoVersion
        WAAL_RELEASE_RUSTC_VERSION = $RustcVersion
        WAAL_RELEASE_CARGO_SHA256 = $CargoSha256
        WAAL_RELEASE_RUSTC_SHA256 = $RustcSha256
        WAAL_RELEASE_RUST_SYSROOT_SHA256 = $RustSysrootSha256
        WAAL_RELEASE_NATIVE_TOOLCHAIN_SHA256 = $NativeToolchainSha256
        WAAL_RELEASE_MATERIALS_SHA256 = $ReleaseMaterialsSha256
        WAAL_WINDOWS_AUTHENTICODE_PUBLISHER = $WindowsPublisher
        WAAL_WINDOWS_AUTHENTICODE_CERT_SHA256 = $WindowsSignerCertSha256
        LIB = $TrustedLib
        INCLUDE = $TrustedInclude
        LIBPATH = $TrustedLibPath
        CL = ""
        _CL_ = ""
        LINK = ""
        _LINK_ = ""
    }
    $targetEnvironmentTriple = $TargetTriple.Replace('-', '_')
    foreach ($prefix in @("CC", "CXX")) {
        $controlled["${prefix}_$TargetTriple"] = $Compiler
        $controlled["${prefix}_$targetEnvironmentTriple"] = $Compiler
    }
    foreach ($prefix in @("AR", "RANLIB")) {
        $controlled["${prefix}_$TargetTriple"] = $Librarian
        $controlled["${prefix}_$targetEnvironmentTriple"] = $Librarian
    }
    $controlled["RC_$TargetTriple"] = $ResourceCompiler
    $controlled["RC_$targetEnvironmentTriple"] = $ResourceCompiler
    if ($Development) {
        $controlled.WAAL_DEVELOPMENT_RELEASE = "1"
    }
    else {
        $controlled.WAAL_PUBLISHABLE_RELEASE = "1"
    }
    foreach ($name in $controlled.Keys) {
        if ($name -notin $managedNames) {
            if ($existingEnvironment.Contains($name)) {
                $original[$name] = [string]$existingEnvironment[$name]
            }
            [Environment]::SetEnvironmentVariable([string]$name, $null, "Process")
            $managedNames += [string]$name
        }
    }

    $captured = $null
    try {
        foreach ($entry in $controlled.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, "Process")
        }
        Microsoft.PowerShell.Management\Push-Location $CargoWorkingDir
        try {
            if ($CaptureOutput) {
                $stderrPath = Microsoft.PowerShell.Management\Join-Path $BuildTempDir ("cargo-stderr-" + [Guid]::NewGuid().ToString("N") + ".txt")
                $output = & $Cargo @Arguments 2> $stderrPath
                if ($LASTEXITCODE -ne 0) {
                    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $stderrPath) {
                        Microsoft.PowerShell.Management\Get-Content -LiteralPath $stderrPath | Microsoft.PowerShell.Core\ForEach-Object { Microsoft.PowerShell.Utility\Write-Host $_ }
                    }
                    throw "Cargo command failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
                }
                $captured = ($output | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
            }
            else {
                Invoke-Checked $Cargo $Arguments
            }
        }
        finally {
            Microsoft.PowerShell.Management\Pop-Location
        }
    }
    finally {
        foreach ($name in $managedNames) {
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
        }
        foreach ($entry in $original.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, "Process")
        }
    }
    Assert-MaterializedReleaseSource
    Assert-ReleaseToolchainIntegrity
    if ($CaptureOutput) { return $captured }
}

function Verify-ReleaseDependencyGraph {
    $metadataJson = Invoke-SanitizedCargo @(
        "metadata", "--locked", "--format-version", "1", "--filter-platform", $TargetTriple,
        "--manifest-path", (Microsoft.PowerShell.Management\Join-Path $ReleaseSourceDir "Cargo.toml")
    ) -CaptureOutput
    $metadata = $metadataJson | Microsoft.PowerShell.Utility\ConvertFrom-Json
    $rootManifest = Normalize-Path (Microsoft.PowerShell.Management\Join-Path $ReleaseSourceDir "Cargo.toml")
    foreach ($package in $metadata.packages) {
        if ($null -eq $package.source) {
            if ((Normalize-Path $package.manifest_path) -ne $rootManifest) {
                throw "Distribution dependency graph contains an external path package: $($package.manifest_path)"
            }
        }
        elseif ($package.source -cne "registry+https://github.com/rust-lang/crates.io-index") {
            throw "Distribution dependency graph contains a non-crates.io source: $($package.source)"
        }
    }
}

function Require-MetadataField {
    param(
        [Parameter(Mandatory = $true)][string]$Metadata,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Expected
    )
    if (-not $Metadata.Contains(";$Name=$Expected;")) {
        throw "Executable build metadata field $Name does not match the expected value."
    }
}

function Verify-ExecutableMetadata {
    param([Parameter(Mandatory = $true)][string]$ExecutablePath)

    $ascii = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($ExecutablePath))
    $markers = @($ascii.Split([char]0) | Microsoft.PowerShell.Core\Where-Object { $_.StartsWith("WAAL_BUILD_METADATA_V1;") })
    if ($markers.Count -ne 1) {
        throw "Executable must contain exactly one WAAL build metadata marker; found $($markers.Count)."
    }
    $metadata = $markers[0]
    $expectedArtifactKind = if ($Development) { "development" } else { "release" }
    Require-MetadataField $metadata "artifact-kind" $expectedArtifactKind
    Require-MetadataField $metadata "profile" "release"
    Require-MetadataField $metadata "target-os" "windows"
    Require-MetadataField $metadata "target-arch" "x86_64"
    Require-MetadataField $metadata "debug-assertions" "false"
    Require-MetadataField $metadata "debug-fill" "false"
    Require-MetadataField $metadata "dev-tools" "false"
    Require-MetadataField $metadata "diagnostics-ui" "false"
    Require-MetadataField $metadata "release-diagnostics" "false"
    Require-MetadataField $metadata "windows-authenticode-publisher" $WindowsPublisher
    Require-MetadataField $metadata "source-git-commit" $ReleaseGitCommit
    Require-MetadataField $metadata "source-git-tree" $ReleaseGitTree
    Require-MetadataField $metadata "release-cargo-version" $CargoVersion
    Require-MetadataField $metadata "release-rustc-version" $RustcVersion
    Require-MetadataField $metadata "release-cargo-sha256" $CargoSha256
    Require-MetadataField $metadata "release-rustc-sha256" $RustcSha256
    Require-MetadataField $metadata "release-rust-sysroot-sha256" $RustSysrootSha256
    Require-MetadataField $metadata "release-native-toolchain-sha256" $NativeToolchainSha256
    Require-MetadataField $metadata "release-materials-sha256" $ReleaseMaterialsSha256
    Require-MetadataField $metadata "windows-authenticode-cert-sha256" $WindowsSignerCertSha256
}

function Resolve-SigningCertificate {
    $normalizedThumbprint = $SigningCertificateThumbprint.Replace(" ", "").ToUpperInvariant()
    if ($normalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
        throw "WAAL_WINDOWS_SIGN_CERT_THUMBPRINT must be an exact 40-hex certificate thumbprint for a code-signing certificate."
    }
    $certificate = Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath "Cert:\CurrentUser\My\$normalizedThumbprint" -ErrorAction SilentlyContinue |
        Microsoft.PowerShell.Utility\Select-Object -First 1
    if (-not $certificate) {
        throw "The requested Authenticode signing certificate is not installed in CurrentUser\\My. LocalMachine certificates are intentionally unsupported because signtool store selection must be unambiguous."
    }
    if (-not $certificate.HasPrivateKey) { throw "The requested Authenticode certificate has no accessible private key." }
    if ($certificate.NotAfter -le [DateTime]::UtcNow) { throw "The requested Authenticode certificate is expired." }
    if (-not ($certificate.EnhancedKeyUsageList | Microsoft.PowerShell.Core\Where-Object { $_.ObjectId.Value -eq "1.3.6.1.5.5.7.3.3" })) {
        throw "The requested certificate is not valid for code signing."
    }
    return $certificate
}

function Get-CertificateSha256 {
    param([Parameter(Mandatory = $true)]$Certificate)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($Certificate.RawData)
    }
    finally {
        $sha256.Dispose()
    }
    return (($digest | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString("x2") }) -join "")
}

function Sign-AndVerify-Executable {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)]$Certificate
    )

    if (-not $SignTool) { throw "Pinned signtool.exe was not initialized." }
    $timestampUri = $null
    if (-not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$timestampUri) -or
        $timestampUri.Scheme -notin @("http", "https")) {
        throw "WAAL_WINDOWS_TIMESTAMP_URL must be an absolute HTTP(S) RFC 3161 timestamp URL."
    }
    Assert-ReleaseToolchainIntegrity
    Invoke-Checked $SignTool @(
        "sign", "/sha1", $Certificate.Thumbprint, "/fd", "SHA256",
        "/tr", $timestampUri.AbsoluteUri, "/td", "SHA256", $ExecutablePath
    )
    Invoke-Checked $SignTool @("verify", "/pa", "/all", "/v", $ExecutablePath)
    Assert-ReleaseToolchainIntegrity
    Assert-AuthenticodeExecutable $ExecutablePath $Certificate
}

function Assert-AuthenticodeExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)]$Certificate
    )

    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $ExecutablePath
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode signature validation failed: $($signature.Status) $($signature.StatusMessage)"
    }
    if (-not $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -cne $Certificate.Thumbprint) {
        throw "Authenticode signer certificate does not match the requested thumbprint."
    }
    $verifiedPublisher = $signature.SignerCertificate.GetNameInfo(
        [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false
    ).Trim()
    if ($verifiedPublisher -cne $WindowsPublisher) {
        throw "Authenticode signer publisher does not match the publisher embedded at compile time."
    }
    if ((Get-CertificateSha256 $signature.SignerCertificate) -cne $WindowsSignerCertSha256) {
        throw "Authenticode signer certificate does not match the SHA-256 fingerprint embedded at compile time."
    }
    if (-not $signature.TimeStamperCertificate) {
        throw "Publishable Windows executable is missing a trusted RFC 3161 timestamp."
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    [IO.File]::WriteAllText($Path, $Content, (Microsoft.PowerShell.Utility\New-Object Text.UTF8Encoding($false)))
}

function Get-CoreDistributionPayloadHashes {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $hashes = [ordered]@{}
    foreach ($fileName in @($ExeName, "README.md", "LICENSE", "config.example.json")) {
        $path = Microsoft.PowerShell.Management\Join-Path $Directory $fileName
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf) -or
            (((Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Distribution payload is missing a regular file: $fileName"
        }
        $hashes[$fileName] = Get-Sha256 $path
    }
    return $hashes
}

function Get-DistributionPayloadHashes {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $hashes = Get-CoreDistributionPayloadHashes $Directory
    $provenancePath = Microsoft.PowerShell.Management\Join-Path $Directory "BUILD-PROVENANCE.txt"
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $provenancePath -PathType Leaf) -or
        (((Microsoft.PowerShell.Management\Get-Item -LiteralPath $provenancePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Distribution payload is missing a regular file: BUILD-PROVENANCE.txt"
    }
    $hashes["BUILD-PROVENANCE.txt"] = Get-Sha256 $provenancePath
    return $hashes
}

function Get-Sha256ManifestContent {
    param([Parameter(Mandatory = $true)]$PayloadHashes)

    $lines = foreach ($fileName in @(
        $ExeName, "README.md", "LICENSE", "config.example.json", "BUILD-PROVENANCE.txt"
    )) {
        "$($PayloadHashes[$fileName])  $fileName"
    }
    return (($lines -join "`r`n") + "`r`n")
}

function Assert-WindowsDistribution {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)]$ExpectedPayloadHashes,
        [Parameter(Mandatory = $true)][string]$ExpectedProvenance
    )

    Assert-RealDirectory $Directory
    $expectedNames = @(
        $ExeName, "README.md", "LICENSE", "config.example.json",
        "SHA256SUMS.txt", "BUILD-PROVENANCE.txt"
    )
    $actualNames = @()
    foreach ($item in Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Directory -Force) {
        if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Distribution contains a directory, link, or reparse point: $($item.Name)"
        }
        $actualNames += $item.Name
    }
    $expectedSorted = @($expectedNames | Microsoft.PowerShell.Utility\Sort-Object -CaseSensitive)
    $actualSorted = @($actualNames | Microsoft.PowerShell.Utility\Sort-Object -CaseSensitive)
    if (($expectedSorted -join "`n") -cne ($actualSorted -join "`n")) {
        throw "Distribution file set does not match the expected package contents."
    }

    $executable = Microsoft.PowerShell.Management\Join-Path $Directory $ExeName
    Verify-ExecutableMetadata $executable
    $actualPayloadHashes = Get-DistributionPayloadHashes $Directory
    foreach ($fileName in @(
        $ExeName, "README.md", "LICENSE", "config.example.json", "BUILD-PROVENANCE.txt"
    )) {
        if ($actualPayloadHashes[$fileName] -cne $ExpectedPayloadHashes[$fileName]) {
            throw "Distribution payload hash changed during publication: $fileName"
        }
    }
    $expectedManifest = Get-Sha256ManifestContent $ExpectedPayloadHashes
    if ([IO.File]::ReadAllText((Microsoft.PowerShell.Management\Join-Path $Directory "SHA256SUMS.txt")) -cne $expectedManifest) {
        throw "Distribution SHA256SUMS.txt does not match the complete payload."
    }
    if ([IO.File]::ReadAllText((Microsoft.PowerShell.Management\Join-Path $Directory "BUILD-PROVENANCE.txt")) -cne $ExpectedProvenance) {
        throw "Distribution BUILD-PROVENANCE.txt does not match the pinned build inputs."
    }
    if (-not $Development) {
        Assert-AuthenticodeExecutable $executable $SigningCertificate
    }
}

$primaryFailure = $null
$cleanupFailure = $null
try {
    $ReleaseRoot = New-ReleaseRoot
    Resolve-AndVerify-Toolchain
    $sourceState = Get-ReleaseSourceState $Git
    $ReleaseGitCommit = $sourceState.Commit
    $ReleaseGitTree = $sourceState.Tree
    $DistDir = Microsoft.PowerShell.Management\Join-Path $DistRoot "$DistName-$ReleaseGitCommit"
    Assert-ReleaseToolchainIntegrity
    Materialize-ReleaseSource $Git $Tar
    Assert-ReleaseToolchainIntegrity
    Prepare-IsolatedBuildEnvironment
    Assert-ToolchainMatchesManifest
    if (-not $Development) {
        if (-not $SigningCertificateThumbprint) {
            throw "Publishable Windows distribution requires WAAL_WINDOWS_SIGN_CERT_THUMBPRINT or -SigningCertificateThumbprint. Use -Development only for an explicitly unsigned local VM artifact."
        }
        $SigningCertificate = Resolve-SigningCertificate
        $WindowsPublisher = $SigningCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        ).Trim()
        $WindowsSignerCertSha256 = Get-CertificateSha256 $SigningCertificate
        if (-not $WindowsPublisher -or $WindowsPublisher.Length -gt 512 -or $WindowsPublisher -match '[;\r\n]') {
            throw "Authenticode certificate subject cannot be represented safely in build metadata."
        }
        if (-not (Test-LowerHex $WindowsSignerCertSha256 64)) {
            throw "Unable to capture the signing certificate SHA-256 fingerprint."
        }
    }
    Verify-ReleaseDependencyGraph
    Assert-ReleaseSourceUnchanged $Git

    $manifestPath = Microsoft.PowerShell.Management\Join-Path $ReleaseSourceDir "Cargo.toml"
    if (-not $SkipTests) {
        Microsoft.PowerShell.Utility\Write-Host "Running tests from the verified source snapshot..."
        Invoke-SanitizedCargo @(
            "test", "--locked", "--target", $TargetTriple, "--all-targets", "--all-features",
            "--manifest-path", $manifestPath
        )
    }

    Microsoft.PowerShell.Utility\Write-Host "Building release executable from the verified source snapshot..."
    Invoke-SanitizedCargo @(
        "build", "--locked", "--release", "--target", $TargetTriple,
        "--bin", $BinaryName, "--manifest-path", $manifestPath
    )
    $targetExe = Microsoft.PowerShell.Management\Join-Path $BuildTargetDir "$TargetTriple\release\$BinaryName.exe"
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $targetExe -PathType Leaf)) {
        throw "Release build did not produce expected executable: $targetExe"
    }
    Verify-ExecutableMetadata $targetExe
    Assert-ReleaseSourceUnchanged $Git

    $stagedDist = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot $DistName
    Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $stagedDist | Microsoft.PowerShell.Core\Out-Null
    Assert-RealDirectory $stagedDist
    $stagedExe = Microsoft.PowerShell.Management\Join-Path $stagedDist $ExeName
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $targetExe -Destination $stagedExe
    Assert-MaterializedReleaseSource
    foreach ($fileName in @("README.md", "LICENSE", "config.example.json")) {
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath (Microsoft.PowerShell.Management\Join-Path $ReleaseSourceDir $fileName) -Destination $stagedDist
    }
    Assert-MaterializedReleaseSource

    $signerDescription = "none-development-only"
    if ($Development) {
        Microsoft.PowerShell.Utility\Write-Warning "Creating an unsigned DEVELOPMENT distribution. It is not a publishable release."
    }
    else {
        Sign-AndVerify-Executable $stagedExe $SigningCertificate
        $signerDescription = $SigningCertificate.Thumbprint
    }
    Verify-ExecutableMetadata $stagedExe

    $corePayloadHashes = Get-CoreDistributionPayloadHashes $stagedDist
    $exeSha256 = $corePayloadHashes[$ExeName]
    $artifactKind = if ($Development) { "development-unsigned" } else { "release-authenticode" }
    $provenance = @(
        "WAAL_WINDOWS_BUILD_PROVENANCE_V1",
        "artifact-kind=$artifactKind",
        "target=$TargetTriple",
        "source-git-commit=$ReleaseGitCommit",
        "source-git-tree=$ReleaseGitTree",
        "git-sha256=$GitSha256",
        "git-runtime-content-sha256=$GitRootSha256",
        "tar-sha256=$TarSha256",
        "cargo-version=$CargoVersion",
        "cargo-sha256=$CargoSha256",
        "rustc-version=$RustcVersion",
        "rustc-sha256=$RustcSha256",
        "rust-sysroot-sha256=$RustSysrootSha256",
        "cl-sha256=$CompilerSha256",
        "lib-exe-sha256=$LibrarianSha256",
        "link-sha256=$LinkerSha256",
        "msvc-bin-content-sha256=$CompilerBinSha256",
        "rc-sha256=$ResourceCompilerSha256",
        "windows-sdk-bin-content-sha256=$SdkBinSha256",
        "signtool-sha256=$SignToolSha256",
        "native-toolchain-sha256=$NativeToolchainSha256",
        "release-materials-sha256=$ReleaseMaterialsSha256",
        "msvc-lib-content-sha256=$TrustedLibSha256",
        "msvc-include-content-sha256=$TrustedIncludeSha256",
        "msvc-libpath-content-sha256=$TrustedLibPathSha256",
        "authenticode-publisher=$WindowsPublisher",
        "authenticode-certificate-sha256=$WindowsSignerCertSha256",
        "authenticode-signer-thumbprint=$signerDescription",
        "executable-sha256=$exeSha256",
        "readme-sha256=$($corePayloadHashes['README.md'])",
        "license-sha256=$($corePayloadHashes['LICENSE'])",
        "config-example-sha256=$($corePayloadHashes['config.example.json'])"
    ) -join "`r`n"
    $expectedProvenance = $provenance + "`r`n"
    Write-Utf8NoBom (Microsoft.PowerShell.Management\Join-Path $stagedDist "BUILD-PROVENANCE.txt") $expectedProvenance
    $payloadHashes = Get-DistributionPayloadHashes $stagedDist
    Write-Utf8NoBom (Microsoft.PowerShell.Management\Join-Path $stagedDist "SHA256SUMS.txt") (Get-Sha256ManifestContent $payloadHashes)

    Assert-ReleaseSourceUnchanged $Git
    Assert-WindowsDistribution $stagedDist $payloadHashes $expectedProvenance
    Assert-ReleaseToolchainIntegrity
    if ($StopRunning) { Stop-DistProcesses }
    $candidateDir = New-PublicationCandidate
    foreach ($fileName in @(
        $ExeName, "README.md", "LICENSE", "config.example.json", "SHA256SUMS.txt", "BUILD-PROVENANCE.txt"
    )) {
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath (Microsoft.PowerShell.Management\Join-Path $stagedDist $fileName) -Destination $candidateDir
    }
    Assert-WindowsDistribution $candidateDir $payloadHashes $expectedProvenance
    Assert-ReleaseSourceUnchanged $Git
    Assert-ReleaseToolchainIntegrity
    Activate-PublicationCandidate
    $finalExe = Microsoft.PowerShell.Management\Join-Path $DistDir $ExeName
    Assert-WindowsDistribution $DistDir $payloadHashes $expectedProvenance
    Assert-ReleaseSourceUnchanged $Git
    Assert-ReleaseToolchainIntegrity
    $finalHash = Get-Sha256 $finalExe
    Complete-Publication

    Microsoft.PowerShell.Utility\Write-Host "Windows distribution complete:"
    Microsoft.PowerShell.Utility\Write-Host "  $DistDir"
    Microsoft.PowerShell.Utility\Write-Host "  $finalExe"
    Microsoft.PowerShell.Utility\Write-Host "  SHA-256: $finalHash"
    if ($Development) { Microsoft.PowerShell.Utility\Write-Warning "This output is unsigned and development-only." }
}
catch {
    $primaryFailure = $_
}
finally {
    try {
        if (-not $PublicationComplete) {
            Restore-PublicationAfterFailure
        }
    }
    catch {
        $cleanupFailure = $_
    }
    try {
        Remove-ReleaseRootSafely
    }
    catch {
        if ($cleanupFailure) {
            Microsoft.PowerShell.Utility\Write-Warning "Release-root cleanup also failed: $($_.Exception.Message)"
        }
        else {
            $cleanupFailure = $_
        }
    }
    finally {
        # Release cleanup must never strand the caller with our sanitized
        # Windows directory environment, even when cleanup itself fails. A
        # restoration error is recorded so it cannot mask the primary failure.
        foreach ($environmentRestore in @(
            [PSCustomObject]@{ Name = "SYSTEMROOT"; Value = $AmbientSystemRoot },
            [PSCustomObject]@{ Name = "WINDIR"; Value = $AmbientWinDir }
        )) {
            try {
                [Environment]::SetEnvironmentVariable(
                    $environmentRestore.Name,
                    $environmentRestore.Value,
                    "Process"
                )
            }
            catch {
                if ($cleanupFailure) {
                    Microsoft.PowerShell.Utility\Write-Warning "Environment restoration also failed for $($environmentRestore.Name): $($_.Exception.Message)"
                }
                else {
                    $cleanupFailure = $_
                }
            }
        }
    }
}
if ($primaryFailure) {
    if ($cleanupFailure) {
        Microsoft.PowerShell.Utility\Write-Warning "Release cleanup also failed after the primary error: $($cleanupFailure.Exception.Message)"
    }
    throw $primaryFailure
}
if ($cleanupFailure) {
    throw $cleanupFailure
}
