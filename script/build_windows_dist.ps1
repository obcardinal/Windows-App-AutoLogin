param(
    [switch]$SkipTests,
    [switch]$StopRunning,
    [switch]$ReuseBuild,
    [switch]$Development,
    [string]$SigningCertificateThumbprint = "",
    [string]$TimestampUrl = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).ProviderPath
$BinaryName = "windows-app-autologin"
$ExeName = "WindowsAppAutoLogin.exe"
$TargetTriple = "x86_64-pc-windows-msvc"
$ProductionDistName = "WindowsAppAutoLogin-windows-x86_64"
$DevelopmentDistName = "WindowsAppAutoLogin-windows-x86_64-development"
$DistName = if ($Development) { $DevelopmentDistName } else { $ProductionDistName }
$DistRoot = Join-Path $RootDir "dist"
$DistDir = Join-Path $DistRoot $DistName
$ReleaseRoot = $null
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
$Tar = $null
$Linker = $null
$ResourceCompiler = $null
$SignTool = $null
$CargoVersion = $null
$RustcVersion = $null
$CargoSha256 = $null
$RustcSha256 = $null
$RustSysrootSha256 = $null
$GitSha256 = $null
$TarSha256 = $null
$LinkerSha256 = $null
$ResourceCompilerSha256 = $null
$SignToolSha256 = ""
$NativeToolchainSha256 = $null
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
$PublicationBackupDir = $null
$PublicationFinalActivated = $false
$PublicationComplete = $false
$PublicationHadOriginal = $false
$AmbientLib = [Environment]::GetEnvironmentVariable("LIB", "Process")
$AmbientInclude = [Environment]::GetEnvironmentVariable("INCLUDE", "Process")
$AmbientLibPath = [Environment]::GetEnvironmentVariable("LIBPATH", "Process")

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

    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
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
        & $FilePath @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
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
        $output | ForEach-Object { Write-Host $_ }
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
    return (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine).Trim()
}

function Invoke-SanitizedGit {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$CaptureOutput
    )

    if (-not $ReleaseRoot) { throw "Release root must exist before invoking provenance Git." }
    $gitHome = Join-Path $ReleaseRoot "git-home"
    if (-not (Test-Path -LiteralPath $gitHome)) {
        New-Item -ItemType Directory -Path $gitHome | Out-Null
    }
    Assert-RealDirectory $gitHome

    $existing = [Environment]::GetEnvironmentVariables("Process")
    $managed = @($existing.Keys | Where-Object {
        $_ -match '^GIT_' -or $_ -in @("HOME", "USERPROFILE", "XDG_CONFIG_HOME")
    }) + @(
        "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL",
        "GIT_NO_REPLACE_OBJECTS", "HOME", "USERPROFILE", "XDG_CONFIG_HOME"
    )
    $managed = @($managed | Sort-Object -Unique)
    $saved = @{}
    foreach ($name in $managed) {
        if ($existing.Contains($name)) { $saved[$name] = [string]$existing[$name] }
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    $sanitizedArguments = @(
        "--no-replace-objects",
        "-c", "core.attributesFile=NUL",
        "-c", "core.hooksPath=NUL"
    ) + $Arguments
    try {
        [Environment]::SetEnvironmentVariable("HOME", $gitHome, "Process")
        [Environment]::SetEnvironmentVariable("USERPROFILE", $gitHome, "Process")
        [Environment]::SetEnvironmentVariable("XDG_CONFIG_HOME", $gitHome, "Process")
        [Environment]::SetEnvironmentVariable("GIT_CONFIG_NOSYSTEM", "1", "Process")
        [Environment]::SetEnvironmentVariable("GIT_CONFIG_SYSTEM", "NUL", "Process")
        [Environment]::SetEnvironmentVariable("GIT_CONFIG_GLOBAL", "NUL", "Process")
        [Environment]::SetEnvironmentVariable("GIT_NO_REPLACE_OBJECTS", "1", "Process")
        if ($CaptureOutput) {
            return Invoke-Captured $GitPath $sanitizedArguments
        }
        Invoke-Checked $GitPath $sanitizedArguments
    }
    finally {
        foreach ($name in $managed) {
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
        }
        foreach ($entry in $saved.GetEnumerator()) {
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
    if ((Normalize-Path $fullPath) -ne (Normalize-Path $Path)) {
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
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            throw "Release input path component does not exist: $current"
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release input path contains a symlink or reparse point: $current"
        }
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
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
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer) { throw "$PathEnvironmentName must identify a regular executable file." }
    $actualHash = Get-Sha256 $path
    if ($actualHash -cne $expectedHash) {
        throw "$Description SHA-256 does not match $HashEnvironmentName."
    }
    return [PSCustomObject]@{ Path = $item.FullName; Hash = $expectedHash }
}

function Resolve-DiscoveredExecutable {
    param([Parameter(Mandatory = $true)][string]$Name)

    $path = (Resolve-Path (Require-Command $Name)).ProviderPath
    Assert-NoReparsePointComponents $path
    $item = Get-Item -LiteralPath $path -Force
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
    $item = Get-Item -LiteralPath $path -Force
    if (-not $item.PSIsContainer) { throw "$PathEnvironmentName must identify a real directory." }
    $actualHash = Get-DirectoryTreeSha256 $item.FullName
    if ($actualHash -cne $expectedHash) {
        throw "$Description SHA-256 does not match $HashEnvironmentName."
    }
    return [PSCustomObject]@{ Path = $item.FullName; Hash = $expectedHash }
}

function Get-DirectoryTreeSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-NoReparsePointComponents $Path
    $rootItem = Get-Item -LiteralPath $Path -Force
    if (-not $rootItem.PSIsContainer) { throw "Tree hash input is not a directory: $Path" }
    $root = $rootItem.FullName.TrimEnd('\', '/')
    $relativePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($item in Get-ChildItem -LiteralPath $root -Recurse -Force) {
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
    $utf8 = New-Object Text.UTF8Encoding($false)
    $nul = [byte[]]@(0)
    try {
        foreach ($relative in $ordered) {
            $filePath = Join-Path $root ($relative.Replace('/', '\'))
            $before = Get-Item -LiteralPath $filePath -Force
            if ($before.PSIsContainer -or
                (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw "Tree hash input changed type while hashing: $filePath"
            }
            $fileHash = Get-Sha256 $filePath
            $after = Get-Item -LiteralPath $filePath -Force
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
        return (($aggregate.Hash | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
        $aggregate.Dispose()
    }
}

function Get-OrderedHashAggregate {
    param([Parameter(Mandatory = $true)][string[]]$Hashes)

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
        return (($aggregate.Hash | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
        $aggregate.Dispose()
    }
}

function Get-ReleaseSourceState {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    $gitRoot = Invoke-SanitizedGit $GitPath @("-C", $RootDir, "rev-parse", "--show-toplevel") -CaptureOutput
    if ((Normalize-Path $gitRoot) -ne (Normalize-Path $RootDir)) {
        throw "Release source must be the root of its Git checkout."
    }
    $commit = Invoke-SanitizedGit $GitPath @("-C", $RootDir, "rev-parse", "--verify", "HEAD^{commit}") -CaptureOutput
    $tree = Invoke-SanitizedGit $GitPath @("-C", $RootDir, "rev-parse", "--verify", "HEAD^{tree}") -CaptureOutput
    if (-not (Test-LowerHex $commit 40) -or -not (Test-LowerHex $tree 40)) {
        throw "Release source commit and tree must be exact lowercase 40-hex Git object IDs."
    }
    $status = Invoke-SanitizedGit $GitPath @(
        "-C", $RootDir,
        "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"
    ) -CaptureOutput
    if ($status) {
        throw "Release source must have no tracked or untracked worktree changes."
    }
    $indexFlags = Invoke-SanitizedGit $GitPath @("-C", $RootDir, "ls-files", "-v") -CaptureOutput
    if (($indexFlags -split "`r?`n" | Where-Object { $_ -cmatch '^[a-zS] ' })) {
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

    if (-not (Test-Path -LiteralPath $Path)) {
        if (-not $Create) {
            throw "Required directory does not exist: $Path"
        }
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
    Assert-NoReparsePointComponents $Path
    $item = Get-Item -LiteralPath $Path -Force
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
    $resolvedDistRoot = (Resolve-Path $DistRoot).ProviderPath
    $parent = Split-Path -Parent $Path
    $leaf = Split-Path -Leaf $Path
    if ((Normalize-Path $parent) -ne (Normalize-Path $resolvedDistRoot) -or
        $leaf -cnotmatch $ExpectedLeafPattern) {
        throw "Refusing to mutate an unexpected distribution path: $Path"
    }
    if (Test-Path -LiteralPath $Path) {
        Assert-NoReparsePointComponents $Path
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer) { throw "Distribution path is not a directory: $Path" }
    }
}

function New-PublicationCandidate {
    Prepare-DistRoot
    $suffix = [Guid]::NewGuid().ToString("N")
    $script:PublicationCandidateDir = Join-Path $DistRoot ".$DistName.candidate-$suffix"
    $script:PublicationBackupDir = Join-Path $DistRoot ".$DistName.backup-$suffix"
    Assert-SafePublicationPath $PublicationCandidateDir ('^\.' + [regex]::Escape($DistName) + '\.candidate-[0-9a-f]{32}$')
    Assert-SafePublicationPath $PublicationBackupDir ('^\.' + [regex]::Escape($DistName) + '\.backup-[0-9a-f]{32}$')
    New-Item -ItemType Directory -Path $PublicationCandidateDir | Out-Null
    Assert-RealDirectory $PublicationCandidateDir
    return $PublicationCandidateDir
}

function Activate-PublicationCandidate {
    Assert-SafePublicationPath $DistDir ('^' + [regex]::Escape($DistName) + '$')
    Assert-SafePublicationPath $PublicationCandidateDir ('^\.' + [regex]::Escape($DistName) + '\.candidate-[0-9a-f]{32}$')
    Assert-SafePublicationPath $PublicationBackupDir ('^\.' + [regex]::Escape($DistName) + '\.backup-[0-9a-f]{32}$')
    if (-not (Test-Path -LiteralPath $PublicationCandidateDir -PathType Container)) {
        throw "Verified publication candidate is missing."
    }
    if (Test-Path -LiteralPath $PublicationBackupDir) {
        throw "Publication backup path unexpectedly already exists."
    }
    if (Test-Path -LiteralPath $DistDir) {
        $script:PublicationHadOriginal = $true
        Move-Item -LiteralPath $DistDir -Destination $PublicationBackupDir
    }
    try {
        Move-Item -LiteralPath $PublicationCandidateDir -Destination $DistDir
        $script:PublicationFinalActivated = $true
    }
    catch {
        if ($PublicationHadOriginal -and
            -not (Test-Path -LiteralPath $DistDir) -and
            (Test-Path -LiteralPath $PublicationBackupDir)) {
            Move-Item -LiteralPath $PublicationBackupDir -Destination $DistDir
            $script:PublicationHadOriginal = $false
        }
        throw
    }
}

function Restore-PublicationAfterFailure {
    if ($PublicationComplete) { return }
    if ($PublicationFinalActivated -and (Test-Path -LiteralPath $DistDir)) {
        Assert-SafePublicationPath $DistDir ('^' + [regex]::Escape($DistName) + '$')
        Remove-Item -LiteralPath $DistDir -Recurse -Force
        $script:PublicationFinalActivated = $false
    }
    if ($PublicationHadOriginal -and (Test-Path -LiteralPath $PublicationBackupDir)) {
        Assert-SafePublicationPath $PublicationBackupDir ('^\.' + [regex]::Escape($DistName) + '\.backup-[0-9a-f]{32}$')
        Move-Item -LiteralPath $PublicationBackupDir -Destination $DistDir
        $script:PublicationHadOriginal = $false
    }
    if ($PublicationCandidateDir -and (Test-Path -LiteralPath $PublicationCandidateDir)) {
        Assert-SafePublicationPath $PublicationCandidateDir ('^\.' + [regex]::Escape($DistName) + '\.candidate-[0-9a-f]{32}$')
        Remove-Item -LiteralPath $PublicationCandidateDir -Recurse -Force
    }
}

function Complete-Publication {
    if ($PublicationHadOriginal -and (Test-Path -LiteralPath $PublicationBackupDir)) {
        Assert-SafePublicationPath $PublicationBackupDir ('^\.' + [regex]::Escape($DistName) + '\.backup-[0-9a-f]{32}$')
        Remove-Item -LiteralPath $PublicationBackupDir -Recurse -Force
        $script:PublicationHadOriginal = $false
    }
    $script:PublicationComplete = $true
}

function Stop-DistProcesses {
    $normalizedDistDir = Normalize-Path $DistDir
    $processes = Get-CimInstance Win32_Process -Filter "Name = 'WindowsAppAutoLogin.exe' OR Name = 'windows-app-autologin.exe'" |
        Where-Object {
            if (-not $_.ExecutablePath) { return $false }
            $processPath = Normalize-Path $_.ExecutablePath
            return $processPath -eq (Normalize-Path (Join-Path $DistDir $ExeName)) -or
                $processPath.StartsWith("$normalizedDistDir\")
        }
    foreach ($process in $processes) {
        Write-Host "Stopping running dist process $($process.ProcessId): $($process.ExecutablePath)"
        Stop-Process -Id $process.ProcessId -Force
    }
}

function New-ReleaseRoot {
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $candidate = Join-Path $temporaryRoot ("waal-windows-release-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $candidate | Out-Null
    Assert-RealDirectory $candidate
    return $candidate
}

function Remove-ReleaseRootSafely {
    if (-not $ReleaseRoot -or -not (Test-Path -LiteralPath $ReleaseRoot)) { return }
    $temporaryRoot = Normalize-Path ([IO.Path]::GetTempPath())
    $parent = Normalize-Path (Split-Path -Parent $ReleaseRoot)
    $leaf = Split-Path -Leaf $ReleaseRoot
    $item = Get-Item -LiteralPath $ReleaseRoot -Force
    if ($parent -ne $temporaryRoot -or $leaf -notmatch '^waal-windows-release-[0-9a-f]{32}$') {
        Write-Warning "Refusing to clean unexpected temporary release path: $ReleaseRoot"
        return
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Write-Warning "Refusing to clean reparse-point temporary release path: $ReleaseRoot"
        return
    }
    Remove-Item -LiteralPath $ReleaseRoot -Recurse -Force
}

function Assert-CommitContainsOnlyRegularFiles {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    $entries = Invoke-Captured $GitPath @(
        "-C", $RootDir, "ls-tree", "-r", "--full-tree", $ReleaseGitCommit
    )
    if (-not $entries) {
        throw "Release source tree is empty."
    }
    foreach ($entry in ($entries -split "`r?`n")) {
        if ($entry -cnotmatch '^(100644|100755) blob [0-9a-f]{40}\t') {
            throw "Release source tree contains a link, gitlink, unsupported mode, or unsafe path encoding."
        }
    }
}

function Assert-MaterializedReleaseSource {
    Assert-RealDirectory $ReleaseSourceDir
    $normalizedRoot = Normalize-Path $ReleaseSourceDir
    $rootPrefix = "$normalizedRoot\"
    foreach ($item in Get-ChildItem -LiteralPath $ReleaseSourceDir -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release source snapshot contains a symlink or reparse point: $($item.FullName)"
        }
        $normalizedItem = Normalize-Path $item.FullName
        if ($normalizedItem -ne $normalizedRoot -and -not $normalizedItem.StartsWith($rootPrefix)) {
            throw "Release source snapshot entry resolves outside the snapshot root."
        }
    }
    foreach ($requiredFile in @("Cargo.toml", "Cargo.lock", "build.rs")) {
        $requiredPath = Join-Path $ReleaseSourceDir $requiredFile
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Release source snapshot is missing a regular tracked file: $requiredFile"
        }
        if (((Get-Item -LiteralPath $requiredPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release source snapshot required file is a reparse point: $requiredFile"
        }
    }
    foreach ($requiredDirectory in @("src", "assets")) {
        $requiredPath = Join-Path $ReleaseSourceDir $requiredDirectory
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Container)) {
            throw "Release source snapshot is missing a real tracked directory: $requiredDirectory"
        }
        if (((Get-Item -LiteralPath $requiredPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release source snapshot required directory is a reparse point: $requiredDirectory"
        }
    }
}

function Materialize-ReleaseSource {
    param(
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$TarPath
    )

    $script:ReleaseSourceDir = Join-Path $ReleaseRoot "source"
    $archivePath = Join-Path $ReleaseRoot "source.tar"
    Assert-CommitContainsOnlyRegularFiles $GitPath
    New-Item -ItemType Directory -Path $ReleaseSourceDir | Out-Null
    Invoke-Checked $GitPath @(
        "-C", $RootDir, "archive", "--format=tar", "--output=$archivePath", $ReleaseGitCommit
    )
    Invoke-Checked $TarPath @("-xf", $archivePath, "-C", $ReleaseSourceDir)
    Assert-MaterializedReleaseSource
}

function Resolve-RustTool {
    param([Parameter(Mandatory = $true)][string]$Name)

    $rustup = Get-Command rustup.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($rustup) {
        $resolved = Invoke-Captured $rustup.Path @("which", $Name)
        if ($resolved -and (Test-Path -LiteralPath $resolved)) {
            return (Resolve-Path $resolved).ProviderPath
        }
    }
    return (Resolve-Path (Require-Command "$Name.exe")).ProviderPath
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
        [AllowEmptyString()][string]$DevelopmentFallback = ""
    )

    $value = Get-EnvironmentValue $EnvironmentName
    if ([string]::IsNullOrEmpty($value)) {
        if (-not $Development) {
            throw "$EnvironmentName must explicitly list trusted MSVC directories for a publishable build."
        }
        $value = $DevelopmentFallback
    }
    if ([string]::IsNullOrEmpty($value)) { return "" }
    $canonicalDirectories = [System.Collections.Generic.List[string]]::new()
    foreach ($directory in ($value -split ';')) {
        if ([string]::IsNullOrWhiteSpace($directory) -or $directory -cne $directory.Trim()) {
            throw "$EnvironmentName contains an empty directory or surrounding whitespace."
        }
        Assert-NoReparsePointComponents $directory
        $item = Get-Item -LiteralPath $directory -Force
        if (-not $item.PSIsContainer) { throw "$EnvironmentName contains a non-directory path: $directory" }
        $null = $canonicalDirectories.Add($item.FullName)
    }
    return ($canonicalDirectories -join ';')
}

function Resolve-AndVerify-Toolchain {
    if ($Development) {
        $gitInput = Resolve-DiscoveredExecutable "git.exe"
        $tarInput = Resolve-DiscoveredExecutable "tar.exe"
        $cargoPath = Resolve-RustTool "cargo"
        $rustcPath = Resolve-RustTool "rustc"
        Assert-NoReparsePointComponents $cargoPath
        Assert-NoReparsePointComponents $rustcPath
        $cargoInput = [PSCustomObject]@{ Path = $cargoPath; Hash = (Get-Sha256 $cargoPath) }
        $rustcInput = [PSCustomObject]@{ Path = $rustcPath; Hash = (Get-Sha256 $rustcPath) }
        $linkInput = Resolve-DiscoveredExecutable "link.exe"
        $rcInput = Resolve-DiscoveredExecutable "rc.exe"
    }
    else {
        $gitInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_GIT_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_GIT_SHA256" "Git"
        $tarInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_TAR_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_TAR_SHA256" "tar"
        $cargoInput = Resolve-ExplicitPinnedExecutable "WAAL_RELEASE_CARGO_PATH" "WAAL_RELEASE_EXPECTED_CARGO_SHA256" "Cargo"
        $rustcInput = Resolve-ExplicitPinnedExecutable "WAAL_RELEASE_RUSTC_PATH" "WAAL_RELEASE_EXPECTED_RUSTC_SHA256" "rustc"
        $linkInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_LINK_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_LINK_SHA256" "link.exe"
        $rcInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_RC_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_RC_SHA256" "rc.exe"
        $signToolInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_SIGNTOOL_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_SIGNTOOL_SHA256" "signtool.exe"
    }

    $script:Git = $gitInput.Path
    $script:Tar = $tarInput.Path
    $script:Cargo = $cargoInput.Path
    $script:Rustc = $rustcInput.Path
    $script:Linker = $linkInput.Path
    $script:ResourceCompiler = $rcInput.Path
    $script:GitSha256 = $gitInput.Hash
    $script:TarSha256 = $tarInput.Hash
    $script:CargoSha256 = $cargoInput.Hash
    $script:RustcSha256 = $rustcInput.Hash
    $script:LinkerSha256 = $linkInput.Hash
    $script:ResourceCompilerSha256 = $rcInput.Hash
    if (-not $Development) {
        $script:SignTool = $signToolInput.Path
        $script:SignToolSha256 = $signToolInput.Hash
    }

    $script:CargoVersion = Get-RustToolVersion $Cargo
    $script:RustcVersion = Get-RustToolVersion $Rustc
    if ($CargoVersion -cne $RustcVersion) {
        throw "Release Cargo and rustc versions must match exactly."
    }
    if ((Normalize-Path (Split-Path -Parent $Cargo)) -ne (Normalize-Path (Split-Path -Parent $Rustc))) {
        throw "Release Cargo and rustc must come from the same pinned toolchain directory."
    }
    $reportedSysroot = Invoke-Captured $Rustc @("--print", "sysroot")
    if ($Development) {
        Assert-NoReparsePointComponents $reportedSysroot
        $script:RustSysroot = (Get-Item -LiteralPath $reportedSysroot -Force).FullName
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
    if (-not (Test-Path -LiteralPath (Join-Path $RustSysroot "lib\rustlib\$TargetTriple\lib") -PathType Container)) {
        throw "Pinned Rust sysroot does not contain the $TargetTriple standard library."
    }

    $nativeHashes = if ($Development) {
        @($LinkerSha256, $ResourceCompilerSha256)
    }
    else {
        @($LinkerSha256, $ResourceCompilerSha256, $SignToolSha256)
    }
    $script:NativeToolchainSha256 = Get-OrderedHashAggregate $nativeHashes
    if (-not $Development) {
        $expectedNativeHash = Get-RequiredExpectedSha256 "WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256"
        if ($NativeToolchainSha256 -cne $expectedNativeHash) {
            throw "WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256 does not match the ordered link.exe/rc.exe/signtool.exe aggregate."
        }
    }

    $script:TrustedLib = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_LIB" $AmbientLib
    $script:TrustedInclude = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_INCLUDE" $AmbientInclude
    $script:TrustedLibPath = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_LIBPATH" $AmbientLibPath
    Assert-ReleaseToolchainIntegrity
}

function Assert-ToolchainMatchesManifest {
    $manifest = Get-Content -LiteralPath (Join-Path $ReleaseSourceDir "Cargo.toml") -Raw
    $expectedMatch = [regex]::Match($manifest, '(?m)^rust-version\s*=\s*"([0-9]+\.[0-9]+)"\s*$')
    if (-not $expectedMatch.Success) { throw "Release Cargo.toml must pin rust-version." }
    $expected = $expectedMatch.Groups[1].Value
    if ($RustcVersion -cne $expected -and -not $RustcVersion.StartsWith("$expected.")) {
        throw "Release toolchain $RustcVersion does not match Cargo.toml rust-version $expected."
    }
}

function Assert-ReleaseToolchainIntegrity {
    foreach ($tool in @(
        [PSCustomObject]@{ Path = $Git; Hash = $GitSha256; Name = "Git" },
        [PSCustomObject]@{ Path = $Tar; Hash = $TarSha256; Name = "tar" },
        [PSCustomObject]@{ Path = $Cargo; Hash = $CargoSha256; Name = "Cargo" },
        [PSCustomObject]@{ Path = $Rustc; Hash = $RustcSha256; Name = "rustc" },
        [PSCustomObject]@{ Path = $Linker; Hash = $LinkerSha256; Name = "link.exe" },
        [PSCustomObject]@{ Path = $ResourceCompiler; Hash = $ResourceCompilerSha256; Name = "rc.exe" }
    )) {
        Assert-NoReparsePointComponents $tool.Path
        if ((Get-Sha256 $tool.Path) -cne $tool.Hash) {
            throw "$($tool.Name) changed after its release hash was pinned."
        }
    }
    if (-not $Development) {
        Assert-NoReparsePointComponents $SignTool
        if ((Get-Sha256 $SignTool) -cne $SignToolSha256) {
            throw "signtool.exe changed after its release hash was pinned."
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
        @($LinkerSha256, $ResourceCompilerSha256)
    }
    else {
        @($LinkerSha256, $ResourceCompilerSha256, $SignToolSha256)
    }
    if ((Get-OrderedHashAggregate $nativeHashes) -cne $NativeToolchainSha256) {
        throw "Native toolchain aggregate changed after it was pinned."
    }
}

function Assert-NoCargoConfigInAncestors {
    param([Parameter(Mandatory = $true)][string]$WorkingDirectory)

    $current = [IO.DirectoryInfo](Resolve-Path $WorkingDirectory).ProviderPath
    while ($current) {
        foreach ($name in @("config", "config.toml")) {
            $candidate = Join-Path (Join-Path $current.FullName ".cargo") $name
            if (Test-Path -LiteralPath $candidate) {
                throw "External Cargo configuration is not allowed in a distribution build: $candidate"
            }
        }
        $current = $current.Parent
    }
}

function Prepare-IsolatedBuildEnvironment {
    $script:BuildTargetDir = Join-Path $ReleaseRoot "target"
    $script:BuildHome = Join-Path $ReleaseRoot "build-home"
    $script:CargoHome = Join-Path $ReleaseRoot "cargo-home"
    $script:CargoWorkingDir = Join-Path $ReleaseRoot "cargo-work"
    $script:BuildTempDir = Join-Path $ReleaseRoot "tmp"
    foreach ($directory in @($BuildTargetDir, $BuildHome, $CargoHome, $CargoWorkingDir, $BuildTempDir)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
        Assert-RealDirectory $directory
    }
    Assert-NoCargoConfigInAncestors $CargoWorkingDir
    foreach ($candidate in @(
        (Join-Path $CargoHome "config"),
        (Join-Path $CargoHome "config.toml"),
        (Join-Path $ReleaseSourceDir ".cargo\config"),
        (Join-Path $ReleaseSourceDir ".cargo\config.toml")
    )) {
        if (Test-Path -LiteralPath $candidate) {
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
    Assert-ReleaseToolchainIntegrity
    $existingEnvironment = [Environment]::GetEnvironmentVariables("Process")
    $managedNames = @()
    foreach ($entry in $existingEnvironment.GetEnumerator()) {
        if ($entry.Key -match '^(CARGO_|RUST|WAAL_|CC$|CXX$|AR$|CFLAGS$|CXXFLAGS$|CPPFLAGS$|LDFLAGS$|DYLD_|LIB$|INCLUDE$|LIBPATH$|CL$|_CL_$|LINK$|_LINK_$)') {
            $managedNames += [string]$entry.Key
        }
    }
    $managedNames += @("HOME", "USERPROFILE", "TEMP", "TMP", "PATH", "RUSTC", "CARGO_HOME")
    $managedNames = @($managedNames | Sort-Object -Unique)
    $original = @{}
    foreach ($name in $managedNames) {
        if ($existingEnvironment.Contains($name)) { $original[$name] = [string]$existingEnvironment[$name] }
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }

    $separator = [char]0x1f
    $rustFlags = "--remap-path-prefix=$ReleaseSourceDir=." + $separator + "--remap-path-prefix=$RootDir=."
    $pathDirectories = @(
        (Split-Path -Parent $Cargo),
        (Split-Path -Parent $Linker),
        (Split-Path -Parent $ResourceCompiler),
        (Join-Path $env:SystemRoot "System32"),
        $env:SystemRoot
    ) | Select-Object -Unique
    $controlled = @{
        HOME = $BuildHome
        USERPROFILE = $BuildHome
        TEMP = $BuildTempDir
        TMP = $BuildTempDir
        PATH = ($pathDirectories -join ";")
        CARGO_HOME = $CargoHome
        CARGO_TARGET_DIR = $BuildTargetDir
        CARGO_ENCODED_RUSTFLAGS = $rustFlags
        CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $Linker
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
    if ($Development) {
        $controlled.WAAL_DEVELOPMENT_RELEASE = "1"
    }
    else {
        $controlled.WAAL_PUBLISHABLE_RELEASE = "1"
    }

    $captured = $null
    try {
        foreach ($entry in $controlled.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, "Process")
        }
        Push-Location $CargoWorkingDir
        try {
            if ($CaptureOutput) {
                $stderrPath = Join-Path $BuildTempDir ("cargo-stderr-" + [Guid]::NewGuid().ToString("N") + ".txt")
                $output = & $Cargo @Arguments 2> $stderrPath
                if ($LASTEXITCODE -ne 0) {
                    if (Test-Path -LiteralPath $stderrPath) {
                        Get-Content -LiteralPath $stderrPath | ForEach-Object { Write-Host $_ }
                    }
                    throw "Cargo command failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
                }
                $captured = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
            }
            else {
                Invoke-Checked $Cargo $Arguments
            }
        }
        finally {
            Pop-Location
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
    Assert-ReleaseToolchainIntegrity
    if ($CaptureOutput) { return $captured }
}

function Verify-ReleaseDependencyGraph {
    $metadataJson = Invoke-SanitizedCargo @(
        "metadata", "--locked", "--format-version", "1", "--filter-platform", $TargetTriple,
        "--manifest-path", (Join-Path $ReleaseSourceDir "Cargo.toml")
    ) -CaptureOutput
    $metadata = $metadataJson | ConvertFrom-Json
    $rootManifest = Normalize-Path (Join-Path $ReleaseSourceDir "Cargo.toml")
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
    $markers = @($ascii.Split([char]0) | Where-Object { $_.StartsWith("WAAL_BUILD_METADATA_V1;") })
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
    Require-MetadataField $metadata "windows-authenticode-cert-sha256" $WindowsSignerCertSha256
}

function Resolve-SigningCertificate {
    $normalizedThumbprint = $SigningCertificateThumbprint.Replace(" ", "").ToUpperInvariant()
    if ($normalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
        throw "WAAL_WINDOWS_SIGN_CERT_THUMBPRINT must be an exact 40-hex certificate thumbprint for a code-signing certificate."
    }
    $certificates = @(
        Get-ChildItem -LiteralPath "Cert:\CurrentUser\My\$normalizedThumbprint" -ErrorAction SilentlyContinue
        Get-ChildItem -LiteralPath "Cert:\LocalMachine\My\$normalizedThumbprint" -ErrorAction SilentlyContinue
    )
    $certificate = $certificates | Select-Object -First 1
    if (-not $certificate) { throw "The requested Authenticode signing certificate is not installed." }
    if (-not $certificate.HasPrivateKey) { throw "The requested Authenticode certificate has no accessible private key." }
    if ($certificate.NotAfter -le [DateTime]::UtcNow) { throw "The requested Authenticode certificate is expired." }
    if (-not ($certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId.Value -eq "1.3.6.1.5.5.7.3.3" })) {
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
    return (($digest | ForEach-Object { $_.ToString("x2") }) -join "")
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

    $signature = Get-AuthenticodeSignature -LiteralPath $ExecutablePath
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
    [IO.File]::WriteAllText($Path, $Content, (New-Object Text.UTF8Encoding($false)))
}

function Assert-WindowsDistribution {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$ExpectedExeSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedProvenance
    )

    Assert-RealDirectory $Directory
    $expectedNames = @(
        $ExeName, "README.md", "LICENSE", "config.example.json",
        "SHA256SUMS.txt", "BUILD-PROVENANCE.txt"
    )
    $actualNames = @()
    foreach ($item in Get-ChildItem -LiteralPath $Directory -Force) {
        if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Distribution contains a directory, link, or reparse point: $($item.Name)"
        }
        $actualNames += $item.Name
    }
    $expectedSorted = @($expectedNames | Sort-Object -CaseSensitive)
    $actualSorted = @($actualNames | Sort-Object -CaseSensitive)
    if (($expectedSorted -join "`n") -cne ($actualSorted -join "`n")) {
        throw "Distribution file set does not match the expected package contents."
    }

    $executable = Join-Path $Directory $ExeName
    Verify-ExecutableMetadata $executable
    if ((Get-Sha256 $executable) -cne $ExpectedExeSha256) {
        throw "Distribution executable hash changed during publication."
    }
    $expectedManifest = "$ExpectedExeSha256  $ExeName`r`n"
    if ([IO.File]::ReadAllText((Join-Path $Directory "SHA256SUMS.txt")) -cne $expectedManifest) {
        throw "Distribution SHA256SUMS.txt does not match the executable."
    }
    if ([IO.File]::ReadAllText((Join-Path $Directory "BUILD-PROVENANCE.txt")) -cne $ExpectedProvenance) {
        throw "Distribution BUILD-PROVENANCE.txt does not match the pinned build inputs."
    }
    if (-not $Development) {
        Assert-AuthenticodeExecutable $executable $SigningCertificate
    }
}

$ReleaseRoot = New-ReleaseRoot

try {
    Resolve-AndVerify-Toolchain
    $sourceState = Get-ReleaseSourceState $Git
    $ReleaseGitCommit = $sourceState.Commit
    $ReleaseGitTree = $sourceState.Tree
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

    $manifestPath = Join-Path $ReleaseSourceDir "Cargo.toml"
    if (-not $SkipTests) {
        Write-Host "Running tests from the verified source snapshot..."
        Invoke-SanitizedCargo @(
            "test", "--locked", "--target", $TargetTriple, "--all-targets", "--all-features",
            "--manifest-path", $manifestPath
        )
    }

    Write-Host "Building release executable from the verified source snapshot..."
    Invoke-SanitizedCargo @(
        "build", "--locked", "--release", "--target", $TargetTriple,
        "--bin", $BinaryName, "--manifest-path", $manifestPath
    )
    $targetExe = Join-Path $BuildTargetDir "$TargetTriple\release\$BinaryName.exe"
    if (-not (Test-Path -LiteralPath $targetExe -PathType Leaf)) {
        throw "Release build did not produce expected executable: $targetExe"
    }
    Verify-ExecutableMetadata $targetExe
    Assert-ReleaseSourceUnchanged $Git

    $stagedDist = Join-Path $ReleaseRoot $DistName
    New-Item -ItemType Directory -Path $stagedDist | Out-Null
    Assert-RealDirectory $stagedDist
    $stagedExe = Join-Path $stagedDist $ExeName
    Copy-Item -LiteralPath $targetExe -Destination $stagedExe
    foreach ($fileName in @("README.md", "LICENSE", "config.example.json")) {
        Copy-Item -LiteralPath (Join-Path $ReleaseSourceDir $fileName) -Destination $stagedDist
    }

    $signerDescription = "none-development-only"
    if ($Development) {
        Write-Warning "Creating an unsigned DEVELOPMENT distribution. It is not a publishable release."
    }
    else {
        Sign-AndVerify-Executable $stagedExe $SigningCertificate
        $signerDescription = $SigningCertificate.Thumbprint
    }
    Verify-ExecutableMetadata $stagedExe

    $exeSha256 = (Get-FileHash -LiteralPath $stagedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Utf8NoBom (Join-Path $stagedDist "SHA256SUMS.txt") "$exeSha256  $ExeName`r`n"
    $artifactKind = if ($Development) { "development-unsigned" } else { "release-authenticode" }
    $provenance = @(
        "WAAL_WINDOWS_BUILD_PROVENANCE_V1",
        "artifact-kind=$artifactKind",
        "target=$TargetTriple",
        "source-git-commit=$ReleaseGitCommit",
        "source-git-tree=$ReleaseGitTree",
        "git-sha256=$GitSha256",
        "tar-sha256=$TarSha256",
        "cargo-version=$CargoVersion",
        "cargo-sha256=$CargoSha256",
        "rustc-version=$RustcVersion",
        "rustc-sha256=$RustcSha256",
        "rust-sysroot-sha256=$RustSysrootSha256",
        "link-sha256=$LinkerSha256",
        "rc-sha256=$ResourceCompilerSha256",
        "signtool-sha256=$SignToolSha256",
        "native-toolchain-sha256=$NativeToolchainSha256",
        "authenticode-publisher=$WindowsPublisher",
        "authenticode-certificate-sha256=$WindowsSignerCertSha256",
        "authenticode-signer-thumbprint=$signerDescription",
        "executable-sha256=$exeSha256"
    ) -join "`r`n"
    $expectedProvenance = $provenance + "`r`n"
    Write-Utf8NoBom (Join-Path $stagedDist "BUILD-PROVENANCE.txt") $expectedProvenance

    Assert-ReleaseSourceUnchanged $Git
    Assert-WindowsDistribution $stagedDist $exeSha256 $expectedProvenance
    Assert-ReleaseToolchainIntegrity
    if ($StopRunning) { Stop-DistProcesses }
    $candidateDir = New-PublicationCandidate
    foreach ($fileName in @(
        $ExeName, "README.md", "LICENSE", "config.example.json", "SHA256SUMS.txt", "BUILD-PROVENANCE.txt"
    )) {
        Copy-Item -LiteralPath (Join-Path $stagedDist $fileName) -Destination $candidateDir
    }
    Assert-WindowsDistribution $candidateDir $exeSha256 $expectedProvenance
    Assert-ReleaseSourceUnchanged $Git
    Assert-ReleaseToolchainIntegrity
    Activate-PublicationCandidate
    $finalExe = Join-Path $DistDir $ExeName
    Assert-WindowsDistribution $DistDir $exeSha256 $expectedProvenance
    Assert-ReleaseSourceUnchanged $Git
    Assert-ReleaseToolchainIntegrity
    $finalHash = Get-Sha256 $finalExe
    Complete-Publication

    Write-Host "Windows distribution complete:"
    Write-Host "  $DistDir"
    Write-Host "  $finalExe"
    Write-Host "  SHA-256: $finalHash"
    if ($Development) { Write-Warning "This output is unsigned and development-only." }
}
catch {
    Restore-PublicationAfterFailure
    throw
}
finally {
    if (-not $PublicationComplete) {
        Restore-PublicationAfterFailure
    }
    Remove-ReleaseRootSafely
}
