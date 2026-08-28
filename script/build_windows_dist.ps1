#Requires -Version 5.1

param(
    [switch]$SkipTests,
    [switch]$StopRunning,
    [switch]$ReuseBuild,
    [switch]$Development,
    [string]$SigningCertificateThumbprint = "",
    [string]$TimestampUrl = "",
    [string]$InternalCleanShellNonce = "",
    [string]$InternalOuterPackagerSha256 = "",
    [string]$InternalRepositoryRoot = ""
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Local path-based Cargo and signtool transitions cannot attribute bytes to a
# producer or signer against another process running in the same Windows
# security context. Reject publishable mode and all signing inputs before even
# validating or spawning the clean PowerShell child. Publishable Windows
# releases require a separately isolated builder with an authenticated output
# channel; this local script intentionally produces only unsigned VM-test
# artifacts.
if (-not $Development) {
    throw "Publishable Windows packaging is disabled in the local packager. Use an isolated authenticated builder; pass -Development only for an explicitly unsigned local VM artifact."
}
if ($SigningCertificateThumbprint -or $TimestampUrl -or
    $env:WAAL_WINDOWS_SIGN_CERT_THUMBPRINT -or
    $env:WAAL_WINDOWS_TIMESTAMP_URL) {
    throw "The development-only Windows packager rejects certificate and timestamp inputs."
}

# Capture the source text already parsed into this process. Reading
# $PSCommandPath later would only observe the then-current worktree file and
# could therefore bind an A-loaded packager to a concurrently checked-out B
# commit. ScriptBlockAst.Extent is the code this process is actually running.
$executingPackagerSource = $MyInvocation.MyCommand.ScriptBlock.Ast.Extent.Text
if ([string]::IsNullOrEmpty($executingPackagerSource)) {
    throw "Unable to capture the executing Windows packager source."
}

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

$cleanShellArgumentPayloadName = "WAAL_INTERNAL_CLEAN_SHELL_ARGUMENTS"
$cleanShellBootstrapSource = @'
Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
try {
    $payload = [Environment]::GetEnvironmentVariable(
        "WAAL_INTERNAL_CLEAN_SHELL_ARGUMENTS",
        "Process"
    )
    if ([string]::IsNullOrEmpty($payload) -or $payload.Length -gt 16384 -or
        $payload -cnotmatch '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$') {
        throw "The clean-shell argument payload is missing or malformed."
    }
    $payloadBytes = [Convert]::FromBase64String($payload)
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $argumentText = $utf8.GetString($payloadBytes)
    $arguments = @($argumentText.Split(
        [char[]]@([char]0),
        [StringSplitOptions]::None
    ))
    if ($arguments.Count -lt 6 -or $arguments.Count -gt 14) {
        throw "The clean-shell argument vector has an invalid length."
    }
    foreach ($argument in $arguments) {
        if ([string]::IsNullOrEmpty($argument) -or $argument.IndexOf([char]0) -ge 0) {
            throw "The clean-shell argument vector contains an invalid value."
        }
    }

    $parameters = @{}
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($argumentIndex = 0; $argumentIndex -lt $arguments.Count; $argumentIndex++) {
        $argumentName = $arguments[$argumentIndex]
        $parameterName = $null
        $takesValue = $false
        switch -CaseSensitive ($argumentName) {
            "-SkipTests" { $parameterName = "SkipTests"; break }
            "-StopRunning" { $parameterName = "StopRunning"; break }
            "-ReuseBuild" { $parameterName = "ReuseBuild"; break }
            "-Development" { $parameterName = "Development"; break }
            "-SigningCertificateThumbprint" {
                $parameterName = "SigningCertificateThumbprint"
                $takesValue = $true
                break
            }
            "-TimestampUrl" {
                $parameterName = "TimestampUrl"
                $takesValue = $true
                break
            }
            "-InternalCleanShellNonce" {
                $parameterName = "InternalCleanShellNonce"
                $takesValue = $true
                break
            }
            "-InternalOuterPackagerSha256" {
                $parameterName = "InternalOuterPackagerSha256"
                $takesValue = $true
                break
            }
            "-InternalRepositoryRoot" {
                $parameterName = "InternalRepositoryRoot"
                $takesValue = $true
                break
            }
            default { throw "The clean-shell argument vector contains an unknown parameter." }
        }
        if (-not $seen.Add($argumentName)) {
            throw "The clean-shell argument vector contains a duplicate parameter."
        }
        if ($takesValue) {
            $argumentIndex++
            if ($argumentIndex -ge $arguments.Count -or
                [string]::IsNullOrEmpty($arguments[$argumentIndex])) {
                throw "The clean-shell argument vector is missing a parameter value."
            }
            $parameters[$parameterName] = $arguments[$argumentIndex]
        }
        else {
            $parameters[$parameterName] = $true
        }
    }
    foreach ($required in @(
        "-InternalCleanShellNonce",
        "-InternalOuterPackagerSha256",
        "-InternalRepositoryRoot"
    )) {
        if (-not $seen.Contains($required)) {
            throw "The clean-shell argument vector is missing an internal parameter."
        }
    }

    # -File - executes prompt statements one at a time and cannot bind the
    # trailing script parameters on Windows PowerShell 5.1. Read the exact
    # redirected stream ourselves, parse it once as one root ScriptBlock, and
    # invoke it only through the validated hashtable above.
    $source = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrEmpty($source) -or $source.Length -gt 4194304 -or
        $source.IndexOf([char]0) -ge 0) {
        throw "The clean-shell packager source is missing or malformed."
    }
    for ($sourceIndex = 0; $sourceIndex -lt $source.Length; $sourceIndex++) {
        if ([int]$source[$sourceIndex] -gt 0x7f) {
            throw "The clean-shell packager source is not ASCII."
        }
    }
    $scriptBlock = [System.Management.Automation.ScriptBlock]::Create($source)
    & $scriptBlock @parameters
    if (-not $?) { exit 1 }
    exit 0
}
catch {
    [Console]::Error.WriteLine(
        "Windows clean-shell bootstrap failed: " + $_.Exception.Message
    )
    exit 1
}
'@

function New-CleanShellScriptArguments {
    param(
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$OuterPackagerSha256,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )

    $arguments = @()
    if ($SkipTests) { $arguments += "-SkipTests" }
    if ($StopRunning) { $arguments += "-StopRunning" }
    if ($ReuseBuild) { $arguments += "-ReuseBuild" }
    if ($Development) { $arguments += "-Development" }
    if ($SigningCertificateThumbprint) {
        $arguments += @("-SigningCertificateThumbprint", $SigningCertificateThumbprint)
    }
    if ($TimestampUrl) { $arguments += @("-TimestampUrl", $TimestampUrl) }
    $arguments += @(
        "-InternalCleanShellNonce", $Nonce,
        "-InternalOuterPackagerSha256", $OuterPackagerSha256,
        "-InternalRepositoryRoot", $RepositoryRoot
    )
    return $arguments
}

function ConvertTo-CleanShellArgumentPayload {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    if ($Arguments.Count -lt 1 -or $Arguments.Count -gt 32) {
        throw "The clean-shell argument vector has an invalid length."
    }
    foreach ($argument in $Arguments) {
        if ([string]::IsNullOrEmpty($argument) -or
            $argument.Length -gt 8192 -or $argument.IndexOf([char]0) -ge 0) {
            throw "The clean-shell argument vector contains an unsafe value."
        }
    }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $payload = [Convert]::ToBase64String(
        $utf8.GetBytes(($Arguments -join [char]0))
    )
    if ($payload.Length -gt 16384) {
        throw "The clean-shell argument payload exceeds its fixed limit."
    }
    return $payload
}

function New-CleanShellEngineArguments {
    $encodedBootstrap = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($cleanShellBootstrapSource)
    )
    return @(
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        $encodedBootstrap
    )
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

function Get-PackagerSourceSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Source)

    if ([string]::IsNullOrEmpty($Source) -or $Source.IndexOf([char]0) -ge 0) {
        throw "Windows packager source must be non-empty and contain no NUL bytes."
    }
    for ($index = 0; $index -lt $Source.Length; $index++) {
        if ([int]$Source[$index] -gt 0x7f) {
            throw "Windows packager must remain ASCII so Windows PowerShell 5.1 decoding is unambiguous."
        }
    }

    # Git stores this repository's scripts with LF, while a normal Windows
    # checkout may materialize CRLF. Line endings do not change PowerShell
    # logic, so normalize only that representation difference; every other
    # character inside the parsed script extent remains hash-bound.
    $canonicalSource = $Source.Replace("`r`n", "`n").Replace("`r", "`n")
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($canonicalSource))
        return (($digest | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
        $sha256.Dispose()
    }
}

function Assert-PackagerSourceHashingSelfTest {
    $lf = "alpha`nbeta`n"
    $crlf = "alpha`r`nbeta`r`n"
    $baseline = Get-PackagerSourceSha256 $lf
    if ($baseline -cne "e49c81e2d2f84e259d40e2fb8192f3bcd198b355184845d76d8f58807d0d78ee") {
        throw "Windows packager source hashing does not match its fixed ASCII SHA-256 test vector."
    }
    if ($baseline -cne (Get-PackagerSourceSha256 $crlf)) {
        throw "Windows packager source hashing does not normalize checkout line endings."
    }
    if ($baseline -ceq (Get-PackagerSourceSha256 "alpha`ngamma`n")) {
        throw "Windows packager source hashing does not distinguish changed logic."
    }
    if ($baseline -cnotmatch '^[0-9a-f]{64}$') {
        throw "Windows packager source hashing did not produce a lowercase SHA-256 digest."
    }
}

# This digest describes the exact root AST that was already parsed into this
# process. Compute it before any re-entry decision so the clean child can prove
# that it loaded the same A, instead of silently accepting a pathname that
# changed to B between CreateProcess and parsing.
Assert-PackagerSourceHashingSelfTest
$loadedPackagerSourceSha256 = Get-PackagerSourceSha256 $executingPackagerSource

$bootstrapRepositoryRoot = $InternalRepositoryRoot
if (-not $bootstrapRepositoryRoot) {
    if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        throw "The outer Windows packager could not determine its repository root."
    }
    $bootstrapRepositoryRoot = [IO.Path]::GetFullPath(
        (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot "..")
    ).TrimEnd('\', '/')
}
Assert-PhysicalBootstrapPath -Path $bootstrapRepositoryRoot -ExpectDirectory $true

$cleanShellMarkerName = "WAAL_INTERNAL_CLEAN_SHELL_NONCE"
$cleanShellMarker = [Environment]::GetEnvironmentVariable($cleanShellMarkerName, "Process")
$cleanShellArgumentPayload = [Environment]::GetEnvironmentVariable(
    $cleanShellArgumentPayloadName,
    "Process"
)
$currentProcessArguments = [Environment]::GetCommandLineArgs()
$currentInvocationArguments = @()
if ($currentProcessArguments.Count -gt 1) {
    $currentInvocationArguments = @($currentProcessArguments[1..($currentProcessArguments.Count - 1)])
}
$expectedInvocationArguments = @(New-CleanShellEngineArguments)
$expectedScriptArguments = @()
$expectedCleanShellArgumentPayload = ""
if ($InternalCleanShellNonce) {
    $expectedScriptArguments = @(New-CleanShellScriptArguments `
        -Nonce $InternalCleanShellNonce `
        -OuterPackagerSha256 $InternalOuterPackagerSha256 `
        -RepositoryRoot $InternalRepositoryRoot)
    $expectedCleanShellArgumentPayload = ConvertTo-CleanShellArgumentPayload `
        $expectedScriptArguments
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
    $cleanShellArgumentPayload -ceq $expectedCleanShellArgumentPayload -and
    $modulePathIsTrusted -and
    (Test-OrdinalArgumentVector -Actual $currentInvocationArguments -Expected $expectedInvocationArguments)
)

if (-not $cleanShellVerified) {
    if ($InternalCleanShellNonce -or $InternalOuterPackagerSha256 -or
        $InternalRepositoryRoot -or $cleanShellMarker -or
        $cleanShellArgumentPayload) {
        throw "Reserved clean-shell bootstrap parameters were supplied outside the exact parent invocation."
    }
    $nonce = [Guid]::NewGuid().ToString("N")
    $childScriptArguments = @(New-CleanShellScriptArguments `
        -Nonce $nonce `
        -OuterPackagerSha256 $loadedPackagerSourceSha256 `
        -RepositoryRoot $bootstrapRepositoryRoot)
    $childArgumentPayload = ConvertTo-CleanShellArgumentPayload $childScriptArguments
    $childEngineArguments = @(New-CleanShellEngineArguments)
    foreach ($argument in $childEngineArguments) {
        if ([string]::IsNullOrEmpty($argument) -or
            $argument -cnotmatch '^[A-Za-z0-9+/_=-]+$') {
            throw "The clean-shell engine argument vector cannot be encoded unambiguously."
        }
    }

    # ProcessStartInfo keeps the physical executable separate from its fixed,
    # whitespace-free engine arguments. Only stdin is redirected: stdout and
    # stderr remain attached to the caller for normal release diagnostics.
    $startInfo = Microsoft.PowerShell.Utility\New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $enginePath
    $startInfo.Arguments = $childEngineArguments -join " "
    if ($startInfo.Arguments.Length -gt 30000) {
        throw "The deterministic clean-shell bootstrap exceeds the Windows command-line limit."
    }
    $startInfo.WorkingDirectory = $bootstrapRepositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.EnvironmentVariables["PSModulePath"] = $trustedModulePath
    $startInfo.EnvironmentVariables[$cleanShellMarkerName] = $nonce
    $startInfo.EnvironmentVariables[$cleanShellArgumentPayloadName] = $childArgumentPayload

    $childProcess = Microsoft.PowerShell.Utility\New-Object Diagnostics.Process
    $childProcess.StartInfo = $startInfo
    $childStarted = $false
    $childInputClosed = $false
    $childInputStream = $null
    $childExitCode = $null
    $sourceBytes = [Text.Encoding]::ASCII.GetBytes($executingPackagerSource)
    try {
        if (-not $childProcess.Start()) {
            throw "Unable to start the clean PowerShell release subprocess."
        }
        $childStarted = $true
        # .NET Framework 4.x (and therefore Windows PowerShell 5.1) has no
        # ProcessStartInfo.StandardInputEncoding property. Write the validated
        # ASCII bytes directly to the redirected pipe's BaseStream: this adds
        # neither an encoding preamble nor a trailing newline.
        $childInputStream = $childProcess.StandardInput.BaseStream
        $childInputStream.Write($sourceBytes, 0, $sourceBytes.Length)
        $childInputStream.Flush()
        $childInputStream.Close()
        $childInputClosed = $true
        $sourceBytes = $null
        $childProcess.WaitForExit()
        $childExitCode = $childProcess.ExitCode
    }
    finally {
        $sourceBytes = $null
        if ($childStarted -and -not $childInputClosed) {
            try {
                if ($childInputStream) { $childInputStream.Close() }
                else { $childProcess.StandardInput.BaseStream.Close() }
            }
            catch { Microsoft.PowerShell.Utility\Write-Warning $_.Exception.Message }
        }
        if ($childStarted) {
            try {
                if (-not $childProcess.HasExited) { $childProcess.WaitForExit() }
            }
            catch { Microsoft.PowerShell.Utility\Write-Warning $_.Exception.Message }
        }
        $childProcess.Dispose()
    }
    if ($childExitCode -ne 0) {
        throw "The clean PowerShell release subprocess failed with exit code $childExitCode."
    }
    $executingPackagerSource = $null
    return
}

# Do not leak the one-shot bootstrap capability into release tools or their
# subprocesses after the exact clean invocation has been established.
[Environment]::SetEnvironmentVariable($cleanShellMarkerName, $null, "Process")
[Environment]::SetEnvironmentVariable($cleanShellArgumentPayloadName, $null, "Process")
if ($InternalOuterPackagerSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $loadedPackagerSourceSha256 -cne $InternalOuterPackagerSha256) {
    throw "The clean PowerShell child did not parse the exact packager source loaded by its parent."
}
$InternalCleanShellNonce = ""
$InternalOuterPackagerSha256 = ""
$verifiedRepositoryRoot = $InternalRepositoryRoot
$InternalRepositoryRoot = ""
$ExecutingPackagerSourceSha256 = $loadedPackagerSourceSha256
$loadedPackagerSourceSha256 = $null
$executingPackagerSource = $null

$RootDir = $verifiedRepositoryRoot
$BinaryName = "windows-app-autologin"
$ExeName = "WindowsAppAutoLogin.exe"
$UiBinaryName = "windows-app-autologin-ui"
$UiExeName = "WindowsAppAutoLoginUI.exe"
$TargetTriple = "x86_64-pc-windows-msvc"
$ProductionDistName = "WindowsAppAutoLogin-windows-x86_64"
$DevelopmentDistName = "WindowsAppAutoLogin-windows-x86_64-development"
$DistName = $DevelopmentDistName
$DistRoot = Microsoft.PowerShell.Management\Join-Path $RootDir "dist"
$DistDir = $null
$ReleaseRoot = $null
$ReleaseRootHandle = $null
$ReleaseRootParentHandle = $null
$ReleaseSourceDir = $null
$ReleaseSourceHandle = $null
$BuildTargetDir = $null
$BuildHome = $null
$GitHome = $null
$GitHomeMustRemainAbsent = $false
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
$PackagerSourceSha256 = $ExecutingPackagerSourceSha256
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
$PublicationParentHandle = $null
$PublicationCandidateHandle = $null
$PublicationFinalHandle = $null
$PublicationPayloadHandles = @()
$PublicationFinalActivated = $false
$PublicationComplete = $false
$GitRuntimeLockState = $null
$TarLockState = $null
$ToolchainDirectoryLocks = @{}
$UnsignedExecutableBytes = $null
$UnsignedUiExecutableBytes = $null
$BuiltExecutableHandle = $null
$BuiltUiExecutableHandle = $null
$BuiltExecutableDirectoryHandle = $null
$StagedExecutableHandle = $null
$StagedExecutableSha256 = $null
$StagedUiExecutableHandle = $null
$StagedUiExecutableSha256 = $null
$StagedPayloadHandles = @()
$CommittedPayloadHashes = $null
$CodeDomCompiler = $null
$CodeDomCompilerSha256 = $null
$CodeDomRuntime = $null
$CodeDomRuntimeSha256 = $null
$CodeDomRuntimeLockState = $null
$AmbientLib = [Environment]::GetEnvironmentVariable("LIB", "Process")
$AmbientInclude = [Environment]::GetEnvironmentVariable("INCLUDE", "Process")
$AmbientLibPath = [Environment]::GetEnvironmentVariable("LIBPATH", "Process")
$AmbientSystemRoot = [Environment]::GetEnvironmentVariable("SYSTEMROOT", "Process")
$AmbientWinDir = [Environment]::GetEnvironmentVariable("WINDIR", "Process")

if ($ReuseBuild) {
    throw "-ReuseBuild is incompatible with fresh-snapshot development builds. Every local test artifact is rebuilt from a fresh captured Git snapshot."
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
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$RawBytes
    )

    if (-not $Git -or -not $GitHome) {
        throw "Pinned Git and its isolated home must be initialized before provenance inspection."
    }
    if (-not $WindowsDirectory -or -not $WindowsSystemDirectory -or -not $GitRoot) {
        throw "Trusted Windows and Git-runtime directories must be resolved before invoking Git."
    }
    if ($GitHomeMustRemainAbsent) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $GitHome) {
            throw "The pre-attestation Git home sentinel was created or replaced."
        }
    }
    else {
        Assert-RealDirectory $GitHome
    }

    $existingEnvironment = [Environment]::GetEnvironmentVariables("Process")
    $managedNames = @()
    # Git has configuration, protocol, pager, transport, shell, proxy, and
    # credential-helper environment inputs outside the GIT_* namespace. Clear
    # the complete inherited command surface before the first pre-attestation
    # Git invocation; an isolated HOME alone is not a sufficient boundary.
    $gitEnvironmentPattern = '^(?:GIT_|HOME$|USERPROFILE$|XDG_CONFIG_HOME$|PATH$|PATHEXT$|COMSPEC$|SYSTEMROOT$|WINDIR$|LC_ALL$|LC_[A-Z_]+$|LANG$|LANGUAGE$|SSH_|SVN_|CVS_|RSH$|PLINK_PROTOCOL$|PAGER$|LESS$|LV$|TERM$|COLORTERM$|EDITOR$|VISUAL$|EMAIL$|GNUPGHOME$|GPG_|HTTP_PROXY$|HTTPS_PROXY$|FTP_PROXY$|ALL_PROXY$|NO_PROXY$|BASH_ENV$|ENV$|CDPATH$|MSYSTEM$|CHERE_INVOKING$|CYGWIN$)'
    $explicitForbiddenGitNames = @(
        "GIT_ALLOW_PROTOCOL",
        "GIT_CONFIG_PARAMETERS",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "BASH_ENV"
    )
    foreach ($entry in $existingEnvironment.GetEnumerator()) {
        if ([string]$entry.Key -match $gitEnvironmentPattern) {
            $managedNames += [string]$entry.Key
        }
    }
    $managedNames = @($managedNames | Microsoft.PowerShell.Utility\Sort-Object -Unique)
    $managedNames = @(
        @($managedNames + $explicitForbiddenGitNames) |
            Microsoft.PowerShell.Utility\Sort-Object -Unique
    )
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
        PATH = "$(Microsoft.PowerShell.Management\Join-Path $GitRoot 'mingw64\bin');$WindowsSystemDirectory;$WindowsDirectory"
        PATHEXT = ".COM;.EXE;.BAT;.CMD"
        COMSPEC = (Microsoft.PowerShell.Management\Join-Path $WindowsSystemDirectory "cmd.exe")
        SYSTEMROOT = $WindowsDirectory
        WINDIR = $WindowsDirectory
        GIT_CONFIG_NOSYSTEM = "1"
        GIT_CONFIG_SYSTEM = "NUL"
        GIT_CONFIG_GLOBAL = "NUL"
        GIT_CONFIG_COUNT = "0"
        GIT_TERMINAL_PROMPT = "0"
        GIT_PROTOCOL_FROM_USER = "0"
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
        foreach ($entry in [Environment]::GetEnvironmentVariables("Process").GetEnumerator()) {
            if ([string]$entry.Key -match $gitEnvironmentPattern -and
                -not $controlled.ContainsKey([string]$entry.Key)) {
                throw "A forbidden inherited Git process variable survived sanitization: $($entry.Key)"
            }
        }
        foreach ($name in $explicitForbiddenGitNames) {
            if ($null -ne [Environment]::GetEnvironmentVariable($name, "Process")) {
                throw "A forbidden explicit Git process variable survived sanitization: $name"
            }
        }
        if ($RawBytes) {
            foreach ($argument in $safeArguments) {
                if ($argument -cnotmatch '^[A-Za-z0-9._/:=+{}^-]+$') {
                    throw "Raw Git byte capture received an argument requiring ambiguous command-line quoting."
                }
            }
            $startInfo = Microsoft.PowerShell.Utility\New-Object Diagnostics.ProcessStartInfo
            $startInfo.FileName = $Git
            $startInfo.Arguments = $safeArguments -join " "
            # Raw byte capture cannot use PowerShell 5.1 redirection, and its
            # deliberately restricted argument encoder does not quote an
            # arbitrary repository path. Bind repository discovery through
            # ProcessStartInfo instead of inheriting the caller's working
            # directory.
            $startInfo.WorkingDirectory = $RootDir
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $process = Microsoft.PowerShell.Utility\New-Object Diagnostics.Process
            $process.StartInfo = $startInfo
            $memory = Microsoft.PowerShell.Utility\New-Object IO.MemoryStream
            try {
                if (-not $process.Start()) {
                    throw "Unable to start pinned Git for exact blob capture."
                }
                $stderrTask = $process.StandardError.ReadToEndAsync()
                $process.StandardOutput.BaseStream.CopyTo($memory)
                $process.WaitForExit()
                $stderr = $stderrTask.Result
                if ($process.ExitCode -ne 0) {
                    throw "Pinned Git blob capture failed with exit code $($process.ExitCode): $stderr"
                }
                if ($GitHomeMustRemainAbsent -and
                    (Microsoft.PowerShell.Management\Test-Path -LiteralPath $GitHome)) {
                    throw "Pinned Git created the pre-attestation home sentinel."
                }
                return ,$memory.ToArray()
            }
            finally {
                $memory.Dispose()
                $process.Dispose()
            }
        }
        $captured = Invoke-Captured $Git $safeArguments
        if ($GitHomeMustRemainAbsent -and
            (Microsoft.PowerShell.Management\Test-Path -LiteralPath $GitHome)) {
            throw "Pinned Git created the pre-attestation home sentinel."
        }
        return $captured
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

function Invoke-SanitizedTar {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    if (-not $Tar -or -not $WindowsDirectory -or -not $WindowsSystemDirectory) {
        throw "Pinned tar and trusted Windows directories must be initialized before extraction."
    }
    Assert-ReleaseSourceToolIntegrity
    $existingEnvironment = [Environment]::GetEnvironmentVariables("Process")
    $managedPattern = '^(?:TAR_OPTIONS$|TAPE$|LIBARCHIVE|BSDTAR|HOME$|USERPROFILE$|PATH$|PATHEXT$|COMSPEC$|SYSTEMROOT$|WINDIR$|LC_ALL$|LC_[A-Z_]+$|LANG$|LANGUAGE$|BASH_ENV$|ENV$|CDPATH$)'
    $managedNames = @()
    foreach ($entry in $existingEnvironment.GetEnumerator()) {
        if ([string]$entry.Key -match $managedPattern) {
            $managedNames += [string]$entry.Key
        }
    }
    $managedNames = @($managedNames | Microsoft.PowerShell.Utility\Sort-Object -Unique)
    try {
        foreach ($name in $managedNames) {
            [Environment]::SetEnvironmentVariable($name, $null, "Process")
        }
        [Environment]::SetEnvironmentVariable("PATH", "$WindowsSystemDirectory;$WindowsDirectory", "Process")
        [Environment]::SetEnvironmentVariable("PATHEXT", ".COM;.EXE;.BAT;.CMD", "Process")
        [Environment]::SetEnvironmentVariable(
            "COMSPEC",
            (Microsoft.PowerShell.Management\Join-Path $WindowsSystemDirectory "cmd.exe"),
            "Process"
        )
        [Environment]::SetEnvironmentVariable("SYSTEMROOT", $WindowsDirectory, "Process")
        [Environment]::SetEnvironmentVariable("WINDIR", $WindowsDirectory, "Process")
        [Environment]::SetEnvironmentVariable("LC_ALL", "C", "Process")
        [Environment]::SetEnvironmentVariable("LANG", "C", "Process")
        foreach ($entry in [Environment]::GetEnvironmentVariables("Process").GetEnumerator()) {
            if ([string]$entry.Key -match '^(?:TAR_OPTIONS$|TAPE$|LIBARCHIVE|BSDTAR|BASH_ENV$|ENV$|CDPATH$)') {
                throw "A forbidden inherited tar process variable survived sanitization: $($entry.Key)"
            }
        }
        Invoke-Checked $Tar $Arguments
    }
    finally {
        $restoreNames = @(
            @($managedNames + @(
                "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR", "LC_ALL", "LANG"
            )) | Microsoft.PowerShell.Utility\Sort-Object -Unique
        )
        foreach ($name in $restoreNames) {
            $restoreValue = $null
            if ($existingEnvironment.Contains($name)) {
                $restoreValue = [string]$existingEnvironment[$name]
            }
            [Environment]::SetEnvironmentVariable($name, $restoreValue, "Process")
        }
    }
    Assert-ReleaseSourceToolIntegrity
}

function Initialize-PreAttestationGitHome {
    $candidate = Microsoft.PowerShell.Management\Join-Path `
        $RootDir `
        (".waal-absent-git-home-" + [Guid]::NewGuid().ToString("N"))
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $candidate) {
        throw "The pre-attestation Git home sentinel unexpectedly exists."
    }
    $script:GitHome = $candidate
    $script:GitHomeMustRemainAbsent = $true
}

function Initialize-ReleaseGitHome {
    if (-not $ReleaseRoot) {
        throw "The tracked private release root must exist before creating Git home."
    }
    $script:GitHome = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot "git-home"
    Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $GitHome | Microsoft.PowerShell.Core\Out-Null
    Assert-RealDirectory $GitHome
    $script:GitHomeMustRemainAbsent = $false
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

function Assert-RegularSingleLinkFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-NoReparsePointComponents $Path
    $handle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenRegularSingleLink($Path)
    try {
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertRegularSingleLink($handle)
    }
    finally {
        $handle.Dispose()
    }
}

function Get-SingleLinkSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashRegularSingleLinkSha256($Path)
}

function Read-SingleLinkText {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::ReadRegularSingleLinkBytes($Path)
    $utf8 = Microsoft.PowerShell.Utility\New-Object Text.UTF8Encoding($false, $true)
    return $utf8.GetString($bytes)
}

function Copy-SingleLinkFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Destination) {
        throw "Single-link copy destination already exists: $Destination"
    }
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::CopyRegularSingleLink(
        $Source,
        $Destination
    )
}

function Copy-SingleLinkFileFromHandle {
    param(
        [Parameter(Mandatory = $true)]$SourceHandle,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Destination) {
        throw "Single-link copy destination already exists: $Destination"
    }
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::CopyTrackedRegularSingleLink(
        $SourceHandle,
        $Destination
    )
}

function Copy-SingleLinkExecutableAndCaptureBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Destination) {
        throw "Executable copy destination already exists: $Destination"
    }
    $bytes = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::CopyRegularSingleLinkAndCaptureBytes(
        $Source,
        $Destination
    )
    if ($null -eq $bytes -or $bytes.GetType() -ne [byte[]] -or $bytes.Length -eq 0) {
        throw "Executable copy did not return one exact non-empty byte snapshot."
    }
    return ,$bytes
}

function Copy-SingleLinkExecutableFromHandleAndCaptureBytes {
    param(
        [Parameter(Mandatory = $true)]$SourceHandle,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Destination) {
        throw "Executable copy destination already exists: $Destination"
    }
    $bytes = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::CopyTrackedRegularSingleLinkAndCaptureBytes(
        $SourceHandle,
        $Destination
    )
    if ($null -eq $bytes -or $bytes.GetType() -ne [byte[]] -or $bytes.Length -eq 0) {
        throw "Handle-bound executable copy did not return one exact non-empty byte snapshot."
    }
    return ,$bytes
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

function Get-DirectoryRelativeFilePaths {
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
    return ,$ordered
}

function Open-DirectoryTreeReadLocks {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-NoReparsePointComponents $Path
    $root = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force).FullName.TrimEnd('\', '/')
    $relativePaths = Get-DirectoryRelativeFilePaths $root
    $entries = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($relative in $relativePaths) {
            $filePath = Microsoft.PowerShell.Management\Join-Path $root ($relative.Replace('/', '\'))
            $before = Microsoft.PowerShell.Management\Get-Item -LiteralPath $filePath -Force
            if ($before.PSIsContainer -or
                (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw "Tree lock input changed type before it was opened: $filePath"
            }
            # FileShare.Read keeps compilers/loaders usable while denying writes,
            # hard-link writes, replacement, and deletion for the lifetime of
            # the retained stream.
            $stream = [IO.File]::Open(
                $filePath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read
            )
            $null = $entries.Add([PSCustomObject]@{
                Relative = $relative
                Path = $filePath
                Stream = $stream
            })
            $after = Microsoft.PowerShell.Management\Get-Item -LiteralPath $filePath -Force
            if ($after.PSIsContainer -or
                (($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
                $stream.Length -ne $after.Length) {
                throw "Tree lock input changed while its non-write-sharing handle was opened: $filePath"
            }
        }
        $afterPaths = Get-DirectoryRelativeFilePaths $root
        if (($relativePaths -join "`n") -cne ($afterPaths -join "`n")) {
            throw "Tree hash input file set changed while its handles were locked."
        }
        return [PSCustomObject]@{
            Root = $root
            Entries = $entries.ToArray()
        }
    }
    catch {
        foreach ($entry in $entries) {
            if ($entry.Stream) { $entry.Stream.Dispose() }
        }
        throw
    }
}

function Get-LockedFileSha256 {
    param([Parameter(Mandatory = $true)]$Stream)

    if (-not $Stream -or -not $Stream.CanRead -or $Stream.SafeFileHandle.IsInvalid -or
        $Stream.SafeFileHandle.IsClosed) {
        throw "A retained release-input file handle is unavailable."
    }
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        $digest = $sha256.ComputeHash($Stream)
        $Stream.Position = 0
        return (($digest | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-LockedDirectoryTreeSha256 {
    param([Parameter(Mandatory = $true)]$State)

    Assert-NoReparsePointComponents $State.Root
    $currentPaths = Get-DirectoryRelativeFilePaths $State.Root
    $expectedPaths = @($State.Entries | Microsoft.PowerShell.Core\ForEach-Object { $_.Relative })
    if (($expectedPaths -join "`n") -cne ($currentPaths -join "`n")) {
        throw "A retained release-input directory changed its exact file set."
    }

    $aggregate = [Security.Cryptography.SHA256]::Create()
    $utf8 = Microsoft.PowerShell.Utility\New-Object Text.UTF8Encoding($false)
    $nul = [byte[]]@(0)
    try {
        foreach ($entry in $State.Entries) {
            $pathItem = Microsoft.PowerShell.Management\Get-Item -LiteralPath $entry.Path -Force
            if ($pathItem.PSIsContainer -or
                (($pathItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
                $pathItem.Length -ne $entry.Stream.Length) {
                throw "A retained release-input path no longer identifies a regular file: $($entry.Path)"
            }
            if ("Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner" -as [type]) {
                [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertRegularSingleLink(
                    $entry.Stream.SafeFileHandle
                )
                [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularPath(
                    $entry.Path,
                    $entry.Stream.SafeFileHandle
                )
            }
            $fileHash = Get-LockedFileSha256 $entry.Stream
            foreach ($bytes in @(
                $utf8.GetBytes($entry.Relative), $nul, $utf8.GetBytes($fileHash), $nul
            )) {
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

function Close-DirectoryTreeReadLocks {
    param([AllowNull()]$State)

    $failure = $null
    if ($State) {
        foreach ($entry in $State.Entries) {
            try {
                if ($entry.Stream) { $entry.Stream.Dispose() }
            }
            catch {
                if (-not $failure) { $failure = $_ }
            }
        }
    }
    if ($failure) { throw $failure }
}

function Get-DirectoryTreeSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $state = Open-DirectoryTreeReadLocks $Path
    try {
        return (Get-LockedDirectoryTreeSha256 $state)
    }
    finally {
        Close-DirectoryTreeReadLocks $state
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

function Open-LockedRegularFileState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    Assert-NoReparsePointComponents $Path
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $state = [PSCustomObject]@{
            Path = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force).FullName
            Stream = $stream
            ExpectedSha256 = $ExpectedSha256
        }
        if ((Get-LockedFileSha256 $stream) -cne $ExpectedSha256) {
            throw "A release input changed before its non-write-sharing lock was established: $Path"
        }
        return $state
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Assert-LockedRegularFileState {
    param([Parameter(Mandatory = $true)]$State)

    Assert-NoReparsePointComponents $State.Path
    if ((Get-LockedFileSha256 $State.Stream) -cne $State.ExpectedSha256) {
        throw "A locked release executable changed unexpectedly: $($State.Path)"
    }
    if ("Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner" -as [type]) {
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertRegularSingleLink(
            $State.Stream.SafeFileHandle
        )
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularPath(
            $State.Path,
            $State.Stream.SafeFileHandle
        )
    }
}

function Lock-SourceToolInputs {
    if ($GitRuntimeLockState -or $TarLockState) {
        throw "Source-tool locks were initialized more than once."
    }
    $gitState = $null
    $tarState = $null
    try {
        $gitState = Open-DirectoryTreeReadLocks $GitRoot
        if ((Get-LockedDirectoryTreeSha256 $gitState) -cne $GitRootSha256) {
            throw "Git runtime tree changed before its release lock was established."
        }
        $tarState = Open-LockedRegularFileState $Tar $TarSha256
        $script:GitRuntimeLockState = $gitState
        $script:TarLockState = $tarState
        $gitState = $null
        $tarState = $null
    }
    finally {
        if ($gitState) { Close-DirectoryTreeReadLocks $gitState }
        if ($tarState -and $tarState.Stream) { $tarState.Stream.Dispose() }
    }
}

function Assert-SourceToolLocks {
    if (-not $GitRuntimeLockState -or -not $TarLockState) {
        throw "Pinned Git runtime and tar locks are unavailable."
    }
    if ((Get-LockedDirectoryTreeSha256 $GitRuntimeLockState) -cne $GitRootSha256) {
        throw "Locked Git runtime tree no longer matches its reviewed digest."
    }
    Assert-LockedRegularFileState $TarLockState
}

function Resolve-AndLock-CodeDomCompiler {
    if ($CodeDomRuntimeLockState) {
        throw "CodeDom compiler runtime was initialized more than once."
    }
    if (-not $Development -and
        ($PSVersionTable.PSEdition -cne "Desktop" -or
         $PSVersionTable.PSVersion.Major -ne 5 -or
         $PSVersionTable.PSVersion.Minor -ne 1)) {
        throw "Publishable Windows packaging requires the Windows PowerShell 5.1 Desktop CodeDom runtime."
    }
    $reportedRuntime = [IO.Path]::GetFullPath(
        [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    ).TrimEnd('\', '/')
    $reportedCompiler = [IO.Path]::Combine($reportedRuntime, "csc.exe")
    Assert-NoReparsePointComponents $reportedRuntime
    Assert-NoReparsePointComponents $reportedCompiler
    if ($Development) {
        $runtimeInput = [PSCustomObject]@{
            Path = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $reportedRuntime -Force).FullName
            Hash = (Get-DirectoryTreeSha256 $reportedRuntime)
        }
        $compilerInput = [PSCustomObject]@{
            Path = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $reportedCompiler -Force).FullName
            Hash = (Get-Sha256 $reportedCompiler)
        }
    }
    else {
        $runtimeInput = Resolve-ExplicitPinnedDirectory `
            "WAAL_WINDOWS_RELEASE_CODEDOM_RUNTIME" `
            "WAAL_WINDOWS_RELEASE_EXPECTED_CODEDOM_RUNTIME_SHA256" `
            "Windows PowerShell CodeDom runtime"
        $compilerInput = Resolve-ExplicitPinnedExecutable `
            "WAAL_WINDOWS_RELEASE_CODEDOM_CSC_PATH" `
            "WAAL_WINDOWS_RELEASE_EXPECTED_CODEDOM_CSC_SHA256" `
            "Windows PowerShell CodeDom csc.exe"
        if ((Normalize-Path $runtimeInput.Path) -ne (Normalize-Path $reportedRuntime) -or
            (Normalize-Path $compilerInput.Path) -ne (Normalize-Path $reportedCompiler)) {
            throw "Pinned CodeDom compiler/runtime do not match the executing Windows PowerShell 5.1 CLR."
        }
    }
    Assert-PathWithinPinnedDirectory $compilerInput.Path $runtimeInput.Path "CodeDom csc.exe"
    if ((Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $compilerInput.Path)) -ne
        (Normalize-Path $runtimeInput.Path)) {
        throw "CodeDom csc.exe must be a direct child of its pinned runtime directory."
    }
    $lockState = Open-DirectoryTreeReadLocks $runtimeInput.Path
    try {
        if ((Get-LockedDirectoryTreeSha256 $lockState) -cne $runtimeInput.Hash) {
            throw "CodeDom runtime changed before its release lock was established."
        }
        $script:CodeDomCompiler = $compilerInput.Path
        $script:CodeDomCompilerSha256 = $compilerInput.Hash
        $script:CodeDomRuntime = $runtimeInput.Path
        $script:CodeDomRuntimeSha256 = $runtimeInput.Hash
        $script:CodeDomRuntimeLockState = $lockState
        $lockState = $null
    }
    finally {
        if ($lockState) { Close-DirectoryTreeReadLocks $lockState }
    }
}

function Assert-CodeDomCompilerIntegrity {
    if (-not $CodeDomRuntimeLockState -or -not $CodeDomCompiler -or
        -not (Test-LowerHex $CodeDomCompilerSha256 64) -or
        -not (Test-LowerHex $CodeDomRuntimeSha256 64)) {
        throw "CodeDom compiler provenance is unavailable."
    }
    if ((Get-LockedDirectoryTreeSha256 $CodeDomRuntimeLockState) -cne $CodeDomRuntimeSha256) {
        throw "Locked CodeDom runtime no longer matches its reviewed digest."
    }
    if ((Get-Sha256 $CodeDomCompiler) -cne $CodeDomCompilerSha256) {
        throw "Locked CodeDom compiler no longer matches its reviewed digest."
    }
}

function Get-LockedDirectoryListContentSha256 {
    param([AllowEmptyString()][string]$DirectoryList = "")

    $treeHashes = [System.Collections.Generic.List[string]]::new()
    if ($DirectoryList) {
        foreach ($directory in ($DirectoryList -split ';')) {
            $key = Normalize-Path $directory
            if (-not $ToolchainDirectoryLocks.ContainsKey($key)) {
                throw "Approved toolchain directory is not retained by a release lock: $directory"
            }
            $null = $treeHashes.Add(
                (Get-LockedDirectoryTreeSha256 $ToolchainDirectoryLocks[$key])
            )
        }
    }
    return (Get-OrderedHashAggregate ($treeHashes.ToArray()))
}

function Assert-ToolchainDirectoryLocks {
    if ($ToolchainDirectoryLocks.Count -eq 0) {
        throw "Toolchain directory locks are unavailable."
    }
    foreach ($input in @(
        [PSCustomObject]@{ Path = $RustSysroot; Hash = $RustSysrootSha256; Name = "Rust sysroot" },
        [PSCustomObject]@{ Path = $CompilerBin; Hash = $CompilerBinSha256; Name = "MSVC bin" },
        [PSCustomObject]@{ Path = $SdkBin; Hash = $SdkBinSha256; Name = "Windows SDK bin" }
    )) {
        $key = Normalize-Path $input.Path
        if (-not $ToolchainDirectoryLocks.ContainsKey($key) -or
            (Get-LockedDirectoryTreeSha256 $ToolchainDirectoryLocks[$key]) -cne $input.Hash) {
            throw "$($input.Name) no longer matches its locked reviewed digest."
        }
    }
    if ((Get-LockedDirectoryListContentSha256 $TrustedLib) -cne $TrustedLibSha256 -or
        (Get-LockedDirectoryListContentSha256 $TrustedInclude) -cne $TrustedIncludeSha256 -or
        (Get-LockedDirectoryListContentSha256 $TrustedLibPath) -cne $TrustedLibPathSha256) {
        throw "A locked approved MSVC directory list no longer matches its reviewed digest."
    }
}

function Lock-ToolchainDirectories {
    if ($ToolchainDirectoryLocks.Count -ne 0) {
        throw "Toolchain directory locks were initialized more than once."
    }
    $directories = [System.Collections.Generic.List[string]]::new()
    foreach ($directory in @($RustSysroot, $CompilerBin, $SdkBin)) {
        $null = $directories.Add($directory)
    }
    foreach ($list in @($TrustedLib, $TrustedInclude, $TrustedLibPath)) {
        if ($list) {
            foreach ($directory in ($list -split ';')) {
                $null = $directories.Add($directory)
            }
        }
    }
    $opened = @{}
    try {
        foreach ($directory in $directories) {
            $key = Normalize-Path $directory
            if (-not $opened.ContainsKey($key)) {
                $opened[$key] = Open-DirectoryTreeReadLocks $directory
            }
        }
        $script:ToolchainDirectoryLocks = $opened
        $opened = @{}
        Assert-ToolchainDirectoryLocks
    }
    finally {
        foreach ($state in $opened.Values) {
            Close-DirectoryTreeReadLocks $state
        }
    }
}

function Close-AllReleaseInputLocks {
    $failure = $null
    foreach ($state in $ToolchainDirectoryLocks.Values) {
        try { Close-DirectoryTreeReadLocks $state }
        catch { if (-not $failure) { $failure = $_ } }
    }
    $script:ToolchainDirectoryLocks = @{}
    try { Close-DirectoryTreeReadLocks $GitRuntimeLockState }
    catch { if (-not $failure) { $failure = $_ } }
    $script:GitRuntimeLockState = $null
    try { Close-DirectoryTreeReadLocks $CodeDomRuntimeLockState }
    catch { if (-not $failure) { $failure = $_ } }
    $script:CodeDomRuntimeLockState = $null
    if ($TarLockState -and $TarLockState.Stream) {
        try { $TarLockState.Stream.Dispose() }
        catch { if (-not $failure) { $failure = $_ } }
    }
    $script:TarLockState = $null
    if ($failure) { throw $failure }
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

function Assert-ReleaseSourceStateUnchanged {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    $state = Get-ReleaseSourceState $GitPath
    if ($state.Commit -cne $ReleaseGitCommit -or $state.Tree -cne $ReleaseGitTree) {
        throw "Release source HEAD or tree changed during packaging."
    }
}

function Assert-ReleaseSourceUnchangedBeforeToolchain {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    # Before Cargo/rustc/native-tool resolution, only the pinned Git runtime
    # and tar are available. Keep this transition fail-closed without calling
    # the full toolchain verifier on deliberately uninitialized paths.
    Assert-ReleaseSourceToolIntegrity
    Assert-ReleaseSourceStateUnchanged $GitPath
    Assert-ReleaseSourceToolIntegrity
}

function Assert-ReleaseSourceUnchanged {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    Assert-ReleaseToolchainIntegrity
    Assert-ReleaseSourceStateUnchanged $GitPath
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
    if ($PublicationParentHandle -or $PublicationCandidateHandle -or $PublicationFinalHandle) {
        throw "Publication directory handles were initialized more than once."
    }
    $suffix = [Guid]::NewGuid().ToString("N")
    $script:PublicationCandidateDir = Microsoft.PowerShell.Management\Join-Path $DistRoot ".$DistName.candidate-$suffix"
    Assert-SafePublicationPath $PublicationCandidateDir ('^\.' + [regex]::Escape($DistName) + '\.candidate-[0-9a-f]{32}$')
    Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $PublicationCandidateDir | Microsoft.PowerShell.Core\Out-Null
    Assert-RealDirectory $PublicationCandidateDir
    $parentHandle = $null
    $candidateHandle = $null
    try {
        $parentHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackPublicationParent(
            $DistRoot
        )
        $candidateLeaf = Microsoft.PowerShell.Management\Split-Path -Leaf $PublicationCandidateDir
        $candidateHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackPublicationCandidate(
            $parentHandle,
            $candidateLeaf
        )
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedDirectoryChild(
            $parentHandle,
            $candidateLeaf,
            $candidateHandle
        )
        $script:PublicationParentHandle = $parentHandle
        $script:PublicationCandidateHandle = $candidateHandle
        $parentHandle = $null
        $candidateHandle = $null
    }
    finally {
        if ($candidateHandle -and -not $candidateHandle.IsClosed) { $candidateHandle.Dispose() }
        if ($parentHandle -and -not $parentHandle.IsClosed) { $parentHandle.Dispose() }
    }
    return $PublicationCandidateDir
}

function Lock-PublicationCandidateDirectory {
    if (-not $PublicationParentHandle -or $PublicationParentHandle.IsClosed -or
        -not $PublicationCandidateHandle -or $PublicationCandidateHandle.IsClosed) {
        throw "Publication candidate is not pinned for its immutable transition."
    }
    $candidateLeaf = Microsoft.PowerShell.Management\Split-Path -Leaf $PublicationCandidateDir
    $previous = $PublicationCandidateHandle
    try {
        $locked = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::UpgradeTrackedPublicationDirectory(
            $PublicationParentHandle,
            $candidateLeaf,
            $previous
        )
        $script:PublicationCandidateHandle = $locked
    }
    catch {
        # Upgrade closes the mutable handle immediately before its exact
        # handle-relative reopen. If that transition cannot be proven, retain
        # the (possibly closed) object only as evidence and leave the pathname
        # untouched during fail-closed cleanup.
        $script:PublicationCandidateHandle = $previous
        throw
    }
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedDirectoryChild(
        $PublicationParentHandle,
        $candidateLeaf,
        $PublicationCandidateHandle
    )
}

function Activate-PublicationCandidate {
    Assert-SafePublicationPath $DistDir ('^' + [regex]::Escape($DistName) + '-[0-9a-f]{40}$')
    Assert-SafePublicationPath $PublicationCandidateDir ('^\.' + [regex]::Escape($DistName) + '\.candidate-[0-9a-f]{32}$')
    if (-not $PublicationParentHandle -or $PublicationParentHandle.IsClosed -or
        -not $PublicationCandidateHandle -or $PublicationCandidateHandle.IsClosed) {
        throw "Verified publication candidate handles are unavailable."
    }
    $candidateLeaf = Microsoft.PowerShell.Management\Split-Path -Leaf $PublicationCandidateDir
    $finalLeaf = Microsoft.PowerShell.Management\Split-Path -Leaf $DistDir
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedDirectoryChild(
        $PublicationParentHandle,
        $candidateLeaf,
        $PublicationCandidateHandle
    )
    # Activate the exact candidate object through its DELETE-capable handle.
    # FILE_RENAME_INFO with zero flags supplies atomic same-volume no-replace
    # semantics; the pinned parent handle is the destination authority.
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::RenameTrackedDirectoryNoReplace(
        $PublicationCandidateHandle,
        $PublicationParentHandle,
        $finalLeaf
    )
    $script:PublicationFinalHandle = $PublicationCandidateHandle
    $script:PublicationCandidateHandle = $null
    $script:PublicationFinalActivated = $true
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedDirectoryChild(
        $PublicationParentHandle,
        $finalLeaf,
        $PublicationFinalHandle
    )
}

function Move-TrackedPublicationAside {
    param(
        [Parameter(Mandatory = $true)]$DirectoryHandle,
        [Parameter(Mandatory = $true)][ValidateSet("failed", "abandoned")][string]$Kind
    )

    if (-not $PublicationParentHandle -or $PublicationParentHandle.IsClosed -or
        -not $DirectoryHandle -or $DirectoryHandle.IsClosed) {
        throw "Tracked publication handles are unavailable for quarantine."
    }
    $quarantineLeaf = ".$DistName.$Kind-" + [Guid]::NewGuid().ToString("N")
    if ($quarantineLeaf -cnotmatch ('^\.' + [regex]::Escape($DistName) + '\.(?:failed|abandoned)-[0-9a-f]{32}$')) {
        throw "Generated publication quarantine leaf is unsafe."
    }
    # Cleanup never resolves or mutates a candidate/final pathname. Rename the
    # exact still-open directory object to a fresh no-replace quarantine leaf.
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::RenameTrackedDirectoryNoReplace(
        $DirectoryHandle,
        $PublicationParentHandle,
        $quarantineLeaf
    )
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedDirectoryChild(
        $PublicationParentHandle,
        $quarantineLeaf,
        $DirectoryHandle
    )
}

function Restore-PublicationAfterFailure {
    if ($PublicationComplete) { return }
    $trackedDirectory = $null
    $kind = "abandoned"
    if ($PublicationFinalHandle -and -not $PublicationFinalHandle.IsClosed) {
        $trackedDirectory = $PublicationFinalHandle
        $kind = "failed"
    }
    elseif ($PublicationCandidateHandle -and -not $PublicationCandidateHandle.IsClosed) {
        $trackedDirectory = $PublicationCandidateHandle
    }
    if ($trackedDirectory) {
        Move-TrackedPublicationAside $trackedDirectory $kind
        $script:PublicationFinalActivated = $false
        return
    }
    if ($PublicationCandidateDir -or $PublicationFinalActivated) {
        Microsoft.PowerShell.Utility\Write-Warning `
            "Leaving an unverified publication directory in place because its exact handle identity is unavailable."
    }
}

function Complete-DevelopmentPublication {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)]$ExpectedPayloadHashes,
        [Parameter(Mandatory = $true)][string]$ExpectedMetadata
    )

    # Re-enumerate the exact seven-file set at the completion boundary. The
    # resulting directory remains a mutable, non-attested development output;
    # consumers must validate SHA256SUMS.txt again before using its payload.
    Assert-WindowsDistribution $Directory $ExpectedPayloadHashes $ExpectedMetadata
    $script:PublicationComplete = $true
}

function Stop-DistProcesses {
    Prepare-DistRoot
    $normalizedDistRoot = Normalize-Path (Microsoft.PowerShell.Management\Resolve-Path $DistRoot).ProviderPath
    $productionPattern = '^' + [regex]::Escape($ProductionDistName) + '-[0-9a-f]{40}$'
    $developmentPattern = '^' + [regex]::Escape($DevelopmentDistName) + '-[0-9a-f]{40}$'
    $processes = CimCmdlets\Get-CimInstance Win32_Process -Filter "Name = 'WindowsAppAutoLogin.exe' OR Name = 'windows-app-autologin.exe' OR Name = 'WindowsAppAutoLoginUI.exe' OR Name = 'windows-app-autologin-ui.exe'" |
        Microsoft.PowerShell.Core\Where-Object {
            if (-not $_.ExecutablePath) { return $false }
            try {
                $physicalProcessPath = [IO.Path]::GetFullPath($_.ExecutablePath)
                $processLeaf = Microsoft.PowerShell.Management\Split-Path -Leaf $physicalProcessPath
                if ($processLeaf -ine $ExeName -and
                    $processLeaf -ine "$BinaryName.exe" -and
                    $processLeaf -ine $UiExeName -and
                    $processLeaf -ine "$UiBinaryName.exe") {
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
    Assert-CodeDomCompilerIntegrity
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
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Obcardinal.WindowsAppAutoLogin
{
    public static class ReleaseTreeCleaner
    {
        private const uint DeleteAccess = 0x00010000;
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint FileListDirectory = 0x00000001;
        private const uint FileReadAttributes = 0x00000080;
        private const uint FileWriteAttributes = 0x00000100;
        private const uint Synchronize = 0x00100000;

        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint FileShareDelete = 0x00000004;

        private const uint OpenExisting = 3;
        private const uint CreateNew = 1;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileOpenForBackupIntent = 0x00004000;
        private const uint FileOpenReparsePoint = 0x00200000;
        private const uint FileSynchronousIoNonAlert = 0x00000020;
        private const uint FileDirectoryFile = 0x00000001;
        private const uint FileCreate = 2;
        private const uint ObjectCaseInsensitive = 0x00000040;

        private const uint FileAttributeReadOnly = 0x00000001;
        private const uint FileAttributeDirectory = 0x00000010;
        private const uint FileAttributeNormal = 0x00000080;
        private const uint FileAttributeReparsePoint = 0x00000400;

        private const int FileBasicInfoClass = 0;
        private const int FileRenameInfoClass = 3;
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
        private const int FileRenameRootDirectoryOffset = 8;
        private const int FileRenameNameLengthOffset = 16;
        private const int FileRenameNameOffset = 20;
        private const uint DuplicateSameAccess = 0x00000002;

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
        private struct FileRenameInformationPrefix
        {
            internal uint Flags;
            internal IntPtr RootDirectory;
            internal uint FileNameLength;
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
            internal readonly uint NumberOfLinks;
            internal readonly ulong FileSize;

            internal Identity(ByHandleFileInformation information)
            {
                VolumeSerialNumber = information.VolumeSerialNumber;
                FileId = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
                CreationTime = ((ulong)information.CreationTime.HighDateTime << 32) |
                    information.CreationTime.LowDateTime;
                Attributes = information.FileAttributes;
                NumberOfLinks = information.NumberOfLinks;
                FileSize = ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow;
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

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DuplicateHandle(
            IntPtr sourceProcess,
            IntPtr sourceHandle,
            IntPtr targetProcess,
            out IntPtr targetHandle,
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint options);

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

        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileRenameInformationByHandle(
            SafeFileHandle file,
            int informationClass,
            IntPtr information,
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
        private static extern int NtCreateFile(
            out IntPtr fileHandle,
            uint desiredAccess,
            ref ObjectAttributes objectAttributes,
            out IoStatusBlock ioStatusBlock,
            IntPtr allocationSize,
            uint fileAttributes,
            uint shareAccess,
            uint createDisposition,
            uint createOptions,
            IntPtr eaBuffer,
            uint eaLength);

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
                if (!identity.IsDirectory || identity.IsReparsePoint || identity.NumberOfLinks != 1)
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

        public static SafeFileHandle TrackPublicationParent(string path)
        {
            ValidateNativeLayouts();
            if (String.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path))
            {
                throw new ArgumentException("Publication parent must be an absolute path.", "path");
            }

            // Keep the exact dist directory pinned without denying the
            // candidate's ordinary construction writes. Omitting delete share
            // prevents the parent itself from being renamed or replaced.
            SafeFileHandle handle = CreateFile(
                path,
                FileListDirectory | FileReadAttributes | Synchronize,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            EnsureValid(handle, "open and pin the distribution parent");
            try
            {
                Identity identity = GetIdentity(handle, "identify the distribution parent");
                if (!identity.IsDirectory || identity.IsReparsePoint || identity.NumberOfLinks != 1)
                {
                    throw new IOException("The distribution parent is not a physical directory.");
                }
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static SafeFileHandle TrackPublicationCandidate(
            SafeFileHandle parent,
            string leafName)
        {
            SafeFileHandle handle = OpenChildNoFollow(
                parent,
                leafName,
                DeleteAccess | FileListDirectory | FileReadAttributes | Synchronize,
                FileShareRead | FileShareWrite);
            try
            {
                Identity identity = GetIdentity(handle, "identify the publication candidate");
                if (!identity.IsDirectory || identity.IsReparsePoint || identity.NumberOfLinks != 1)
                {
                    throw new IOException("The publication candidate is not a physical directory.");
                }
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static SafeFileHandle UpgradeTrackedPublicationDirectory(
            SafeFileHandle parent,
            string leafName,
            SafeFileHandle previous)
        {
            if (previous == null || previous.IsInvalid || previous.IsClosed)
            {
                throw new InvalidOperationException("The mutable publication-directory handle is unavailable.");
            }
            Identity expected = GetIdentity(previous, "identify the publication directory before locking it");
            if (!expected.IsDirectory || expected.IsReparsePoint || expected.NumberOfLinks != 1)
            {
                throw new IOException("The mutable publication directory has an unsafe identity.");
            }

            // Windows share modes cannot be strengthened on an existing
            // handle. Release the construction handle, reopen the same child
            // relative to the pinned parent with write/delete sharing denied,
            // and reject any object substitution across that transition.
            previous.Dispose();
            SafeFileHandle locked = OpenChildNoFollow(
                parent,
                leafName,
                DeleteAccess | FileListDirectory | FileReadAttributes | Synchronize,
                FileShareRead);
            try
            {
                Identity actual = GetIdentity(locked, "identify the locked publication directory");
                if (!expected.SameObjectAndKind(actual) || !actual.IsDirectory ||
                    actual.IsReparsePoint || actual.NumberOfLinks != 1)
                {
                    throw new IOException("The publication directory changed identity while its lock was upgraded.");
                }
                return locked;
            }
            catch
            {
                locked.Dispose();
                throw;
            }
        }

        public static void AssertTrackedDirectoryChild(
            SafeFileHandle parent,
            string leafName,
            SafeFileHandle expectedChild)
        {
            if (expectedChild == null || expectedChild.IsInvalid || expectedChild.IsClosed)
            {
                throw new InvalidOperationException("Tracked publication-directory handle is unavailable.");
            }
            Identity expected = GetIdentity(expectedChild, "identify a tracked publication directory");
            using (SafeFileHandle opened = OpenChildNoFollow(
                parent,
                leafName,
                FileReadAttributes | Synchronize,
                FileShareRead | FileShareWrite | FileShareDelete))
            {
                Identity actual = GetIdentity(opened, "reopen a tracked publication directory");
                if (!expected.SameObjectAndKind(actual) || !expected.IsDirectory ||
                    expected.IsReparsePoint || expected.NumberOfLinks != 1 ||
                    actual.NumberOfLinks != 1)
                {
                    throw new IOException("The publication pathname no longer names the tracked directory.");
                }
            }
        }

        public static SafeFileHandle OpenTrackedRegularSingleLinkForRename(
            SafeFileHandle directory,
            string leafName)
        {
            SafeFileHandle handle = OpenChildNoFollow(
                directory,
                leafName,
                GenericRead | FileReadAttributes | Synchronize,
                FileShareRead | FileShareDelete);
            try
            {
                Identity identity = GetIdentity(handle, "identify a publication payload before rename");
                if (identity.IsDirectory || identity.IsReparsePoint || identity.NumberOfLinks != 1)
                {
                    throw new IOException("Publication payload must be regular, non-reparse, and single-link.");
                }
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static SafeFileHandle LockTrackedRegularSingleLinkAfterRename(
            SafeFileHandle directory,
            string leafName,
            SafeFileHandle expectedChild)
        {
            if (expectedChild == null || expectedChild.IsInvalid || expectedChild.IsClosed)
            {
                throw new InvalidOperationException("Pre-rename publication payload handle is unavailable.");
            }
            Identity expected = GetIdentity(expectedChild, "identify a pre-rename publication payload");
            SafeFileHandle locked = OpenChildNoFollow(
                directory,
                leafName,
                GenericRead | FileReadAttributes | Synchronize,
                FileShareRead);
            try
            {
                Identity actual = GetIdentity(locked, "identify a locked final publication payload");
                EnsureStableSingleLinkFile(expected, actual, "publication payload across directory rename");
                return locked;
            }
            catch
            {
                locked.Dispose();
                throw;
            }
        }

        public static void AssertTrackedRegularChild(
            SafeFileHandle directory,
            string leafName,
            SafeFileHandle expectedChild)
        {
            if (expectedChild == null || expectedChild.IsInvalid || expectedChild.IsClosed)
            {
                throw new InvalidOperationException("Tracked publication payload handle is unavailable.");
            }
            Identity expected = GetIdentity(expectedChild, "identify a tracked publication payload");
            using (SafeFileHandle opened = OpenChildNoFollow(
                directory,
                leafName,
                FileReadAttributes | Synchronize,
                FileShareRead | FileShareWrite | FileShareDelete))
            {
                Identity actual = GetIdentity(opened, "reopen a tracked publication payload");
                EnsureStableSingleLinkFile(expected, actual, "publication payload pathname");
            }
        }

        public static void RenameTrackedDirectoryNoReplace(
            SafeFileHandle directory,
            SafeFileHandle destinationParent,
            string destinationLeaf)
        {
            if (directory == null || directory.IsInvalid || directory.IsClosed ||
                destinationParent == null || destinationParent.IsInvalid || destinationParent.IsClosed)
            {
                throw new InvalidOperationException("Tracked publication handles are unavailable for activation.");
            }
            ValidateLeafName(destinationLeaf);
            Identity directoryBefore = GetIdentity(directory, "identify the publication directory before activation");
            Identity parentBefore = GetIdentity(destinationParent, "identify the publication parent before activation");
            if (!directoryBefore.IsDirectory || directoryBefore.IsReparsePoint ||
                directoryBefore.NumberOfLinks != 1 || !parentBefore.IsDirectory ||
                parentBefore.IsReparsePoint || parentBefore.NumberOfLinks != 1)
            {
                throw new IOException("Publication activation received an unsafe directory identity.");
            }

            byte[] nameBytes = Encoding.Unicode.GetBytes(destinationLeaf);
            // Allocate the trailing WCHAR required by FILE_RENAME_INFO and
            // leave it zero, while FileNameLength continues to exclude it.
            int bufferLength = checked(FileRenameNameOffset + nameBytes.Length + 2);
            IntPtr buffer = IntPtr.Zero;
            bool parentReferenceAdded = false;
            try
            {
                // A zero Flags/ReplaceIfExists union is the documented
                // no-replace FILE_RENAME_INFO contract.
                byte[] zeroed = new byte[bufferLength];
                buffer = Marshal.AllocHGlobal(bufferLength);
                Marshal.Copy(zeroed, 0, buffer, bufferLength);
                Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, FileRenameNameOffset), nameBytes.Length);
                destinationParent.DangerousAddRef(ref parentReferenceAdded);
                Marshal.WriteIntPtr(
                    buffer,
                    FileRenameRootDirectoryOffset,
                    destinationParent.DangerousGetHandle());
                Marshal.WriteInt32(buffer, FileRenameNameLengthOffset, nameBytes.Length);
                if (!SetFileRenameInformationByHandle(
                    directory,
                    FileRenameInfoClass,
                    buffer,
                    checked((uint)bufferLength)))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to atomically activate the publication directory without replacement.");
                }
            }
            finally
            {
                if (parentReferenceAdded)
                {
                    destinationParent.DangerousRelease();
                }
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            Identity directoryAfter = GetIdentity(directory, "re-identify the activated publication directory");
            Identity parentAfter = GetIdentity(destinationParent, "re-identify the publication parent after activation");
            if (!directoryBefore.SameObjectAndKind(directoryAfter) ||
                directoryAfter.NumberOfLinks != 1 ||
                !parentBefore.SameObjectAndKind(parentAfter) || parentAfter.NumberOfLinks != 1)
            {
                throw new IOException("Publication directory or parent changed identity during activation.");
            }
            AssertTrackedDirectoryChild(destinationParent, destinationLeaf, directory);
        }

        public static SafeFileHandle[] CreateTrackedRoot(
            string parentPath,
            string leafName,
            byte[] securityDescriptor)
        {
            ValidateNativeLayouts();
            if (String.IsNullOrWhiteSpace(parentPath) || !Path.IsPathRooted(parentPath))
            {
                throw new ArgumentException("Cleanup-root parent must be absolute.", "parentPath");
            }
            ValidateLeafName(leafName);
            if (securityDescriptor == null || securityDescriptor.Length == 0)
            {
                throw new ArgumentException("Cleanup-root security descriptor is required.", "securityDescriptor");
            }

            SafeFileHandle parent = CreateFile(
                parentPath,
                FileListDirectory | FileReadAttributes | Synchronize,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            EnsureValid(parent, "open and pin the private release-root parent");
            SafeFileHandle child = null;
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr unicodeStringBuffer = IntPtr.Zero;
            IntPtr descriptorBuffer = IntPtr.Zero;
            bool parentReferenceAdded = false;
            bool ownershipTransferred = false;
            try
            {
                Identity parentIdentity = GetIdentity(parent, "identify the private release-root parent");
                if (!parentIdentity.IsDirectory || parentIdentity.IsReparsePoint)
                {
                    throw new IOException("The private release-root parent is not a physical directory.");
                }

                int nameByteLength = checked(leafName.Length * 2);
                if (nameByteLength > UInt16.MaxValue - 2)
                {
                    throw new IOException("The private release-root leaf name is too long.");
                }
                nameBuffer = Marshal.StringToHGlobalUni(leafName);
                UnicodeString unicodeName = new UnicodeString();
                unicodeName.Length = (ushort)nameByteLength;
                unicodeName.MaximumLength = (ushort)(nameByteLength + 2);
                unicodeName.Buffer = nameBuffer;
                unicodeStringBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(unicodeName, unicodeStringBuffer, false);
                descriptorBuffer = Marshal.AllocHGlobal(securityDescriptor.Length);
                Marshal.Copy(securityDescriptor, 0, descriptorBuffer, securityDescriptor.Length);

                ObjectAttributes attributes = new ObjectAttributes();
                attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
                parent.DangerousAddRef(ref parentReferenceAdded);
                attributes.RootDirectory = parent.DangerousGetHandle();
                attributes.ObjectName = unicodeStringBuffer;
                attributes.Attributes = ObjectCaseInsensitive;
                attributes.SecurityDescriptor = descriptorBuffer;

                IoStatusBlock statusBlock;
                IntPtr rawHandle;
                int status = NtCreateFile(
                    out rawHandle,
                    DeleteAccess | FileListDirectory | FileReadAttributes |
                        FileWriteAttributes | Synchronize,
                    ref attributes,
                    out statusBlock,
                    IntPtr.Zero,
                    FileAttributeNormal,
                    FileShareRead | FileShareWrite,
                    FileCreate,
                    FileDirectoryFile | FileOpenForBackupIntent | FileSynchronousIoNonAlert,
                    IntPtr.Zero,
                    0);
                if (status < 0)
                {
                    throw new Win32Exception(
                        unchecked((int)RtlNtStatusToDosError(status)),
                        "Unable to atomically create the tracked private release root.");
                }
                child = new SafeFileHandle(rawHandle, true);
                EnsureValid(child, "retain the newly created private release-root handle");
                Identity childIdentity = GetIdentity(child, "identify the newly created private release root");
                if (!childIdentity.IsDirectory || childIdentity.IsReparsePoint ||
                    childIdentity.NumberOfLinks != 1)
                {
                    throw new IOException("The newly created private release root has an unsafe identity.");
                }
                SafeFileHandle[] handles = new SafeFileHandle[] { parent, child };
                ownershipTransferred = true;
                return handles;
            }
            finally
            {
                if (parentReferenceAdded)
                {
                    parent.DangerousRelease();
                }
                if (!ownershipTransferred && child != null)
                {
                    child.Dispose();
                }
                if (!ownershipTransferred && parent != null)
                {
                    parent.Dispose();
                }
                if (descriptorBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(descriptorBuffer);
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

        public static SafeFileHandle OpenRegularSingleLink(string path)
        {
            ValidateNativeLayouts();
            if (String.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path))
            {
                throw new ArgumentException("File path must be absolute.", "path");
            }
            SafeFileHandle handle = CreateFile(
                path,
                GenericRead | FileReadAttributes,
                FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                FileFlagOpenReparsePoint,
                IntPtr.Zero);
            EnsureValid(handle, "open a regular single-link file");
            try
            {
                Identity identity = GetIdentity(handle, "identify a regular single-link file");
                if (identity.IsDirectory || identity.IsReparsePoint || identity.NumberOfLinks != 1)
                {
                    throw new IOException("File must be regular, non-reparse, and have exactly one hard link.");
                }
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static SafeFileHandle OpenTrackedRegularSingleLink(
            SafeFileHandle directory,
            string leafName)
        {
            SafeFileHandle handle = OpenChildNoFollow(
                directory,
                leafName,
                GenericRead | FileReadAttributes | Synchronize,
                FileShareRead);
            try
            {
                Identity identity = GetIdentity(handle, "identify a tracked-directory file");
                if (identity.IsDirectory || identity.IsReparsePoint || identity.NumberOfLinks != 1)
                {
                    throw new IOException(
                        "Tracked-directory file must be regular, non-reparse, and single-link.");
                }
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        public static SafeFileHandle LockTrackedBuildOutputAfterBuild(
            SafeFileHandle directory,
            string leafName)
        {
            if (directory == null || directory.IsInvalid || directory.IsClosed)
            {
                throw new InvalidOperationException("Tracked build-output directory is unavailable.");
            }
            ValidateLeafName(leafName);
            Identity directoryBefore = GetIdentity(
                directory,
                "identify the tracked build-output directory before locking its child");
            if (!directoryBefore.IsDirectory || directoryBefore.IsReparsePoint ||
                directoryBefore.NumberOfLinks != 1)
            {
                throw new IOException("Tracked build-output directory is unsafe.");
            }

            // Cargo must be free to create, remove, and uplift its normal
            // top-level destination while it runs. Once Cargo exits, open the
            // exact child relative to the retained directory and deny write
            // and delete sharing. This either selects and locks one completed
            // object atomically or fails while a writer/replacer remains open.
            SafeFileHandle locked = OpenChildNoFollow(
                directory,
                leafName,
                GenericRead | FileReadAttributes | Synchronize,
                FileShareRead);
            try
            {
                Identity output = GetIdentity(locked, "identify the locked build output");
                if (output.IsDirectory || output.IsReparsePoint || output.NumberOfLinks != 1 ||
                    output.FileSize == 0)
                {
                    throw new IOException(
                        "Cargo output must be a non-empty regular single-link file.");
                }
                Identity directoryAfter = GetIdentity(
                    directory,
                    "re-identify the tracked build-output directory after locking its child");
                if (!directoryBefore.SameObjectAndKind(directoryAfter) ||
                    !directoryAfter.IsDirectory || directoryAfter.IsReparsePoint ||
                    directoryAfter.NumberOfLinks != 1)
                {
                    throw new IOException(
                        "Build-output directory changed while locking the completed child.");
                }
                return locked;
            }
            catch
            {
                locked.Dispose();
                throw;
            }
        }

        public static void AssertRegularSingleLink(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidOperationException("Tracked file handle is unavailable.");
            }
            Identity identity = GetIdentity(handle, "re-identify a regular single-link file");
            if (identity.IsDirectory || identity.IsReparsePoint || identity.NumberOfLinks != 1)
            {
                throw new IOException("Tracked file identity is no longer a regular single-link file.");
            }
        }

        public static void AssertTrackedRegularPath(string path, SafeFileHandle expectedHandle)
        {
            if (expectedHandle == null || expectedHandle.IsInvalid || expectedHandle.IsClosed)
            {
                throw new InvalidOperationException("Tracked regular-file handle is unavailable.");
            }
            Identity expected = GetIdentity(expectedHandle, "identify a tracked regular-file path");
            using (SafeFileHandle opened = OpenRegularSingleLink(path))
            {
                Identity actual = GetIdentity(opened, "reopen a tracked regular-file path");
                EnsureStableSingleLinkFile(expected, actual, "tracked pathname");
            }
        }

        public static string HashTrackedRegularSingleLinkSha256(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidOperationException("Tracked hash-input handle is unavailable.");
            }
            Identity before = GetIdentity(handle, "identify a tracked SHA-256 input");
            if (before.IsDirectory || before.IsReparsePoint || before.NumberOfLinks != 1)
            {
                throw new IOException("Tracked SHA-256 input is not a regular single-link file.");
            }

            bool referenceAdded = false;
            IntPtr duplicateRaw = IntPtr.Zero;
            try
            {
                handle.DangerousAddRef(ref referenceAdded);
                IntPtr process = GetCurrentProcess();
                if (!DuplicateHandle(
                    process,
                    handle.DangerousGetHandle(),
                    process,
                    out duplicateRaw,
                    0,
                    false,
                    DuplicateSameAccess))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to duplicate a tracked SHA-256 input handle.");
                }
            }
            finally
            {
                if (referenceAdded)
                {
                    handle.DangerousRelease();
                }
            }

            using (SafeFileHandle duplicate = new SafeFileHandle(duplicateRaw, true))
            using (FileStream stream = new FileStream(duplicate, FileAccess.Read, 65536, false))
            using (SHA256 sha256 = SHA256.Create())
            {
                // DuplicateHandle shares the underlying file pointer with the
                // retained handle. Every verification pass must therefore
                // rewind explicitly, and leave the shared pointer rewound for
                // the next authoritative post-rename check.
                stream.Position = 0;
                byte[] digest;
                try
                {
                    digest = sha256.ComputeHash(stream);
                }
                finally
                {
                    stream.Position = 0;
                }
                Identity after = GetIdentity(handle, "re-identify a tracked SHA-256 input");
                EnsureStableSingleLinkFile(before, after, "tracked SHA-256 input");
                return ToLowerHex(digest);
            }
        }

        public static string HashTrackedRegularSingleLinkGitBlobSha1(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidOperationException("Tracked Git-blob input handle is unavailable.");
            }
            Identity before = GetIdentity(handle, "identify a tracked Git-blob input");
            if (before.IsDirectory || before.IsReparsePoint || before.NumberOfLinks != 1)
            {
                throw new IOException("Tracked Git-blob input is not a regular single-link file.");
            }

            bool referenceAdded = false;
            IntPtr duplicateRaw = IntPtr.Zero;
            try
            {
                handle.DangerousAddRef(ref referenceAdded);
                IntPtr process = GetCurrentProcess();
                if (!DuplicateHandle(
                    process,
                    handle.DangerousGetHandle(),
                    process,
                    out duplicateRaw,
                    0,
                    false,
                    DuplicateSameAccess))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to duplicate a tracked Git-blob input handle.");
                }
            }
            finally
            {
                if (referenceAdded)
                {
                    handle.DangerousRelease();
                }
            }

            using (SafeFileHandle duplicate = new SafeFileHandle(duplicateRaw, true))
            using (FileStream stream = new FileStream(duplicate, FileAccess.Read, 65536, false))
            using (SHA1 sha1 = SHA1.Create())
            {
                stream.Position = 0;
                try
                {
                    byte[] header = Encoding.ASCII.GetBytes("blob " + before.FileSize + "\0");
                    sha1.TransformBlock(header, 0, header.Length, header, 0);
                    byte[] buffer = new byte[1048576];
                    int read;
                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        sha1.TransformBlock(buffer, 0, read, buffer, 0);
                    }
                    sha1.TransformFinalBlock(new byte[0], 0, 0);
                }
                finally
                {
                    // DuplicateHandle shares the file pointer with the
                    // retained source handle. Keep every verification pass
                    // independent by rewinding it before returning.
                    stream.Position = 0;
                }
                Identity after = GetIdentity(handle, "re-identify a tracked Git-blob input");
                EnsureStableSingleLinkFile(before, after, "tracked Git-blob input");
                return ToLowerHex(sha1.Hash);
            }
        }

        public static void AssertPhysicalDirectory(SafeFileHandle handle)
        {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
            {
                throw new InvalidOperationException("Tracked directory handle is unavailable.");
            }
            Identity identity = GetIdentity(handle, "re-identify a physical directory");
            if (!identity.IsDirectory || identity.IsReparsePoint || identity.NumberOfLinks != 1)
            {
                throw new IOException("Tracked directory identity is no longer safe.");
            }
        }

        public static void AssertTrackedDirectoryPath(string path, SafeFileHandle expectedHandle)
        {
            if (expectedHandle == null || expectedHandle.IsInvalid || expectedHandle.IsClosed)
            {
                throw new InvalidOperationException("Tracked directory handle is unavailable.");
            }
            Identity expected = GetIdentity(expectedHandle, "identify a tracked directory path");
            SafeFileHandle opened = CreateFile(
                path,
                FileReadAttributes | Synchronize,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                IntPtr.Zero);
            EnsureValid(opened, "reopen a tracked directory path");
            using (opened)
            {
                Identity actual = GetIdentity(opened, "reopen a tracked directory path");
                if (!expected.SameObjectAndKind(actual) || !expected.IsDirectory ||
                    expected.IsReparsePoint || expected.NumberOfLinks != 1 ||
                    actual.NumberOfLinks != 1)
                {
                    throw new IOException("Tracked directory pathname changed identity.");
                }
            }
        }

        public static void AssertTrackedChild(
            SafeFileHandle directory,
            string leafName,
            SafeFileHandle expectedChild)
        {
            if (directory == null || directory.IsInvalid || directory.IsClosed ||
                expectedChild == null || expectedChild.IsInvalid || expectedChild.IsClosed)
            {
                throw new InvalidOperationException("Tracked directory or child handle is unavailable.");
            }
            Identity expected = GetIdentity(expectedChild, "identify an anchored compiler child");
            // The anchor is still held for read/write with write/delete
            // sharing denied and FILE_FLAG_DELETE_ON_CLOSE. Reopen only for
            // identity attributes. This verifier must share the original
            // handle's read/write/delete accesses so Windows accepts the open;
            // it requests no write or delete access itself, and the original
            // handle continues to deny every competing writer or replacement.
            using (SafeFileHandle opened = OpenChildNoFollow(
                directory,
                leafName,
                FileReadAttributes | Synchronize,
                FileShareRead | FileShareWrite | FileShareDelete))
            {
                Identity actual = GetIdentity(opened, "re-open an anchored compiler child");
                if (!expected.SameObjectAndKind(actual) || expected.IsDirectory ||
                    expected.IsReparsePoint || expected.NumberOfLinks != 1 ||
                    actual.NumberOfLinks != 1)
                {
                    throw new IOException("Tracked directory no longer contains the exact anchored child.");
                }
            }
        }

        public static byte[] ReadRegularSingleLinkBytes(string path)
        {
            using (SafeFileHandle handle = OpenRegularSingleLink(path))
            using (FileStream stream = new FileStream(handle, FileAccess.Read, 65536, false))
            using (MemoryStream memory = new MemoryStream())
            {
                Identity before = GetIdentity(handle, "identify a single-link byte input");
                stream.CopyTo(memory);
                Identity after = GetIdentity(handle, "re-identify a single-link byte input");
                EnsureStableSingleLinkFile(before, after, "byte input");
                return memory.ToArray();
            }
        }

        public static string HashRegularSingleLinkSha256(string path)
        {
            using (SafeFileHandle handle = OpenRegularSingleLink(path))
            using (FileStream stream = new FileStream(handle, FileAccess.Read, 65536, false))
            using (SHA256 sha256 = SHA256.Create())
            {
                Identity before = GetIdentity(handle, "identify a single-link SHA-256 input");
                byte[] digest = sha256.ComputeHash(stream);
                Identity after = GetIdentity(handle, "re-identify a single-link SHA-256 input");
                EnsureStableSingleLinkFile(before, after, "SHA-256 input");
                return ToLowerHex(digest);
            }
        }

        public static string HashRegularSingleLinkGitBlobSha1(string path)
        {
            using (SafeFileHandle handle = OpenRegularSingleLink(path))
            using (FileStream stream = new FileStream(handle, FileAccess.Read, 65536, false))
            using (SHA1 sha1 = SHA1.Create())
            {
                Identity before = GetIdentity(handle, "identify a single-link Git-blob input");
                byte[] header = Encoding.ASCII.GetBytes("blob " + before.FileSize + "\0");
                sha1.TransformBlock(header, 0, header.Length, header, 0);
                byte[] buffer = new byte[1048576];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha1.TransformBlock(buffer, 0, read, buffer, 0);
                }
                sha1.TransformFinalBlock(new byte[0], 0, 0);
                Identity after = GetIdentity(handle, "re-identify a single-link Git-blob input");
                EnsureStableSingleLinkFile(before, after, "Git-blob input");
                return ToLowerHex(sha1.Hash);
            }
        }

        public static void CopyRegularSingleLink(string sourcePath, string destinationPath)
        {
            CopyRegularSingleLinkCore(sourcePath, destinationPath, false);
        }

        public static byte[] CopyRegularSingleLinkAndCaptureBytes(
            string sourcePath,
            string destinationPath)
        {
            return CopyRegularSingleLinkCore(sourcePath, destinationPath, true);
        }

        private static byte[] CopyRegularSingleLinkCore(
            string sourcePath,
            string destinationPath,
            bool captureDestination)
        {
            using (SafeFileHandle source = OpenRegularSingleLink(sourcePath))
            {
                return CopyTrackedRegularSingleLinkCore(
                    source,
                    destinationPath,
                    captureDestination);
            }
        }

        public static void CopyTrackedRegularSingleLink(
            SafeFileHandle source,
            string destinationPath)
        {
            CopyTrackedRegularSingleLinkCore(source, destinationPath, false);
        }

        public static byte[] CopyTrackedRegularSingleLinkAndCaptureBytes(
            SafeFileHandle source,
            string destinationPath)
        {
            return CopyTrackedRegularSingleLinkCore(source, destinationPath, true);
        }

        private static byte[] CopyTrackedRegularSingleLinkCore(
            SafeFileHandle source,
            string destinationPath,
            bool captureDestination)
        {
            if (source == null || source.IsInvalid || source.IsClosed)
            {
                throw new InvalidOperationException("Tracked copy-source handle is unavailable.");
            }
            Identity sourceBefore = GetIdentity(source, "identify a tracked single-link copy source");
            if (sourceBefore.IsDirectory || sourceBefore.IsReparsePoint ||
                sourceBefore.NumberOfLinks != 1)
            {
                throw new IOException("Tracked copy source is not a regular single-link file.");
            }

            bool referenceAdded = false;
            IntPtr duplicateRaw = IntPtr.Zero;
            try
            {
                source.DangerousAddRef(ref referenceAdded);
                IntPtr process = GetCurrentProcess();
                if (!DuplicateHandle(
                    process,
                    source.DangerousGetHandle(),
                    process,
                    out duplicateRaw,
                    0,
                    false,
                    DuplicateSameAccess))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Unable to duplicate a tracked single-link copy source.");
                }
            }
            finally
            {
                if (referenceAdded)
                {
                    source.DangerousRelease();
                }
            }

            using (SafeFileHandle duplicate = new SafeFileHandle(duplicateRaw, true))
            {
                SafeFileHandle destination = CreateFile(
                    destinationPath,
                    GenericRead | GenericWrite | FileReadAttributes | Synchronize,
                    FileShareRead,
                    IntPtr.Zero,
                    CreateNew,
                    FileAttributeNormal | FileFlagOpenReparsePoint,
                    IntPtr.Zero);
                EnsureValid(destination, "create a tracked single-link copy destination");
                using (destination)
                using (FileStream sourceStream = new FileStream(duplicate, FileAccess.Read, 65536, false))
                using (FileStream destinationStream = new FileStream(destination, FileAccess.ReadWrite, 65536, false))
                using (SHA256 sourceSha256 = SHA256.Create())
                using (SHA256 destinationSha256 = SHA256.Create())
                {
                    Identity destinationCreated = GetIdentity(destination, "identify a new single-link copy destination");
                    if (destinationCreated.IsDirectory || destinationCreated.IsReparsePoint ||
                        destinationCreated.NumberOfLinks != 1 || destinationCreated.FileSize != 0)
                    {
                        throw new IOException("New copy destination is not an empty regular single-link file.");
                    }
                    sourceStream.Position = 0;
                    try
                    {
                        sourceStream.CopyTo(destinationStream);
                        destinationStream.Flush(true);
                        Identity destinationWritten = GetIdentity(
                            destination,
                            "identify the written single-link copy destination");
                        EnsureSameSingleLinkFileIdentity(
                            destinationCreated,
                            destinationWritten,
                            "copy destination write transition");
                        if (destinationWritten.FileSize != sourceBefore.FileSize)
                        {
                            throw new IOException("Copy destination size does not match its source.");
                        }
                        sourceStream.Position = 0;
                        destinationStream.Position = 0;
                        byte[] sourceDigest = sourceSha256.ComputeHash(sourceStream);
                        byte[] destinationDigest = destinationSha256.ComputeHash(destinationStream);
                        Identity sourceAfter = GetIdentity(source, "re-identify a tracked single-link copy source");
                        Identity destinationAfter = GetIdentity(destination, "re-identify a single-link copy destination");
                        EnsureStableSingleLinkFile(sourceBefore, sourceAfter, "tracked copy source");
                        EnsureStableSingleLinkFile(destinationWritten, destinationAfter, "copy destination");
                        if (!ConstantTimeEquals(sourceDigest, destinationDigest))
                        {
                            throw new IOException("Tracked single-link copy did not preserve exact file bytes.");
                        }
                        if (captureDestination)
                        {
                            destinationStream.Position = 0;
                            using (MemoryStream captured = new MemoryStream())
                            {
                                destinationStream.CopyTo(captured);
                                Identity destinationCaptured = GetIdentity(
                                    destination,
                                    "re-identify a captured copy destination");
                                EnsureStableSingleLinkFile(
                                    destinationWritten,
                                    destinationCaptured,
                                    "captured copy destination");
                                return captured.ToArray();
                            }
                        }
                    }
                    finally
                    {
                        // DuplicateHandle shares the retained source handle's
                        // file pointer. Leave it rewound so later exact-handle
                        // identity/hash checks remain independent of this copy.
                        sourceStream.Position = 0;
                    }
                }
            }
            return null;
        }

        public static void DeleteTrackedTree(SafeFileHandle trackedRoot)
        {
            if (trackedRoot == null || trackedRoot.IsInvalid || trackedRoot.IsClosed)
            {
                throw new InvalidOperationException("The tracked release-root handle is unavailable.");
            }

            Identity cleanupIdentity = GetIdentity(trackedRoot, "re-identify the tracked release root");
            if (!cleanupIdentity.IsDirectory || cleanupIdentity.IsReparsePoint ||
                cleanupIdentity.NumberOfLinks != 1)
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

            if (!beforeTraversal.IsDirectory && beforeTraversal.NumberOfLinks != 1)
            {
                throw new IOException("Refusing cleanup of a multiply linked private release file.");
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
            if (!beforeDelete.IsDirectory && beforeDelete.NumberOfLinks != 1)
            {
                throw new IOException("Refusing to mutate a multiply linked private release file.");
            }
            ClearReadOnly(handle, beforeDelete.Attributes);
            Identity afterAttributeUpdate = GetIdentity(
                handle,
                "verify an entry after its read-only attribute update");
            if (!expectedIdentity.SameObjectAndKind(afterAttributeUpdate))
            {
                throw new IOException("A release-tree entry changed identity before disposition.");
            }
            if (!afterAttributeUpdate.IsDirectory && afterAttributeUpdate.NumberOfLinks != 1)
            {
                throw new IOException("A private release file gained another hard link before deletion.");
            }
            MarkDelete(handle);
        }

        private static SafeFileHandle OpenChildNoFollow(SafeFileHandle parent, string name)
        {
            return OpenChildNoFollow(
                parent,
                name,
                DeleteAccess | FileListDirectory | FileReadAttributes |
                    FileWriteAttributes | Synchronize,
                FileShareRead);
        }

        private static SafeFileHandle OpenChildNoFollow(
            SafeFileHandle parent,
            string name,
            uint desiredAccess,
            uint shareAccess)
        {
            if (parent == null || parent.IsInvalid || parent.IsClosed)
            {
                throw new InvalidOperationException("Verified parent handle is unavailable.");
            }
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
                    desiredAccess,
                    ref attributes,
                    out statusBlock,
                    shareAccess,
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
                Marshal.SizeOf(typeof(IoStatusBlock)) != 16 ||
                Marshal.OffsetOf(
                    typeof(FileRenameInformationPrefix),
                    "RootDirectory").ToInt32() != FileRenameRootDirectoryOffset ||
                Marshal.OffsetOf(
                    typeof(FileRenameInformationPrefix),
                    "FileNameLength").ToInt32() != FileRenameNameLengthOffset ||
                FileRenameNameLengthOffset + sizeof(uint) != FileRenameNameOffset)
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

        private static void EnsureStableSingleLinkFile(
            Identity before,
            Identity after,
            string description)
        {
            if (!before.SameObjectAndKind(after) || before.IsDirectory || before.IsReparsePoint ||
                before.NumberOfLinks != 1 || after.NumberOfLinks != 1 ||
                before.FileSize != after.FileSize)
            {
                throw new IOException("A regular single-link " + description + " changed during use.");
            }
        }

        private static void EnsureSameSingleLinkFileIdentity(
            Identity before,
            Identity after,
            string description)
        {
            if (!before.SameObjectAndKind(after) || before.IsDirectory || before.IsReparsePoint ||
                before.NumberOfLinks != 1 || after.NumberOfLinks != 1)
            {
                throw new IOException("A regular single-link " + description + " changed identity.");
            }
        }

        private static bool ConstantTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length)
            {
                return false;
            }
            int difference = 0;
            for (int index = 0; index < left.Length; index++)
            {
                difference |= left[index] ^ right[index];
            }
            return difference == 0;
        }

        private static string ToLowerHex(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }
            StringBuilder builder = new StringBuilder(value.Length * 2);
            foreach (byte item in value)
            {
                builder.Append(item.ToString("x2"));
            }
            return builder.ToString();
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
    Assert-CodeDomCompilerIntegrity
}

function New-ReleaseRoot {
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    Assert-NoReparsePointComponents $temporaryRoot
    $leaf = "waal-windows-release-" + [Guid]::NewGuid().ToString("N")
    $candidate = Microsoft.PowerShell.Management\Join-Path $temporaryRoot $leaf
    $compilerTemp = Microsoft.PowerShell.Management\Join-Path `
        $temporaryRoot `
        ("waal-cleanup-compiler-" + [Guid]::NewGuid().ToString("N"))
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

    # The CodeDom helper is compiled only after packager/commit attestation and
    # before the real release root exists. A new sentinel that denies write and
    # delete sharing is held throughout compilation; after the helper loads,
    # handle-relative reopening must prove that TEMP/TMP still names the
    # directory containing that exact sentinel before cleanup is allowed.
    $compilerSentinelName = ".compiler-anchor"
    $compilerSentinelPath = Microsoft.PowerShell.Management\Join-Path `
        $compilerTemp `
        $compilerSentinelName
    $compilerDirectoryCreated = $false
    $compilerSentinel = $null
    $compilerDirectoryHandle = $null
    $compilerAnchorVerified = $false
    try {
        $compilerDirectory = [IO.Directory]::CreateDirectory($compilerTemp, $acl)
        $compilerDirectoryCreated = $true
        Assert-RealDirectory $compilerTemp
        $compilerAcl = $compilerDirectory.GetAccessControl(
            [Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Access
        )
        $compilerRules = @($compilerAcl.GetAccessRules(
            $true,
            $false,
            [Security.Principal.SecurityIdentifier]
        ))
        if (-not $compilerAcl.AreAccessRulesProtected -or
            -not $compilerAcl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($identity.User) -or
            $compilerRules.Count -ne 2) {
            throw "Cleanup-helper compiler temp owner or ACL protection could not be established."
        }
        foreach ($rule in $compilerRules) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                (-not $rule.IdentityReference.Equals($identity.User) -and
                 -not $rule.IdentityReference.Equals($systemSid))) {
                throw "Cleanup-helper compiler temp contains an unexpected access-control entry."
            }
        }
        $compilerSentinel = [IO.FileStream]::new(
            $compilerSentinelPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::Read,
            4096,
            [IO.FileOptions]::DeleteOnClose
        )
        $anchorBytes = [Text.Encoding]::ASCII.GetBytes([Guid]::NewGuid().ToString("N"))
        $compilerSentinel.Write($anchorBytes, 0, $anchorBytes.Length)
        $compilerSentinel.Flush($true)
        Initialize-ReleaseTreeCleanup -PrivateCompilerTemp $compilerTemp
        $compilerDirectoryHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackRoot(
            $compilerTemp
        )
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedChild(
            $compilerDirectoryHandle,
            $compilerSentinelName,
            $compilerSentinel.SafeFileHandle
        )
        $compilerAnchorVerified = $true
    }
    finally {
        if ($compilerSentinel) {
            try {
                $compilerSentinel.Dispose()
            }
            catch {
                Microsoft.PowerShell.Utility\Write-Warning `
                    "Unable to close cleanup compiler sentinel: $($_.Exception.Message)"
            }
        }
        try {
            if ($compilerDirectoryHandle -and $compilerAnchorVerified) {
                [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::DeleteTrackedTree(
                    $compilerDirectoryHandle
                )
                $compilerDirectoryHandle.Dispose()
                $compilerDirectoryHandle = $null
            }
            elseif ($compilerDirectoryHandle) {
                $compilerDirectoryHandle.Dispose()
                $compilerDirectoryHandle = $null
                Microsoft.PowerShell.Utility\Write-Warning `
                    "Leaving unverified cleanup compiler directory in place: $compilerTemp"
            }
            elseif ($compilerDirectoryCreated -and
                [IO.Directory]::Exists($compilerTemp) -and
                ("Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner" -as [type])) {
                # The helper may have loaded before a later integrity or
                # handle-setup check failed. Recover a native root handle and
                # still perform non-following recursive cleanup.
                $compilerDirectoryHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackRoot(
                    $compilerTemp
                )
                [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::DeleteTrackedTree(
                    $compilerDirectoryHandle
                )
                $compilerDirectoryHandle.Dispose()
                $compilerDirectoryHandle = $null
            }
            elseif ($compilerDirectoryCreated -and
                [IO.Directory]::Exists($compilerTemp) -and
                [IO.Directory]::GetFileSystemEntries($compilerTemp).Length -eq 0) {
                # Before the native helper exists, use only non-recursive
                # deletion of an empty, cryptographically named directory.
                # Never path-traverse compiler output after a helper failure.
                [IO.Directory]::Delete($compilerTemp, $false)
            }
            elseif ($compilerDirectoryCreated -and [IO.Directory]::Exists($compilerTemp)) {
                Microsoft.PowerShell.Utility\Write-Warning `
                    "Leaving non-empty unverified cleanup compiler directory in place: $compilerTemp"
            }
        }
        catch {
            Microsoft.PowerShell.Utility\Write-Warning "Unable to remove cleanup compiler temp safely: $($_.Exception.Message)"
            if ($compilerDirectoryHandle -and -not $compilerDirectoryHandle.IsClosed) {
                $compilerDirectoryHandle.Dispose()
            }
        }
    }

    $securityDescriptor = $acl.GetSecurityDescriptorBinaryForm()
    $handles = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::CreateTrackedRoot(
        $temporaryRoot,
        $leaf,
        $securityDescriptor
    )
    if ($null -eq $handles -or $handles.Count -ne 2) {
        throw "Native release-root creation did not return its pinned parent and root handles."
    }
    $script:ReleaseRootParentHandle = $handles[0]
    $script:ReleaseRootHandle = $handles[1]
    $script:ReleaseRoot = $candidate
    Assert-RealDirectory $candidate
    $created = Microsoft.PowerShell.Management\Get-Item -LiteralPath $candidate -Force
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
    return $candidate
}

function Remove-ReleaseRootSafely {
    if (-not $ReleaseRootHandle) {
        if ($ReleaseRoot) {
            Microsoft.PowerShell.Utility\Write-Warning "The private release root has no tracked cleanup handle; leaving it in place: $ReleaseRoot"
        }
        $untrackedCleanupFailure = $null
        try {
            if ($ReleaseSourceHandle -and -not $ReleaseSourceHandle.IsClosed) {
                $ReleaseSourceHandle.Dispose()
            }
        }
        catch {
            $untrackedCleanupFailure = $_
        }
        $script:ReleaseSourceHandle = $null
        try {
            if ($ReleaseRootParentHandle -and -not $ReleaseRootParentHandle.IsClosed) {
                $ReleaseRootParentHandle.Dispose()
            }
        }
        catch {
            if (-not $untrackedCleanupFailure) { $untrackedCleanupFailure = $_ }
            else {
                Microsoft.PowerShell.Utility\Write-Warning `
                    "Release-root parent-handle disposal also failed: $($_.Exception.Message)"
            }
        }
        $script:ReleaseRootParentHandle = $null
        if ($untrackedCleanupFailure) { throw $untrackedCleanupFailure }
        return
    }
    try {
        $cleanupFailure = $null
        if ($ReleaseSourceHandle -and -not $ReleaseSourceHandle.IsClosed) {
            try {
                [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertPhysicalDirectory(
                    $ReleaseSourceHandle
                )
            }
            catch {
                $cleanupFailure = $_
            }
            finally {
                try {
                    $ReleaseSourceHandle.Dispose()
                }
                catch {
                    if (-not $cleanupFailure) { $cleanupFailure = $_ }
                    else {
                        Microsoft.PowerShell.Utility\Write-Warning `
                            "Release-source handle disposal also failed: $($_.Exception.Message)"
                    }
                }
                $script:ReleaseSourceHandle = $null
            }
        }
        try {
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::DeleteTrackedTree(
                $ReleaseRootHandle
            )
        }
        catch {
            if (-not $cleanupFailure) { $cleanupFailure = $_ }
            else {
                Microsoft.PowerShell.Utility\Write-Warning `
                    "Tracked release-root deletion also failed: $($_.Exception.Message)"
            }
        }
        if ($cleanupFailure) { throw $cleanupFailure }
    }
    finally {
        try {
            if ($ReleaseRootHandle -and -not $ReleaseRootHandle.IsClosed) {
                $ReleaseRootHandle.Dispose()
            }
        }
        catch {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Release-root handle disposal failed: $($_.Exception.Message)"
        }
        $script:ReleaseRootHandle = $null
        try {
            if ($ReleaseRootParentHandle -and -not $ReleaseRootParentHandle.IsClosed) {
                $ReleaseRootParentHandle.Dispose()
            }
        }
        catch {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Release-root parent-handle disposal failed: $($_.Exception.Message)"
        }
        $script:ReleaseRootParentHandle = $null
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

function Get-SingleLinkGitBlobSha1 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashRegularSingleLinkGitBlobSha1($Path)
}

function Get-GitBlobSha1FromBytes {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    $sha1 = [Security.Cryptography.SHA1]::Create()
    try {
        $header = [Text.Encoding]::ASCII.GetBytes("blob $($Bytes.Length)`0")
        $null = $sha1.TransformBlock($header, 0, $header.Length, $header, 0)
        $null = $sha1.TransformFinalBlock($Bytes, 0, $Bytes.Length)
        return (($sha1.Hash | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
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
            $actual.Add($relativePath, (Get-SingleLinkGitBlobSha1 $item.FullName))
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

function Open-MaterializedReleaseSourceHandles {
    $handles = [System.Collections.Generic.List[object]]::new()
    try {
        $expectedDirectories = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($entry in $ReleaseTreeEntries) {
            $segments = $entry.Path.Split('/')
            for ($segmentCount = 1; $segmentCount -lt $segments.Length; $segmentCount++) {
                $relativeDirectory = ($segments[0..($segmentCount - 1)] -join '/')
                $null = $expectedDirectories.Add($relativeDirectory)
            }
        }
        foreach ($relativeDirectory in @($expectedDirectories | Microsoft.PowerShell.Utility\Sort-Object)) {
            $path = Microsoft.PowerShell.Management\Join-Path `
                $ReleaseSourceDir `
                ($relativeDirectory.Replace('/', '\'))
            $null = $handles.Add([PSCustomObject]@{
                Handle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackRoot(
                    $path
                )
                Directory = $true
                Path = $path
                RelativePath = $relativeDirectory
                ExpectedBlob = $null
            })
        }
        foreach ($entry in $ReleaseTreeEntries) {
            $path = Microsoft.PowerShell.Management\Join-Path `
                $ReleaseSourceDir `
                ($entry.Path.Replace('/', '\'))
            $null = $handles.Add([PSCustomObject]@{
                Handle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenRegularSingleLink($path)
                Directory = $false
                Path = $path
                RelativePath = $entry.Path
                ExpectedBlob = $entry.Blob
            })
        }
        $result = $handles.ToArray()
        Assert-MaterializedReleaseSourceHandleState $result
        return $result
    }
    catch {
        foreach ($state in $handles) {
            $state.Handle.Dispose()
        }
        throw
    }
}

function Assert-MaterializedReleaseSourceHandleState {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Handles)

    $expectedFiles = [System.Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal
    )
    $expectedDirectories = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($entry in $ReleaseTreeEntries) {
        $expectedFiles.Add($entry.Path, $entry.Blob)
        $segments = $entry.Path.Split('/')
        for ($segmentCount = 1; $segmentCount -lt $segments.Length; $segmentCount++) {
            $relativeDirectory = ($segments[0..($segmentCount - 1)] -join '/')
            $null = $expectedDirectories.Add($relativeDirectory)
        }
    }

    if ($Handles.Count -ne ($expectedFiles.Count + $expectedDirectories.Count)) {
        throw "Tracked release source handle count does not match the complete Git tree."
    }
    $seenFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenDirectories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($state in $Handles) {
        $relativePath = [string]$state.RelativePath
        if ([string]::IsNullOrEmpty($relativePath)) {
            throw "Tracked release source handle is missing its Git-relative path."
        }
        $expectedPath = Microsoft.PowerShell.Management\Join-Path `
            $ReleaseSourceDir `
            ($relativePath.Replace('/', '\'))
        if ((Normalize-Path ([string]$state.Path)) -cne (Normalize-Path $expectedPath)) {
            throw "Tracked release source handle path does not match its Git-relative path: $relativePath"
        }
        if ($state.Directory) {
            if (-not $expectedDirectories.Contains($relativePath) -or
                -not $seenDirectories.Add($relativePath) -or
                $null -ne $state.ExpectedBlob) {
                throw "Tracked release source directory set does not match the complete Git tree: $relativePath"
            }
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertPhysicalDirectory(
                $state.Handle
            )
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedDirectoryPath(
                $state.Path,
                $state.Handle
            )
        }
        else {
            if (-not $expectedFiles.ContainsKey($relativePath) -or
                -not $seenFiles.Add($relativePath) -or
                ([string]$state.ExpectedBlob) -cne $expectedFiles[$relativePath]) {
                throw "Tracked release source file set does not match the complete Git tree: $relativePath"
            }
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertRegularSingleLink(
                $state.Handle
            )
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularPath(
                $state.Path,
                $state.Handle
            )
            $handleBlob = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkGitBlobSha1(
                $state.Handle
            )
            if ($handleBlob -cne $expectedFiles[$relativePath]) {
                throw "Tracked release source handle does not match its exact Git blob: $relativePath"
            }
        }
    }
    if ($seenFiles.Count -ne $expectedFiles.Count -or
        $seenDirectories.Count -ne $expectedDirectories.Count) {
        throw "Tracked release source handles do not cover the complete Git tree."
    }

    # This pathname walk rejects missing and additional files while the exact
    # expected file objects above are still pinned against writes/replacement.
    Assert-MaterializedReleaseSource
}

function Assert-AndCloseMaterializedReleaseSourceHandles {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Handles)

    $failure = $null
    try {
        Assert-MaterializedReleaseSourceHandleState $Handles
    }
    catch {
        $failure = $_
    }
    foreach ($state in $Handles) {
        $stateFailure = $null
        try {
            $state.Handle.Dispose()
        }
        catch {
            if (-not $stateFailure) { $stateFailure = $_ }
        }
        if ($stateFailure -and -not $failure) { $failure = $stateFailure }
    }
    if ($failure) { throw $failure }
}

function Copy-CommittedReleasePayloadFiles {
    param([Parameter(Mandatory = $true)][string]$DestinationDirectory)

    Assert-RealDirectory $DestinationDirectory
    $fileNames = @("README.md", "LICENSE", "config.example.json")
    $states = [System.Collections.Generic.List[object]]::new()
    $expectedHashes = [ordered]@{}
    $operationFailure = $null
    $closeFailures = [System.Collections.Generic.List[object]]::new()
    $destinationHandles = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($fileName in $fileNames) {
            $matches = @($ReleaseTreeEntries | Microsoft.PowerShell.Core\Where-Object {
                $_.Path -ceq $fileName
            })
            if ($matches.Count -ne 1) {
                throw "Captured release commit must contain exactly one payload blob: $fileName"
            }
            $sourcePath = Microsoft.PowerShell.Management\Join-Path `
                $ReleaseSourceDir `
                $fileName
            $committedBytes = Invoke-SanitizedGit @(
                "cat-file", "blob", ([string]$matches[0].Blob)
            ) -RawBytes
            if ($null -eq $committedBytes -or $committedBytes.GetType() -ne [byte[]] -or
                (Get-GitBlobSha1FromBytes $committedBytes) -cne ([string]$matches[0].Blob)) {
                throw "Pinned Git did not return the exact committed payload blob: $fileName"
            }
            $committedSha256 = Get-ByteArraySha256 $committedBytes
            $committedBytes = $null
            $handle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenRegularSingleLink(
                $sourcePath
            )
            $state = [PSCustomObject]@{
                Name = $fileName
                Path = $sourcePath
                ExpectedBlob = [string]$matches[0].Blob
                ExpectedSha256 = $committedSha256
                SourceSha256 = $null
                Handle = $handle
            }
            $null = $states.Add($state)
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularPath(
                $state.Path,
                $state.Handle
            )
            $sourceBlob = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkGitBlobSha1(
                $state.Handle
            )
            if ($sourceBlob -cne $state.ExpectedBlob) {
                throw "Payload source handle does not match its blob in captured commit ${ReleaseGitCommit}: $fileName"
            }
            $state.SourceSha256 = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
                $state.Handle
            )
            if ($state.SourceSha256 -cne $state.ExpectedSha256) {
                throw "Payload source bytes differ from the exact blob returned by pinned Git: $fileName"
            }
            $expectedHashes[$fileName] = $state.ExpectedSha256
        }

        # Reject additions/removals elsewhere in the snapshot while all three
        # exact payload objects remain pinned without write/delete sharing.
        Assert-MaterializedReleaseSource
        foreach ($state in $states) {
            $destinationPath = Microsoft.PowerShell.Management\Join-Path `
                $DestinationDirectory `
                $state.Name
            Copy-SingleLinkFileFromHandle $state.Handle $destinationPath
            if ((Get-SingleLinkGitBlobSha1 $destinationPath) -cne $state.ExpectedBlob) {
                throw "Copied payload does not match its exact committed Git blob: $($state.Name)"
            }
            if ((Get-SingleLinkSha256 $destinationPath) -cne $state.SourceSha256) {
                throw "Copied payload SHA-256 does not match its retained source handle: $($state.Name)"
            }
            if ((Get-SingleLinkSha256 $destinationPath) -cne $state.ExpectedSha256) {
                throw "Copied payload SHA-256 does not match the exact committed Git bytes: $($state.Name)"
            }
            $destinationHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenRegularSingleLink(
                $destinationPath
            )
            $null = $destinationHandles.Add([PSCustomObject]@{
                Name = $state.Name
                Handle = $destinationHandle
                ExpectedHash = $state.ExpectedSha256
            })
        }

        foreach ($state in $states) {
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularPath(
                $state.Path,
                $state.Handle
            )
            if ([Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkGitBlobSha1(
                $state.Handle
            ) -cne $state.ExpectedBlob) {
                throw "Committed payload source changed during handle-bound copy: $($state.Name)"
            }
            if ([Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
                $state.Handle
            ) -cne $state.SourceSha256) {
                throw "Committed payload source SHA-256 changed during handle-bound copy: $($state.Name)"
            }
        }
        Assert-MaterializedReleaseSource
    }
    catch {
        $operationFailure = $_
    }
    finally {
        foreach ($state in $states) {
            try {
                if ($state.Handle -and -not $state.Handle.IsClosed) {
                    $state.Handle.Dispose()
                }
            }
            catch {
                $null = $closeFailures.Add($_)
            }
        }
    }
    if ($operationFailure -or $closeFailures.Count -gt 0 -or
        $expectedHashes.Count -ne $fileNames.Count) {
        foreach ($destinationState in $destinationHandles) {
            try {
                if ($destinationState.Handle -and -not $destinationState.Handle.IsClosed) {
                    $destinationState.Handle.Dispose()
                }
            }
            catch {
                $null = $closeFailures.Add($_)
            }
        }
    }
    if ($operationFailure) {
        foreach ($closeFailure in $closeFailures) {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Payload-source handle cleanup also failed: $($closeFailure.Exception.Message)"
        }
        throw $operationFailure
    }
    if ($closeFailures.Count -gt 0) {
        for ($index = 1; $index -lt $closeFailures.Count; $index++) {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Additional payload-source handle cleanup failure: $($closeFailures[$index].Exception.Message)"
        }
        throw $closeFailures[0]
    }
    if ($expectedHashes.Count -ne $fileNames.Count) {
        throw "Committed payload hash set is incomplete."
    }
    return [PSCustomObject]@{
        ExpectedHashes = $expectedHashes
        Handles = $destinationHandles.ToArray()
    }
}

function Assert-CommittedReleasePayloadHashes {
    param(
        [Parameter(Mandatory = $true)]$ActualHashes,
        [Parameter(Mandatory = $true)]$ExpectedHashes
    )

    $fileNames = @("README.md", "LICENSE", "config.example.json")
    if ($ExpectedHashes.Count -ne $fileNames.Count) {
        throw "Expected committed payload hash set is incomplete."
    }
    foreach ($fileName in $fileNames) {
        if (-not $ActualHashes.Contains($fileName) -or
            -not $ExpectedHashes.Contains($fileName) -or
            $ActualHashes[$fileName] -cne $ExpectedHashes[$fileName]) {
            throw "Distribution payload is not the exact file from captured commit ${ReleaseGitCommit}: $fileName"
        }
    }
}

function Assert-StagedPayloadHandles {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]$Handles,
        [Parameter(Mandatory = $true)]$ExpectedHashes
    )

    $fileNames = @("README.md", "LICENSE", "config.example.json")
    if ($Handles.Count -ne $fileNames.Count -or $ExpectedHashes.Count -ne $fileNames.Count) {
        throw "Staged committed-payload handle set is incomplete."
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($state in $Handles) {
        if ($state.Name -cnotin $fileNames -or -not $seen.Add($state.Name) -or
            -not $ExpectedHashes.Contains($state.Name) -or
            $state.ExpectedHash -cne $ExpectedHashes[$state.Name]) {
            throw "Staged committed-payload handle set is invalid: $($state.Name)"
        }
        $path = Microsoft.PowerShell.Management\Join-Path $Directory $state.Name
        try {
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularPath(
                $path,
                $state.Handle
            )
        }
        catch {
            throw "Staged committed payload path changed identity while retained: $($state.Name)"
        }
        $handleHash = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
            $state.Handle
        )
        if ($handleHash -cne $ExpectedHashes[$state.Name]) {
            throw "Exact staged payload handle no longer matches its committed bytes: $($state.Name)"
        }
    }
}

function Close-StagedPayloadHandles {
    $failure = $null
    foreach ($state in $StagedPayloadHandles) {
        try {
            if ($state.Handle -and -not $state.Handle.IsClosed) { $state.Handle.Dispose() }
        }
        catch {
            if (-not $failure) { $failure = $_ }
        }
    }
    $script:StagedPayloadHandles = @()
    if ($failure) { throw $failure }
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
    $script:ReleaseSourceHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackRoot(
        $ReleaseSourceDir
    )
    $null = Invoke-SanitizedGit @(
        "-C", $RootDir, "archive", "--format=tar", "--output=$archivePath", $ReleaseGitCommit
    )
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $archivePath -PathType Leaf) -or
        (((Microsoft.PowerShell.Management\Get-Item -LiteralPath $archivePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Pinned Git did not create a regular source archive."
    }
    $archiveHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenRegularSingleLink($archivePath)
    try {
        $archiveSha256 = Get-SingleLinkSha256 $archivePath
        if ((Normalize-Path $TarPath) -ne (Normalize-Path $Tar)) {
            throw "Release source extraction must use the pinned tar executable."
        }
        Invoke-SanitizedTar @("-xf", $archivePath, "-C", $ReleaseSourceDir)
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertRegularSingleLink($archiveHandle)
        if ((Get-SingleLinkSha256 $archivePath) -cne $archiveSha256) {
            throw "Pinned Git source archive changed while tar materialized it."
        }
    }
    finally {
        $archiveHandle.Dispose()
    }
    Assert-MaterializedReleaseSource
}

function Get-CommittedReleaseTreeEntries {
    param([Parameter(Mandatory = $true)][string]$GitPath)

    Assert-CommitContainsOnlyRegularFiles $GitPath
}

function Assert-ExecutingPackagerMatchesReleaseCommit {
    # All PowerShell packaging helpers are functions in this file; the script
    # intentionally neither dot-sources repository files nor imports a
    # repository module. Binding this parsed source therefore binds the complete
    # PowerShell packager logic to the captured commit/tree.
    $relativePath = "script/build_windows_dist.ps1"
    $matchingEntry = $null
    $matchingCount = 0
    foreach ($entry in $ReleaseTreeEntries) {
        if ($entry.Path -ceq $relativePath) {
            $matchingEntry = $entry
            $matchingCount++
        }
    }
    if ($matchingCount -ne 1 -or -not $matchingEntry) {
        throw "Captured release commit must contain exactly one tracked Windows packager."
    }

    # Capture exact blob bytes directly from the pinned Git object database.
    # PowerShell text redirection is intentionally avoided because Windows
    # PowerShell 5.1 would decode and re-encode stdout. One raw byte buffer drives
    # both the Git-object check and the AST comparison.
    $snapshotBytes = Invoke-SanitizedGit @("cat-file", "blob", $matchingEntry.Blob) -RawBytes
    if ($null -eq $snapshotBytes -or $snapshotBytes.GetType() -ne [byte[]]) {
        throw "Pinned Git did not return one exact byte buffer for the committed Windows packager."
    }
    if ((Get-GitBlobSha1FromBytes $snapshotBytes) -cne $matchingEntry.Blob) {
        throw "Captured Windows packager does not match its commit blob."
    }

    for ($index = 0; $index -lt $snapshotBytes.Length; $index++) {
        if ($snapshotBytes[$index] -gt 0x7f) {
            throw "Captured Windows packager must be ASCII without a BOM so Windows PowerShell 5.1 decoding is unambiguous."
        }
    }
    $snapshotSource = [Text.Encoding]::ASCII.GetString($snapshotBytes)
    $snapshotBytes = $null
    $tokens = $null
    $parseErrors = $null
    $snapshotAst = [System.Management.Automation.Language.Parser]::ParseInput(
        $snapshotSource,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -ne 0) {
        throw "Captured Windows packager cannot be parsed by the executing PowerShell engine."
    }
    $snapshotSha256 = Get-PackagerSourceSha256 $snapshotAst.Extent.Text
    $snapshotSource = $null
    if ($snapshotSha256 -cne $ExecutingPackagerSourceSha256) {
        throw "Executing Windows packager logic does not match the captured release commit; the checkout changed while packaging started."
    }
    if ($snapshotSha256 -cne $PackagerSourceSha256) {
        throw "Windows packager source digest changed after bootstrap."
    }
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

function Resolve-AndVerify-SourceTools {
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
    }
    else {
        $gitInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_GIT_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_GIT_SHA256" "Git"
        $gitRootInput = Resolve-ExplicitPinnedDirectory "WAAL_WINDOWS_RELEASE_GIT_ROOT" "WAAL_WINDOWS_RELEASE_EXPECTED_GIT_ROOT_SHA256" "Git runtime tree"
        $tarInput = Resolve-ExplicitPinnedExecutable "WAAL_WINDOWS_RELEASE_TAR_PATH" "WAAL_WINDOWS_RELEASE_EXPECTED_TAR_SHA256" "tar"
    }

    $script:Git = $gitInput.Path
    $script:GitRoot = $gitRootInput.Path
    $script:Tar = $tarInput.Path
    $script:GitSha256 = $gitInput.Hash
    $script:GitRootSha256 = $gitRootInput.Hash
    $script:TarSha256 = $tarInput.Hash
    Lock-SourceToolInputs
    Assert-ReleaseSourceToolIntegrity
}

function Resolve-AndVerify-Toolchain {
    # The source snapshot and executing packager must already be attested before
    # this function can resolve or execute rustup, Cargo, rustc, or native build
    # tools. Rechecking only the source tools here keeps that trust boundary
    # explicit and fails if Git/tar changed after attestation.
    Assert-ReleaseSourceToolIntegrity
    if ($Development) {
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

    $script:Cargo = $cargoInput.Path
    $script:Rustc = $rustcInput.Path
    $script:Compiler = $compilerInput.Path
    $script:Librarian = $librarianInput.Path
    $script:Linker = $linkInput.Path
    $script:CompilerBin = $compilerBinInput.Path
    $script:ResourceCompiler = $rcInput.Path
    $script:SdkBin = $sdkBinInput.Path
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
        # Resolve every publishable tool directory and retain non-write-sharing
        # handles before executing Cargo, rustc, or any native tool for version
        # discovery. A hash-before-exec check alone leaves an A-to-B-to-A window.
        $sysrootInput = Resolve-ExplicitPinnedDirectory "WAAL_RELEASE_RUST_SYSROOT" "WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256" "Rust sysroot"
        $script:RustSysroot = $sysrootInput.Path
        $script:RustSysrootSha256 = $sysrootInput.Hash
        Assert-PathWithinPinnedDirectory $Cargo $RustSysroot "Cargo"
        Assert-PathWithinPinnedDirectory $Rustc $RustSysroot "rustc"
        foreach ($nativeTool in @($Compiler, $Librarian, $Linker)) {
            if ((Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $nativeTool)) -ne
                (Normalize-Path $CompilerBin)) {
                throw "cl.exe, lib.exe, and link.exe must all come from the pinned MSVC compiler bin directory."
            }
        }
        Assert-PathWithinPinnedDirectory $ResourceCompiler $SdkBin "rc.exe"
        Assert-PathWithinPinnedDirectory $SignTool $SdkBin "signtool.exe"
        $libState = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_LIB" "WAAL_WINDOWS_RELEASE_EXPECTED_LIB_SHA256" $AmbientLib
        $includeState = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_INCLUDE" "WAAL_WINDOWS_RELEASE_EXPECTED_INCLUDE_SHA256" $AmbientInclude
        $libPathState = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_LIBPATH" "WAAL_WINDOWS_RELEASE_EXPECTED_LIBPATH_SHA256" $AmbientLibPath
        $script:TrustedLib = $libState.Value
        $script:TrustedInclude = $includeState.Value
        $script:TrustedLibPath = $libPathState.Value
        $script:TrustedLibSha256 = $libState.Hash
        $script:TrustedIncludeSha256 = $includeState.Hash
        $script:TrustedLibPathSha256 = $libPathState.Hash
        Lock-ToolchainDirectories
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
    $reportedSysroot = Invoke-Captured $Rustc @("--print", "sysroot")
    if ($Development) {
        Assert-NoReparsePointComponents $reportedSysroot
        $script:RustSysroot = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $reportedSysroot -Force).FullName
        $script:RustSysrootSha256 = Get-DirectoryTreeSha256 $RustSysroot
    }
    else {
        if ((Normalize-Path $reportedSysroot) -ne (Normalize-Path $RustSysroot)) {
            throw "WAAL_RELEASE_RUST_SYSROOT does not match the sysroot reported by the pinned rustc."
        }
    }
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath (Microsoft.PowerShell.Management\Join-Path $RustSysroot "lib\rustlib\$TargetTriple\lib") -PathType Container)) {
        throw "Pinned Rust sysroot does not contain the $TargetTriple standard library."
    }
    Assert-PathWithinPinnedDirectory $Cargo $RustSysroot "Cargo"
    Assert-PathWithinPinnedDirectory $Rustc $RustSysroot "rustc"

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

    if ($Development) {
        $libState = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_LIB" "WAAL_WINDOWS_RELEASE_EXPECTED_LIB_SHA256" $AmbientLib
        $includeState = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_INCLUDE" "WAAL_WINDOWS_RELEASE_EXPECTED_INCLUDE_SHA256" $AmbientInclude
        $libPathState = Resolve-TrustedDirectoryList "WAAL_WINDOWS_RELEASE_LIBPATH" "WAAL_WINDOWS_RELEASE_EXPECTED_LIBPATH_SHA256" $AmbientLibPath
        $script:TrustedLib = $libState.Value
        $script:TrustedInclude = $includeState.Value
        $script:TrustedLibPath = $libPathState.Value
        $script:TrustedLibSha256 = $libState.Hash
        $script:TrustedIncludeSha256 = $includeState.Hash
        $script:TrustedLibPathSha256 = $libPathState.Hash
        Lock-ToolchainDirectories
    }
    if (-not (Test-LowerHex $PackagerSourceSha256 64)) {
        throw "Executing Windows packager source must have an exact lowercase SHA-256 digest."
    }
    $script:ReleaseMaterialsSha256 = Get-OrderedHashAggregate @(
        $PackagerSourceSha256,
        $GitSha256,
        $GitRootSha256,
        $TarSha256,
        $CodeDomCompilerSha256,
        $CodeDomRuntimeSha256,
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

function Assert-ReleaseSourceToolIntegrity {
    Assert-SourceToolLocks
    Assert-NoReparsePointComponents $WindowsDirectory
    Assert-NoReparsePointComponents $WindowsSystemDirectory
    if ((Normalize-Path ([Environment]::SystemDirectory)) -ne (Normalize-Path $WindowsSystemDirectory) -or
        (Normalize-Path (Microsoft.PowerShell.Management\Split-Path -Parent $WindowsSystemDirectory)) -ne (Normalize-Path $WindowsDirectory)) {
        throw "Trusted Windows directory resolution changed during packaging."
    }
    foreach ($tool in @(
        [PSCustomObject]@{ Path = $Git; Hash = $GitSha256; Name = "Git" },
        [PSCustomObject]@{ Path = $Tar; Hash = $TarSha256; Name = "tar" }
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
    Assert-SourceToolLocks
    Assert-PathWithinPinnedDirectory $Git $GitRoot "Git executable"
    if (-not $Development) {
        $expectedPhysicalGit = Microsoft.PowerShell.Management\Join-Path $GitRoot "mingw64\bin\git.exe"
        if ((Normalize-Path $Git) -ne (Normalize-Path $expectedPhysicalGit)) {
            throw "Pinned Git executable is no longer the physical Git-for-Windows backend."
        }
    }
    $reportedGitExecPath = Invoke-SanitizedGit @("--exec-path")
    Assert-PathWithinPinnedDirectory $reportedGitExecPath $GitRoot "Git exec-path"
}

function Assert-ReleaseToolchainIntegrity {
    Assert-ReleaseSourceToolIntegrity
    Assert-CodeDomCompilerIntegrity
    Assert-ToolchainDirectoryLocks
    foreach ($tool in @(
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
    Assert-ToolchainDirectoryLocks
    if (-not (Test-LowerHex $PackagerSourceSha256 64) -or
        $PackagerSourceSha256 -cne $ExecutingPackagerSourceSha256) {
        throw "Executing Windows packager source digest changed after it was pinned."
    }
    $currentMaterialsSha256 = Get-OrderedHashAggregate @(
        $PackagerSourceSha256,
        $GitSha256,
        $GitRootSha256,
        $TarSha256,
        $CodeDomCompilerSha256,
        $CodeDomRuntimeSha256,
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
        [switch]$CaptureOutput,
        [string]$RetainBuiltExecutablePath = "",
        [string]$RetainBuiltUiExecutablePath = "",
        $RetainBuiltExecutableDirectoryHandle = $null
    )

    $retainBuiltExecutables = [bool]$RetainBuiltExecutablePath -or
        [bool]$RetainBuiltUiExecutablePath
    if ($CaptureOutput -and $retainBuiltExecutables) {
        throw "Cargo output capture and executable-handle retention are mutually exclusive."
    }
    if ([bool]$RetainBuiltExecutablePath -ne [bool]$RetainBuiltUiExecutablePath -or
        $retainBuiltExecutables -ne [bool]$RetainBuiltExecutableDirectoryHandle) {
        throw "Cargo executable retention requires both fixed outputs and their exact tracked directory."
    }
    $retainedOutputParent = ""
    $retainedOutputSpecs = @()
    if ($retainBuiltExecutables) {
        $retainedOutputPaths = @(
            $RetainBuiltExecutablePath,
            $RetainBuiltUiExecutablePath
        )
        $expectedOutputLeaves = @(
            "$BinaryName.exe",
            "$UiBinaryName.exe"
        )
        for ($outputIndex = 0; $outputIndex -lt $retainedOutputPaths.Count; $outputIndex++) {
            $retainedOutputPath = $retainedOutputPaths[$outputIndex]
            Assert-AbsoluteLocalPath $retainedOutputPath
            $outputParent = Microsoft.PowerShell.Management\Split-Path `
                -Parent `
                $retainedOutputPath
            if ($outputIndex -eq 0) {
                $retainedOutputParent = $outputParent
            }
            elseif ((Normalize-Path $outputParent) -cne (Normalize-Path $retainedOutputParent)) {
                throw "Cargo executable retention outputs must have the same exact parent directory."
            }
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedDirectoryPath(
                $outputParent,
                $RetainBuiltExecutableDirectoryHandle
            )
            $retainedOutputLeaf = Microsoft.PowerShell.Management\Split-Path `
                -Leaf `
                $retainedOutputPath
            if ($retainedOutputLeaf -cne $expectedOutputLeaves[$outputIndex]) {
                throw "Cargo executable retention received an unexpected output leaf name."
            }
            $retainedOutputSpecs += [PSCustomObject]@{
                Leaf = $retainedOutputLeaf
                Path = $retainedOutputPath
            }
        }
    }
    Assert-NoCargoConfigInAncestors $CargoWorkingDir
    Assert-ReleaseToolchainIntegrity
    $sourceHandles = @()
    $retainedOutputStates = [System.Collections.Generic.List[object]]::new()
    # Only the final optimized two-executable build receives UIAccess. Cargo
    # metadata and test builds stay ordinary processes, while build.rs applies
    # the manifest exclusively to the fixed supervisor binary.
    $windowsUiAccessManifest = if ($retainBuiltExecutables) { "1" } else { "" }
    $existingEnvironment = [Environment]::GetEnvironmentVariables("Process")
    $managedNames = @()
    $captured = $null
    $operationFailure = $null
    $cleanupFailures = [System.Collections.Generic.List[object]]::new()
    $locationPushed = $false
    try {
        $sourceHandles = Open-MaterializedReleaseSourceHandles
        foreach ($entry in $existingEnvironment.GetEnumerator()) {
            if ($entry.Key -match '^(CARGO_|RUST|WAAL_|CC(?:$|_)|CXX(?:$|_)|AR(?:$|_)|RANLIB(?:$|_)|CFLAGS(?:$|_)|CXXFLAGS(?:$|_)|CPPFLAGS(?:$|_)|ARFLAGS(?:$|_)|HOST_(?:CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|CPPFLAGS|ARFLAGS)$|TARGET_(?:CC|CXX|AR|RANLIB|CFLAGS|CXXFLAGS|CPPFLAGS|ARFLAGS)$|CRATE_CC_NO_DEFAULTS$|CC_ENABLE_DEBUG_OUTPUT$|CC_SHELL_ESCAPED_FLAGS$|CC_KNOWN_WRAPPER_CUSTOM$|CXXSTDLIB(?:_STATIC)?$|LDFLAGS$|DYLD_|LIB$|INCLUDE$|LIBPATH$|CL$|_CL_$|LINK$|_LINK_$|RC(?:$|_)|SYSTEMROOT$|WINDIR$|VCINSTALLDIR$|VCToolsInstallDir$|VSINSTALLDIR$|WindowsSdkDir$|UniversalCRTSdkDir$|UCRTVersion$|WindowsSDKVersion$)') {
                $managedNames += [string]$entry.Key
            }
        }
        $managedNames += @("HOME", "USERPROFILE", "TEMP", "TMP", "PATH", "RUSTC", "CARGO_HOME")
        $managedNames = @($managedNames | Microsoft.PowerShell.Utility\Sort-Object -Unique)
        foreach ($name in $managedNames) {
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
            WAAL_WINDOWS_UIACCESS_MANIFEST = $windowsUiAccessManifest
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
        $controlled.WAAL_DEVELOPMENT_RELEASE = "1"
        foreach ($name in $controlled.Keys) {
            if ($name -notin $managedNames) {
                $managedNames += [string]$name
                [Environment]::SetEnvironmentVariable([string]$name, $null, "Process")
            }
        }
        foreach ($entry in $controlled.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable([string]$entry.Key, [string]$entry.Value, "Process")
        }
        Microsoft.PowerShell.Management\Push-Location $CargoWorkingDir
        $locationPushed = $true
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
            if ($retainBuiltExecutables) {
                foreach ($outputSpec in $retainedOutputSpecs) {
                    $retainedOutputHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::LockTrackedBuildOutputAfterBuild(
                        $RetainBuiltExecutableDirectoryHandle,
                        $outputSpec.Leaf
                    )
                    $null = $retainedOutputStates.Add([PSCustomObject]@{
                        Leaf = $outputSpec.Leaf
                        Path = $outputSpec.Path
                        Handle = $retainedOutputHandle
                    })
                    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularChild(
                        $RetainBuiltExecutableDirectoryHandle,
                        $outputSpec.Leaf,
                        $retainedOutputHandle
                    )
                }
            }
        }
    }
    catch {
        $operationFailure = $_
    }
    finally {
        if ($locationPushed) {
            try {
                Microsoft.PowerShell.Management\Pop-Location
            }
            catch {
                $null = $cleanupFailures.Add($_)
            }
            $locationPushed = $false
        }
        foreach ($name in $managedNames) {
            try {
                $restoreValue = $null
                if ($existingEnvironment.Contains($name)) {
                    $restoreValue = [string]$existingEnvironment[$name]
                }
                [Environment]::SetEnvironmentVariable($name, $restoreValue, "Process")
            }
            catch {
                $null = $cleanupFailures.Add($_)
            }
        }
        if ($sourceHandles.Count -gt 0) {
            try {
                Assert-AndCloseMaterializedReleaseSourceHandles $sourceHandles
            }
            catch {
                $null = $cleanupFailures.Add($_)
            }
            $sourceHandles = @()
        }
    }
    if ($operationFailure) {
        foreach ($outputState in $retainedOutputStates) {
            if ($outputState.Handle -and -not $outputState.Handle.IsClosed) {
                $outputState.Handle.Dispose()
            }
        }
        $retainedOutputStates.Clear()
        foreach ($cleanupFailure in $cleanupFailures) {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Cargo cleanup also failed after the primary error: $($cleanupFailure.Exception.Message)"
        }
        throw $operationFailure
    }
    if ($cleanupFailures.Count -gt 0) {
        foreach ($outputState in $retainedOutputStates) {
            if ($outputState.Handle -and -not $outputState.Handle.IsClosed) {
                $outputState.Handle.Dispose()
            }
        }
        $retainedOutputStates.Clear()
        for ($index = 1; $index -lt $cleanupFailures.Count; $index++) {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Additional Cargo cleanup failure: $($cleanupFailures[$index].Exception.Message)"
        }
        throw $cleanupFailures[0]
    }
    try {
        Assert-ReleaseToolchainIntegrity
        if ($retainBuiltExecutables) {
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedDirectoryPath(
                $retainedOutputParent,
                $RetainBuiltExecutableDirectoryHandle
            )
            foreach ($outputState in $retainedOutputStates) {
                [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularChild(
                    $RetainBuiltExecutableDirectoryHandle,
                    $outputState.Leaf,
                    $outputState.Handle
                )
            }
        }
    }
    catch {
        foreach ($outputState in $retainedOutputStates) {
            if ($outputState.Handle -and -not $outputState.Handle.IsClosed) {
                $outputState.Handle.Dispose()
            }
        }
        $retainedOutputStates.Clear()
        throw
    }
    if ($CaptureOutput) { return $captured }
    if ($retainBuiltExecutables) {
        $invalidRetainedOutput = $retainedOutputStates.Count -ne 2
        foreach ($outputState in $retainedOutputStates) {
            if (-not $outputState.Handle -or $outputState.Handle.IsInvalid -or
                $outputState.Handle.IsClosed) {
                $invalidRetainedOutput = $true
            }
        }
        if ($invalidRetainedOutput) {
            foreach ($outputState in $retainedOutputStates) {
                if ($outputState.Handle -and -not $outputState.Handle.IsClosed) {
                    $outputState.Handle.Dispose()
                }
            }
            $retainedOutputStates.Clear()
            throw "Cargo completed without both valid retained executable handles."
        }
        return [PSCustomObject]@{
            ExecutableHandle = $retainedOutputStates[0].Handle
            UiExecutableHandle = $retainedOutputStates[1].Handle
        }
    }
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

# Cargo output is not producer-attributed in this local security context. Treat
# its embedded marker as hostile input: every key must have one unambiguous
# value before the packager relies on the mandatory local-only disclaimers.
function ConvertFrom-ExecutableBuildMetadata {
    param([Parameter(Mandatory = $true)][string]$Metadata)

    $prefix = "WAAL_BUILD_METADATA_V1;"
    if (-not $Metadata.StartsWith($prefix, [StringComparison]::Ordinal) -or
        -not $Metadata.EndsWith(";", [StringComparison]::Ordinal)) {
        throw "Executable build metadata has an invalid envelope."
    }

    $fieldText = $Metadata.Substring(
        $prefix.Length,
        $Metadata.Length - $prefix.Length - 1
    )
    if ([string]::IsNullOrEmpty($fieldText)) {
        throw "Executable build metadata contains no fields."
    }

    $fields = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal
    )
    $allowedFields = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($allowedName in @(
        "artifact-kind", "publishable", "attestation", "producer-attribution",
        "profile", "target-os", "target-arch", "debug-assertions", "debug-fill",
        "dev-tools", "diagnostics-ui", "release-diagnostics", "macos-bundle-id",
        "production-macos-bundle-id", "non-production-macos-identity", "macos-team-id",
        "windows-authenticode-publisher", "windows-authenticode-cert-sha256",
        "source-git-commit", "source-git-tree", "release-cargo-version",
        "release-rustc-version", "release-cargo-sha256", "release-rustc-sha256",
        "release-rust-sysroot-sha256", "release-native-toolchain-sha256",
        "release-materials-sha256"
    )) {
        $null = $allowedFields.Add($allowedName)
    }
    foreach ($component in $fieldText.Split([char]';')) {
        $separator = $component.IndexOf([char]'=')
        if ($separator -le 0) {
            throw "Executable build metadata contains a malformed field."
        }
        $name = $component.Substring(0, $separator)
        $value = $component.Substring($separator + 1)
        if ($name -cnotmatch '^[a-z0-9-]+$') {
            throw "Executable build metadata contains an invalid field name."
        }
        if (-not $allowedFields.Contains($name)) {
            throw "Executable build metadata contains an unknown field: $name"
        }
        if ($fields.ContainsKey($name)) {
            throw "Executable build metadata contains a duplicate field: $name"
        }
        $fields.Add($name, $value)
    }
    return (, $fields)
}

function Require-MetadataField {
    param(
        [Parameter(Mandatory = $true)][Collections.Generic.Dictionary[string,string]]$Metadata,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Expected
    )
    if (-not $Metadata.ContainsKey($Name) -or
        -not [StringComparer]::Ordinal.Equals($Metadata[$Name], $Expected)) {
        throw "Executable build metadata field $Name does not match the expected value."
    }
}

function Assert-ExecutableBuildMetadataValidationSelfTest {
    $valid = "WAAL_BUILD_METADATA_V1;artifact-kind=development;publishable=false;" +
        "attestation=none-local-shared-security-context;" +
        "producer-attribution=unavailable-local-shared-security-context;"
    $parsed = ConvertFrom-ExecutableBuildMetadata $valid
    Require-MetadataField $parsed "publishable" "false"
    Require-MetadataField $parsed "attestation" "none-local-shared-security-context"
    Require-MetadataField $parsed "producer-attribution" "unavailable-local-shared-security-context"

    $adversarial = @(
        "WAAL_BUILD_METADATA_V1;artifact-kind=development;" +
            "attestation=none-local-shared-security-context;" +
            "producer-attribution=unavailable-local-shared-security-context;",
        "WAAL_BUILD_METADATA_V1;artifact-kind=development;publishable=true;" +
            "attestation=none-local-shared-security-context;" +
            "producer-attribution=unavailable-local-shared-security-context;",
        "WAAL_BUILD_METADATA_V1;artifact-kind=development;publishable=false;publishable=true;" +
            "attestation=none-local-shared-security-context;" +
            "producer-attribution=unavailable-local-shared-security-context;",
        "WAAL_BUILD_METADATA_V1;artifact-kind=development;publishable=false;" +
            "attestation=none-local-shared-security-context;" +
            "attestation=authenticated-builder;" +
            "producer-attribution=unavailable-local-shared-security-context;",
        "WAAL_BUILD_METADATA_V1;artifact-kind=development;publishable=false;" +
            "attestation=none-local-shared-security-context;" +
            "producer-attribution=unavailable-local-shared-security-context;" +
            "producer-attribution=authenticated-builder;",
        "WAAL_BUILD_METADATA_V1;artifact-kind=development;publishable=false;" +
            "attestation=none-local-shared-security-context;" +
            "producer-attribution=unavailable-local-shared-security-context;" +
            "authenticated-producer=true;"
    )
    foreach ($candidate in $adversarial) {
        $rejected = $false
        try {
            $candidateFields = ConvertFrom-ExecutableBuildMetadata $candidate
            Require-MetadataField $candidateFields "publishable" "false"
            Require-MetadataField `
                $candidateFields `
                "attestation" `
                "none-local-shared-security-context"
            Require-MetadataField `
                $candidateFields `
                "producer-attribution" `
                "unavailable-local-shared-security-context"
        }
        catch {
            $rejected = $true
        }
        if (-not $rejected) {
            throw "Executable build metadata validation accepted an adversarial disclaimer marker."
        }
    }
}

Assert-ExecutableBuildMetadataValidationSelfTest

function Verify-ExecutableMetadata {
    param([Parameter(Mandatory = $true)][string]$ExecutablePath)

    $bytes = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::ReadRegularSingleLinkBytes(
        $ExecutablePath
    )
    try {
        Verify-ExecutableMetadataBytes $bytes
    }
    finally {
        $bytes = $null
    }
}

function Verify-ExecutableMetadataBytes {
    param([Parameter(Mandatory = $true)][byte[]]$ExecutableBytes)

    if ($ExecutableBytes.Length -eq 0) {
        throw "Executable metadata input must not be empty."
    }
    $ascii = [Text.Encoding]::ASCII.GetString($ExecutableBytes)
    $markers = @($ascii.Split([char]0) | Microsoft.PowerShell.Core\Where-Object { $_.StartsWith("WAAL_BUILD_METADATA_V1;") })
    if ($markers.Count -ne 1) {
        throw "Executable must contain exactly one WAAL build metadata marker; found $($markers.Count)."
    }
    $metadata = ConvertFrom-ExecutableBuildMetadata $markers[0]
    # build.rs emits a fixed 27-field V1 schema. Requiring the exact count in
    # addition to every known value makes any unknown or contradictory claim
    # fail closed, even when all mandatory local-only disclaimers are present.
    if ($metadata.Count -ne 27) {
        throw "Executable build metadata does not match the exact V1 field schema."
    }
    Require-MetadataField $metadata "artifact-kind" "development"
    Require-MetadataField $metadata "publishable" "false"
    Require-MetadataField $metadata "attestation" "none-local-shared-security-context"
    Require-MetadataField $metadata "producer-attribution" "unavailable-local-shared-security-context"
    Require-MetadataField $metadata "profile" "release"
    Require-MetadataField $metadata "target-os" "windows"
    Require-MetadataField $metadata "target-arch" "x86_64"
    Require-MetadataField $metadata "debug-assertions" "false"
    Require-MetadataField $metadata "debug-fill" "false"
    Require-MetadataField $metadata "dev-tools" "false"
    Require-MetadataField $metadata "diagnostics-ui" "false"
    Require-MetadataField $metadata "release-diagnostics" "false"
    Require-MetadataField $metadata "macos-bundle-id" "obcardinal.windows-app-autologin"
    Require-MetadataField $metadata "production-macos-bundle-id" ""
    Require-MetadataField $metadata "non-production-macos-identity" "true"
    Require-MetadataField $metadata "macos-team-id" ""
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

function Get-ByteArraySha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($Bytes)
        return (($digest | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString("x2") }) -join "")
    }
    finally {
        $sha256.Dispose()
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
    foreach ($fileName in @(
        $ExeName, $UiExeName, "README.md", "LICENSE", "config.example.json"
    )) {
        $path = Microsoft.PowerShell.Management\Join-Path $Directory $fileName
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path -PathType Leaf) -or
            (((Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Distribution payload is missing a regular file: $fileName"
        }
        $hashes[$fileName] = Get-SingleLinkSha256 $path
    }
    return $hashes
}

function Get-DistributionPayloadHashes {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $hashes = Get-CoreDistributionPayloadHashes $Directory
    $metadataPath = Microsoft.PowerShell.Management\Join-Path $Directory "BUILD-METADATA.txt"
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadataPath -PathType Leaf) -or
        (((Microsoft.PowerShell.Management\Get-Item -LiteralPath $metadataPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Distribution payload is missing a regular file: BUILD-METADATA.txt"
    }
    $hashes["BUILD-METADATA.txt"] = Get-SingleLinkSha256 $metadataPath
    return $hashes
}

function Get-CompleteDistributionFileHashes {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $hashes = Get-DistributionPayloadHashes $Directory
    $manifestPath = Microsoft.PowerShell.Management\Join-Path $Directory "SHA256SUMS.txt"
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        (((Microsoft.PowerShell.Management\Get-Item -LiteralPath $manifestPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Distribution payload is missing a regular file: SHA256SUMS.txt"
    }
    $hashes["SHA256SUMS.txt"] = Get-SingleLinkSha256 $manifestPath
    return $hashes
}

function Get-Sha256ManifestContent {
    param([Parameter(Mandatory = $true)]$PayloadHashes)

    $lines = foreach ($fileName in @(
        $ExeName, $UiExeName, "README.md", "LICENSE", "config.example.json",
        "BUILD-METADATA.txt"
    )) {
        "$($PayloadHashes[$fileName])  $fileName"
    }
    return (($lines -join "`r`n") + "`r`n")
}

function Assert-WindowsDistribution {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)]$ExpectedPayloadHashes,
        [Parameter(Mandatory = $true)][string]$ExpectedMetadata
    )

    Assert-RealDirectory $Directory
    $expectedNames = @(
        $ExeName, $UiExeName, "README.md", "LICENSE", "config.example.json",
        "SHA256SUMS.txt", "BUILD-METADATA.txt"
    )
    $actualNames = @()
    foreach ($item in Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Directory -Force) {
        if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Distribution contains a directory, link, or reparse point: $($item.Name)"
        }
        Assert-RegularSingleLinkFile $item.FullName
        $actualNames += $item.Name
    }
    $expectedSorted = @($expectedNames | Microsoft.PowerShell.Utility\Sort-Object -CaseSensitive)
    $actualSorted = @($actualNames | Microsoft.PowerShell.Utility\Sort-Object -CaseSensitive)
    if (($expectedSorted -join "`n") -cne ($actualSorted -join "`n")) {
        throw "Distribution file set does not match the expected package contents."
    }

    $executable = Microsoft.PowerShell.Management\Join-Path $Directory $ExeName
    $uiExecutable = Microsoft.PowerShell.Management\Join-Path $Directory $UiExeName
    Verify-ExecutableMetadata $executable
    Verify-ExecutableMetadata $uiExecutable
    $actualPayloadHashes = Get-DistributionPayloadHashes $Directory
    foreach ($fileName in @(
        $ExeName, $UiExeName, "README.md", "LICENSE", "config.example.json",
        "BUILD-METADATA.txt"
    )) {
        if ($actualPayloadHashes[$fileName] -cne $ExpectedPayloadHashes[$fileName]) {
            throw "Distribution payload hash changed during publication: $fileName"
        }
    }
    $expectedManifest = Get-Sha256ManifestContent $ExpectedPayloadHashes
    if ((Read-SingleLinkText (Microsoft.PowerShell.Management\Join-Path $Directory "SHA256SUMS.txt")) -cne $expectedManifest) {
        throw "Distribution SHA256SUMS.txt does not match the complete payload."
    }
    if ((Read-SingleLinkText (Microsoft.PowerShell.Management\Join-Path $Directory "BUILD-METADATA.txt")) -cne $ExpectedMetadata) {
        throw "Distribution BUILD-METADATA.txt does not match the captured informational build metadata."
    }
}

function Open-DistributionPayloadHandles {
    param([Parameter(Mandatory = $true)]$DirectoryHandle)

    $handles = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($fileName in @(
            $ExeName, $UiExeName, "README.md", "LICENSE", "config.example.json",
            "SHA256SUMS.txt", "BUILD-METADATA.txt"
        )) {
            $null = $handles.Add([PSCustomObject]@{
                Name = $fileName
                Handle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenTrackedRegularSingleLinkForRename(
                    $DirectoryHandle,
                    $fileName
                )
            })
        }
        return $handles.ToArray()
    }
    catch {
        foreach ($state in $handles) { $state.Handle.Dispose() }
        throw
    }
}

function Lock-DistributionPayloadHandlesAfterRename {
    param(
        [Parameter(Mandatory = $true)]$DirectoryHandle,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]$Handles
    )

    $locked = [System.Collections.Generic.List[object]]::new()
    $failure = $null
    try {
        foreach ($state in $Handles) {
            $null = $locked.Add([PSCustomObject]@{
                Name = $state.Name
                Handle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::LockTrackedRegularSingleLinkAfterRename(
                    $DirectoryHandle,
                    $state.Name,
                    $state.Handle
                )
            })
        }
    }
    catch {
        $failure = $_
    }
    finally {
        foreach ($state in $Handles) {
            if ($state.Handle -and -not $state.Handle.IsClosed) { $state.Handle.Dispose() }
        }
    }
    if ($failure) {
        foreach ($state in $locked) {
            if ($state.Handle -and -not $state.Handle.IsClosed) { $state.Handle.Dispose() }
        }
        throw $failure
    }
    return $locked.ToArray()
}

function Assert-DistributionPayloadHandles {
    param(
        [Parameter(Mandatory = $true)]$DirectoryHandle,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]$Handles,
        [Parameter(Mandatory = $true)]$ExpectedFileHashes
    )

    $expectedNames = @(
        $ExeName, $UiExeName, "README.md", "LICENSE", "config.example.json",
        "SHA256SUMS.txt", "BUILD-METADATA.txt"
    )
    if ($Handles.Count -ne $expectedNames.Count -or
        $ExpectedFileHashes.Count -ne $expectedNames.Count) {
        throw "Publication must retain exactly seven expected payload identities."
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($state in $Handles) {
        if ($state.Name -cnotin $expectedNames -or -not $seen.Add($state.Name) -or
            -not $ExpectedFileHashes.Contains($state.Name)) {
            throw "Publication payload handles contain an unexpected or duplicate name: $($state.Name)"
        }
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertRegularSingleLink($state.Handle)
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularChild(
            $DirectoryHandle,
            $state.Name,
            $state.Handle
        )
        $handleHash = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
            $state.Handle
        )
        if ($handleHash -cne $ExpectedFileHashes[$state.Name]) {
            throw "Exact publication payload handle has an unexpected SHA-256: $($state.Name)"
        }
    }
    foreach ($expectedName in $expectedNames) {
        if (-not $seen.Contains($expectedName)) {
            throw "Publication payload handle set is missing: $expectedName"
        }
    }
}

function Close-DistributionPayloadHandles {
    $failure = $null
    foreach ($state in $PublicationPayloadHandles) {
        try {
            if ($state.Handle -and -not $state.Handle.IsClosed) { $state.Handle.Dispose() }
        }
        catch {
            if (-not $failure) { $failure = $_ }
        }
    }
    $script:PublicationPayloadHandles = @()
    if ($failure) { throw $failure }
}

function Close-BuiltExecutableHandles {
    $failure = $null
    foreach ($handle in @(
        $BuiltExecutableHandle,
        $BuiltUiExecutableHandle,
        $BuiltExecutableDirectoryHandle
    )) {
        try {
            if ($handle -and -not $handle.IsClosed) { $handle.Dispose() }
        }
        catch {
            if (-not $failure) { $failure = $_ }
        }
    }
    $script:BuiltExecutableHandle = $null
    $script:BuiltUiExecutableHandle = $null
    $script:BuiltExecutableDirectoryHandle = $null
    if ($failure) { throw $failure }
}

function Assert-StagedExecutableHandles {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)][string]$UiExecutablePath
    )

    $states = @(
        [PSCustomObject]@{
            Name = $ExeName
            Path = $ExecutablePath
            Handle = $StagedExecutableHandle
            ExpectedSha256 = $StagedExecutableSha256
        },
        [PSCustomObject]@{
            Name = $UiExeName
            Path = $UiExecutablePath
            Handle = $StagedUiExecutableHandle
            ExpectedSha256 = $StagedUiExecutableSha256
        }
    )
    foreach ($state in $states) {
        if (-not $state.Handle -or $state.Handle.IsInvalid -or
            $state.Handle.IsClosed -or -not (Test-LowerHex $state.ExpectedSha256 64)) {
            throw "Authenticated staged executable handle is unavailable: $($state.Name)"
        }
        try {
            [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularPath(
                $state.Path,
                $state.Handle
            )
        }
        catch {
            throw "Staged executable path changed identity while retained: $($state.Name)"
        }
        $actualHash = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
            $state.Handle
        )
        if ($actualHash -cne $state.ExpectedSha256) {
            throw "Exact staged executable bytes changed while retained: $($state.Name)"
        }
    }
}

function Close-StagedExecutableHandles {
    $failure = $null
    foreach ($handle in @($StagedExecutableHandle, $StagedUiExecutableHandle)) {
        try {
            if ($handle -and -not $handle.IsClosed) {
                $handle.Dispose()
            }
        }
        catch {
            if (-not $failure) { $failure = $_ }
        }
    }
    $script:StagedExecutableHandle = $null
    $script:StagedExecutableSha256 = $null
    $script:StagedUiExecutableHandle = $null
    $script:StagedUiExecutableSha256 = $null
    if ($failure) { throw $failure }
}

function Close-PublicationDirectoryHandles {
    $failure = $null
    foreach ($handle in @(
        $PublicationFinalHandle,
        $PublicationCandidateHandle,
        $PublicationParentHandle
    )) {
        try {
            if ($handle -and -not $handle.IsClosed) { $handle.Dispose() }
        }
        catch {
            if (-not $failure) { $failure = $_ }
        }
    }
    $script:PublicationFinalHandle = $null
    $script:PublicationCandidateHandle = $null
    $script:PublicationParentHandle = $null
    if ($failure) { throw $failure }
}

$primaryFailure = $null
$cleanupFailure = $null
try {
    # Nothing below this point may compile or execute a helper/native build tool
    # until the already-parsed packager has been bound to the exact clean Git
    # commit/tree. Pinned Git is the sole pre-attestation executable.
    Initialize-PreAttestationGitHome
    Resolve-AndVerify-SourceTools
    $sourceState = Get-ReleaseSourceState $Git
    $ReleaseGitCommit = $sourceState.Commit
    $ReleaseGitTree = $sourceState.Tree
    $DistDir = Microsoft.PowerShell.Management\Join-Path $DistRoot "$DistName-$ReleaseGitCommit"
    Assert-ReleaseSourceToolIntegrity
    Get-CommittedReleaseTreeEntries $Git
    Assert-ExecutingPackagerMatchesReleaseCommit
    Assert-ReleaseSourceToolIntegrity

    Resolve-AndLock-CodeDomCompiler
    $ReleaseRoot = New-ReleaseRoot
    Initialize-ReleaseGitHome
    Assert-ReleaseSourceUnchangedBeforeToolchain $Git
    Materialize-ReleaseSource $Git $Tar
    Assert-MaterializedReleaseSource
    Assert-ReleaseSourceToolIntegrity
    Resolve-AndVerify-Toolchain
    Assert-ReleaseToolchainIntegrity
    Prepare-IsolatedBuildEnvironment
    Assert-ToolchainMatchesManifest
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

    Microsoft.PowerShell.Utility\Write-Host "Building optimized unsigned development executables from the captured source snapshot..."
    $targetExeDirectory = Microsoft.PowerShell.Management\Join-Path `
        $BuildTargetDir `
        "$TargetTriple\release"
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $targetExeDirectory) {
        throw "Fresh release output directory unexpectedly exists before Cargo build: $targetExeDirectory"
    }
    Microsoft.PowerShell.Management\New-Item `
        -ItemType Directory `
        -Path $targetExeDirectory | Microsoft.PowerShell.Core\Out-Null
    Assert-RealDirectory $targetExeDirectory
    $BuiltExecutableDirectoryHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackRoot(
        $targetExeDirectory
    )
    $targetExe = Microsoft.PowerShell.Management\Join-Path `
        $targetExeDirectory `
        "$BinaryName.exe"
    $targetUiExe = Microsoft.PowerShell.Management\Join-Path `
        $targetExeDirectory `
        "$UiBinaryName.exe"
    $builtExecutableState = Invoke-SanitizedCargo @(
        "build", "--locked", "--release", "--target", $TargetTriple,
        "--bin", $BinaryName, "--bin", $UiBinaryName,
        "--features", "windows-ui-helper", "--manifest-path", $manifestPath
    ) `
        -RetainBuiltExecutablePath $targetExe `
        -RetainBuiltUiExecutablePath $targetUiExe `
        -RetainBuiltExecutableDirectoryHandle $BuiltExecutableDirectoryHandle
    if (-not $builtExecutableState -or
        -not $builtExecutableState.ExecutableHandle -or
        -not $builtExecutableState.UiExecutableHandle) {
        throw "Cargo did not return both retained build-output states."
    }
    $BuiltExecutableHandle = $builtExecutableState.ExecutableHandle
    $BuiltUiExecutableHandle = $builtExecutableState.UiExecutableHandle
    $builtExecutableState = $null
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularChild(
        $BuiltExecutableDirectoryHandle,
        "$BinaryName.exe",
        $BuiltExecutableHandle
    )
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularChild(
        $BuiltExecutableDirectoryHandle,
        "$UiBinaryName.exe",
        $BuiltUiExecutableHandle
    )
    Assert-ReleaseSourceUnchanged $Git

    $stagedDist = Microsoft.PowerShell.Management\Join-Path $ReleaseRoot $DistName
    Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $stagedDist | Microsoft.PowerShell.Core\Out-Null
    Assert-RealDirectory $stagedDist
    $stagedExe = Microsoft.PowerShell.Management\Join-Path $stagedDist $ExeName
    $stagedUiExe = Microsoft.PowerShell.Management\Join-Path $stagedDist $UiExeName
    $UnsignedExecutableBytes = Copy-SingleLinkExecutableFromHandleAndCaptureBytes `
        $BuiltExecutableHandle `
        $stagedExe
    $UnsignedUiExecutableBytes = Copy-SingleLinkExecutableFromHandleAndCaptureBytes `
        $BuiltUiExecutableHandle `
        $stagedUiExe
    Verify-ExecutableMetadataBytes $UnsignedExecutableBytes
    Verify-ExecutableMetadataBytes $UnsignedUiExecutableBytes
    if ((Get-ByteArraySha256 $UnsignedExecutableBytes) -cne
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
            $BuiltExecutableHandle
        )) {
        throw "Staged supervisor bytes do not match the exact retained Cargo output."
    }
    if ((Get-ByteArraySha256 $UnsignedUiExecutableBytes) -cne
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
            $BuiltUiExecutableHandle
        )) {
        throw "Staged UI helper bytes do not match the exact retained Cargo output."
    }
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularChild(
        $BuiltExecutableDirectoryHandle,
        "$BinaryName.exe",
        $BuiltExecutableHandle
    )
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularChild(
        $BuiltExecutableDirectoryHandle,
        "$UiBinaryName.exe",
        $BuiltUiExecutableHandle
    )
    $committedPayloadState = Copy-CommittedReleasePayloadFiles $stagedDist
    $CommittedPayloadHashes = $committedPayloadState.ExpectedHashes
    $StagedPayloadHandles = @($committedPayloadState.Handles)
    $committedPayloadState = $null
    Assert-StagedPayloadHandles $stagedDist $StagedPayloadHandles $CommittedPayloadHashes
    Assert-MaterializedReleaseSource

    Microsoft.PowerShell.Utility\Write-Warning "Creating an unsigned DEVELOPMENT distribution. It is not a publishable release, and its local build metadata is informational rather than an attestation."
    if ((Get-SingleLinkSha256 $stagedExe) -cne
        (Get-ByteArraySha256 $UnsignedExecutableBytes)) {
        throw "Unsigned development supervisor changed after its exact Cargo-output copy."
    }
    if ((Get-SingleLinkSha256 $stagedUiExe) -cne
        (Get-ByteArraySha256 $UnsignedUiExecutableBytes)) {
        throw "Unsigned development UI helper changed after its exact Cargo-output copy."
    }
    # Authenticate and retain both exact staged executable objects before the
    # Cargo-output handles are released. Once opened, these handles deny
    # writers and replacement until candidate transfer is complete. This
    # preserves the selected local test bytes but deliberately does not claim
    # who authored the build outputs within the shared Windows security context.
    $StagedExecutableHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenRegularSingleLink(
        $stagedExe
    )
    $StagedUiExecutableHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenRegularSingleLink(
        $stagedUiExe
    )
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularPath(
        $stagedExe,
        $StagedExecutableHandle
    )
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularPath(
        $stagedUiExe,
        $StagedUiExecutableHandle
    )
    $stagedHandleHash = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
        $StagedExecutableHandle
    )
    $stagedUiHandleHash = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
        $StagedUiExecutableHandle
    )
    if ($stagedHandleHash -cne (Get-ByteArraySha256 $UnsignedExecutableBytes)) {
        throw "Retained development supervisor is not the exact Cargo-output copy."
    }
    if ($stagedUiHandleHash -cne (Get-ByteArraySha256 $UnsignedUiExecutableBytes)) {
        throw "Retained development UI helper is not the exact Cargo-output copy."
    }
    $StagedExecutableSha256 = $stagedHandleHash
    $StagedUiExecutableSha256 = $stagedUiHandleHash
    Assert-StagedExecutableHandles $stagedExe $stagedUiExe
    if ((Get-ByteArraySha256 $UnsignedExecutableBytes) -cne
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
            $BuiltExecutableHandle
        )) {
        throw "Exact retained supervisor Cargo output changed before development validation completed."
    }
    if ((Get-ByteArraySha256 $UnsignedUiExecutableBytes) -cne
        [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
            $BuiltUiExecutableHandle
        )) {
        throw "Exact retained UI-helper Cargo output changed before development validation completed."
    }
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularChild(
        $BuiltExecutableDirectoryHandle,
        "$BinaryName.exe",
        $BuiltExecutableHandle
    )
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedRegularChild(
        $BuiltExecutableDirectoryHandle,
        "$UiBinaryName.exe",
        $BuiltUiExecutableHandle
    )
    Close-BuiltExecutableHandles
    $UnsignedExecutableBytes = $null
    $UnsignedUiExecutableBytes = $null
    Assert-StagedExecutableHandles $stagedExe $stagedUiExe
    Verify-ExecutableMetadata $stagedExe
    Verify-ExecutableMetadata $stagedUiExe

    $corePayloadHashes = Get-CoreDistributionPayloadHashes $stagedDist
    Assert-StagedExecutableHandles $stagedExe $stagedUiExe
    if ($corePayloadHashes[$ExeName] -cne $StagedExecutableSha256) {
        throw "Core payload hash does not match the exact retained staged supervisor."
    }
    if ($corePayloadHashes[$UiExeName] -cne $StagedUiExecutableSha256) {
        throw "Core payload hash does not match the exact retained staged UI helper."
    }
    Assert-StagedPayloadHandles $stagedDist $StagedPayloadHandles $CommittedPayloadHashes
    Assert-CommittedReleasePayloadHashes $corePayloadHashes $CommittedPayloadHashes
    $exeSha256 = $corePayloadHashes[$ExeName]
    $uiExeSha256 = $corePayloadHashes[$UiExeName]
    $metadataDocument = @(
        "WAAL_WINDOWS_LOCAL_BUILD_METADATA_V1",
        "artifact-kind=development-unsigned",
        "publishable=false",
        "attestation=none-local-shared-security-context",
        "producer-attribution=unavailable-local-shared-security-context",
        "target=$TargetTriple",
        "captured-source-git-commit=$ReleaseGitCommit",
        "captured-source-git-tree=$ReleaseGitTree",
        "packager-source-sha256=$PackagerSourceSha256",
        "git-sha256=$GitSha256",
        "git-runtime-content-sha256=$GitRootSha256",
        "tar-sha256=$TarSha256",
        "codedom-csc-sha256=$CodeDomCompilerSha256",
        "codedom-runtime-content-sha256=$CodeDomRuntimeSha256",
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
        "native-toolchain-sha256=$NativeToolchainSha256",
        "observed-materials-sha256=$ReleaseMaterialsSha256",
        "msvc-lib-content-sha256=$TrustedLibSha256",
        "msvc-include-content-sha256=$TrustedIncludeSha256",
        "msvc-libpath-content-sha256=$TrustedLibPathSha256",
        "executable-sha256=$exeSha256",
        "ui-helper-executable-sha256=$uiExeSha256",
        "readme-sha256=$($corePayloadHashes['README.md'])",
        "license-sha256=$($corePayloadHashes['LICENSE'])",
        "config-example-sha256=$($corePayloadHashes['config.example.json'])"
    ) -join "`r`n"
    $expectedMetadata = $metadataDocument + "`r`n"
    Write-Utf8NoBom (Microsoft.PowerShell.Management\Join-Path $stagedDist "BUILD-METADATA.txt") $expectedMetadata
    $payloadHashes = Get-DistributionPayloadHashes $stagedDist
    Write-Utf8NoBom (Microsoft.PowerShell.Management\Join-Path $stagedDist "SHA256SUMS.txt") (Get-Sha256ManifestContent $payloadHashes)
    $completeDistributionHashes = Get-CompleteDistributionFileHashes $stagedDist

    Assert-ReleaseSourceUnchanged $Git
    Assert-StagedExecutableHandles $stagedExe $stagedUiExe
    Assert-StagedPayloadHandles $stagedDist $StagedPayloadHandles $CommittedPayloadHashes
    Assert-WindowsDistribution $stagedDist $payloadHashes $expectedMetadata
    Assert-ReleaseToolchainIntegrity
    if ($StopRunning) { Stop-DistProcesses }
    $candidateDir = New-PublicationCandidate
    foreach ($fileName in @(
        $ExeName, $UiExeName, "README.md", "LICENSE", "config.example.json",
        "SHA256SUMS.txt", "BUILD-METADATA.txt"
    )) {
        Copy-SingleLinkFile `
            (Microsoft.PowerShell.Management\Join-Path $stagedDist $fileName) `
            (Microsoft.PowerShell.Management\Join-Path $candidateDir $fileName)
    }
    Assert-StagedExecutableHandles $stagedExe $stagedUiExe
    Assert-StagedPayloadHandles $stagedDist $StagedPayloadHandles $CommittedPayloadHashes
    Close-StagedExecutableHandles
    Close-StagedPayloadHandles
    Assert-WindowsDistribution $candidateDir $payloadHashes $expectedMetadata
    Lock-PublicationCandidateDirectory
    $PublicationPayloadHandles = Open-DistributionPayloadHandles $PublicationCandidateHandle
    Assert-DistributionPayloadHandles `
        $PublicationCandidateHandle `
        $PublicationPayloadHandles `
        $completeDistributionHashes
    # Retain and validate every selected payload identity. The directory itself
    # is intentionally not described as immutable: this is a local, unsigned,
    # non-attested development output.
    Assert-WindowsDistribution $candidateDir $payloadHashes $expectedMetadata
    Assert-DistributionPayloadHandles `
        $PublicationCandidateHandle `
        $PublicationPayloadHandles `
        $completeDistributionHashes
    Assert-ReleaseSourceUnchanged $Git
    Assert-ReleaseToolchainIntegrity
    Activate-PublicationCandidate
    $finalExe = Microsoft.PowerShell.Management\Join-Path $DistDir $ExeName
    $finalUiExe = Microsoft.PowerShell.Management\Join-Path $DistDir $UiExeName
    $PublicationPayloadHandles = Lock-DistributionPayloadHandlesAfterRename `
        $PublicationFinalHandle `
        $PublicationPayloadHandles
    Assert-DistributionPayloadHandles `
        $PublicationFinalHandle `
        $PublicationPayloadHandles `
        $completeDistributionHashes
    Assert-WindowsDistribution $DistDir $payloadHashes $expectedMetadata
    Assert-ReleaseSourceUnchanged $Git
    Assert-ReleaseToolchainIntegrity
    $finalExeHandles = @($PublicationPayloadHandles | Microsoft.PowerShell.Core\Where-Object {
        $_.Name -ceq $ExeName
    })
    $finalUiExeHandles = @($PublicationPayloadHandles | Microsoft.PowerShell.Core\Where-Object {
        $_.Name -ceq $UiExeName
    })
    if ($finalExeHandles.Count -ne 1 -or $finalUiExeHandles.Count -ne 1) {
        throw "Final publication does not retain exactly both executable identities."
    }
    $finalHash = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
        $finalExeHandles[0].Handle
    )
    $finalUiHash = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::HashTrackedRegularSingleLinkSha256(
        $finalUiExeHandles[0].Handle
    )
    [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::AssertTrackedDirectoryChild(
        $PublicationParentHandle,
        (Microsoft.PowerShell.Management\Split-Path -Leaf $DistDir),
        $PublicationFinalHandle
    )
    Assert-DistributionPayloadHandles `
        $PublicationFinalHandle `
        $PublicationPayloadHandles `
        $completeDistributionHashes
    Complete-DevelopmentPublication $DistDir $payloadHashes $expectedMetadata
    Close-DistributionPayloadHandles
    Close-PublicationDirectoryHandles

    Microsoft.PowerShell.Utility\Write-Host "Windows distribution complete:"
    Microsoft.PowerShell.Utility\Write-Host "  $DistDir"
    Microsoft.PowerShell.Utility\Write-Host "  $finalExe"
    Microsoft.PowerShell.Utility\Write-Host "  SHA-256: $finalHash"
    Microsoft.PowerShell.Utility\Write-Host "  $finalUiExe"
    Microsoft.PowerShell.Utility\Write-Host "  SHA-256: $finalUiHash"
    Microsoft.PowerShell.Utility\Write-Warning "This output is unsigned and development-only."
}
catch {
    $primaryFailure = $_
}
finally {
    try {
        Close-DistributionPayloadHandles
    }
    catch {
        $cleanupFailure = $_
    }
    try {
        Close-BuiltExecutableHandles
    }
    catch {
        if ($cleanupFailure) {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Build-output handle cleanup also failed: $($_.Exception.Message)"
        }
        else {
            $cleanupFailure = $_
        }
    }
    try {
        Close-StagedExecutableHandles
    }
    catch {
        if ($cleanupFailure) {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Staged executable handle cleanup also failed: $($_.Exception.Message)"
        }
        else {
            $cleanupFailure = $_
        }
    }
    try {
        Close-StagedPayloadHandles
    }
    catch {
        if ($cleanupFailure) {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Staged payload handle cleanup also failed: $($_.Exception.Message)"
        }
        else {
            $cleanupFailure = $_
        }
    }
    try {
        if (-not $PublicationComplete) {
            Restore-PublicationAfterFailure
        }
    }
    catch {
        if ($cleanupFailure) {
            Microsoft.PowerShell.Utility\Write-Warning `
                "Publication quarantine also failed: $($_.Exception.Message)"
        }
        else {
            $cleanupFailure = $_
        }
    }
    finally {
        try {
            Close-PublicationDirectoryHandles
        }
        catch {
            if ($cleanupFailure) {
                Microsoft.PowerShell.Utility\Write-Warning `
                    "Publication handle cleanup also failed: $($_.Exception.Message)"
            }
            else {
                $cleanupFailure = $_
            }
        }
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
    try {
        Close-AllReleaseInputLocks
    }
    catch {
        if ($cleanupFailure) {
            Microsoft.PowerShell.Utility\Write-Warning "Release-input handle cleanup also failed: $($_.Exception.Message)"
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
