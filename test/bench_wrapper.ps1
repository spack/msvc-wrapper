# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

<#
.SYNOPSIS
    Measures the overhead this wrapper adds to a compile.

.DESCRIPTION
    Reports two numbers that matter for build throughput:

    1. The wrapper process' own CPU time for a single compile, next to that
       compile's wall time. The wrapper does almost no work of its own, so
       these should be orders of magnitude apart. If the wrapper's CPU time
       tracks the child's wall time, the wrapper is burning a core while it
       waits - which costs nothing visible at -j1 and roughly halves compiler
       throughput at -jN.

    2. Wall-clock for a batch of compiles at -j1 and at -j<cores>, through the
       wrapper and directly. Per-invocation overhead shows up in the -j1
       number; CPU contention shows up only in the -jN number.

    Run from a Visual Studio Developer prompt.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File test\bench_wrapper.ps1
    powershell -ExecutionPolicy Bypass -File test\bench_wrapper.ps1 -Iterations 64
#>

[CmdletBinding()]
param(
    # Wrapper binary to measure; defaults to the cl.exe built at the repo root
    [string] $Wrapper,
    # Number of compiles in the batch runs
    [int]    $Iterations = 32,
    # Parallelism for the contended run; defaults to the machine's core count
    [int]    $Jobs = 0,
    # Working directory for generated sources and objects
    [string] $WorkDir,
    # The real MSVC compiler. Auto-detected from the toolchain install if not
    # given; never guessed from bare PATH order, because picking a wrapper here
    # makes the wrapper spawn a wrapper without bound.
    [string] $RealCl
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

if (-not $Wrapper)  { $Wrapper = Join-Path $repoRoot 'cl.exe' }
if (-not $WorkDir)  { $WorkDir = Join-Path $repoRoot 'tmp\bench' }
if ($Jobs -le 0)    { $Jobs = [Environment]::ProcessorCount }

if (-not (Test-Path $Wrapper)) {
    throw "Wrapper not found at $Wrapper. Build it first: nmake /f Makefile cl.exe"
}
$Wrapper = (Resolve-Path $Wrapper).Path

# ---------------------------------------------------------------------------
# Locate the real compiler.
#
# This must positively identify the MSVC toolchain rather than just taking the
# first cl.exe on PATH, pointing the wrapper's SPACK_CC at any wrapper from here
# produces an unbounded chain of processes.
# ---------------------------------------------------------------------------
function Test-IsMsvcCompiler {
    param([string] $Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $false }
    if ((Resolve-Path $Path).Path -ieq $Wrapper) { return $false }
    # The genuine compiler lives under the toolchain's VC\Tools\MSVC tree; the
    # wrapper never does
    return $Path -imatch '\\VC\\Tools\\MSVC\\'
}

if ($RealCl) {
    if (-not (Test-Path $RealCl)) { throw "-RealCl not found: $RealCl" }
    $realCl = (Resolve-Path $RealCl).Path
    if ((Resolve-Path $realCl).Path -ieq $Wrapper) {
        throw "-RealCl is the wrapper itself; that would recurse without bound."
    }
} else {
    $realCl = $null
    if ($env:VCToolsInstallDir) {
        $hostArch = if ([Environment]::Is64BitOperatingSystem) { 'Hostx64\x64' } else { 'Hostx86\x86' }
        $candidate = Join-Path $env:VCToolsInstallDir "bin\$hostArch\cl.exe"
        if (Test-IsMsvcCompiler $candidate) { $realCl = $candidate }
    }
    if (-not $realCl) {
        foreach ($candidate in (& where.exe cl 2>$null)) {
            if (Test-IsMsvcCompiler $candidate) { $realCl = $candidate; break }
        }
    }
}
if (-not $realCl) {
    throw ("Could not positively identify the MSVC cl.exe. Run from a VS " +
           "Developer prompt, or pass -RealCl <path>.")
}
Write-Host "Wrapper : $Wrapper"
Write-Host "Real cl : $realCl"
Write-Host "Jobs    : $Jobs   Iterations: $Iterations"
Write-Host ""

$env:SPACK_CC                    = $realCl
$env:SPACK_CXX                   = $realCl
# Resolve the linker next to the compiler, a bare
# "link.exe" could resolve to a wrapper symlink
$env:SPACK_LD                    = Join-Path (Split-Path -Parent $realCl) 'link.exe'
$env:SPACK_COMPILER_WRAPPER_PATH = $repoRoot
$env:SPACK_DEBUG_LOG_DIR         = $WorkDir
$env:SPACK_DEBUG_LOG_ID          = 'BENCH'
$env:SPACK_SHORT_SPEC            = 'bench%msvc'
$env:SPACK_SYSTEM_DIRS           = $env:PATH
$env:SPACK_MANAGED_DIRS          = $WorkDir

Remove-Item Env:\SPACK_DEBUG_WRAPPER -ErrorAction SilentlyContinue

if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
New-Item -ItemType Directory -Path $WorkDir | Out-Null

# A source heavy enough that the child runs for a noticeable interval; a
# trivial file compiles too fast to show CPU contention.
$sourcePath = Join-Path $WorkDir 'bench_tu.cxx'
@'
#include <algorithm>
#include <map>
#include <memory>
#include <numeric>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

template <typename T>
struct Holder {
    std::vector<T> items;
    std::map<std::string, std::vector<T>> byName;
    std::unordered_map<std::string, std::shared_ptr<T>> owned;
    T total() const { return std::accumulate(items.begin(), items.end(), T{}); }
    std::string describe() const {
        std::ostringstream out;
        for (const auto& item : items) { out << item << ","; }
        return out.str();
    }
};

template <int N>
struct Chain { static int value() { return N + Chain<N - 1>::value(); } };
template <>
struct Chain<0> { static int value() { return 0; } };

int bench_entry() {
    Holder<int> a; Holder<double> b; Holder<long long> c;
    a.items.assign(64, 1); b.items.assign(64, 1.5); c.items.assign(64, 2);
    std::sort(a.items.begin(), a.items.end());
    return static_cast<int>(a.total() + b.total() + c.total()) +
           Chain<200>::value() +
           static_cast<int>(a.describe().size() + b.describe().size());
}
'@ | Set-Content -Encoding ASCII $sourcePath

function Invoke-Compile {
    param([string] $Exe, [string] $ObjName)
    $compileArgs = @('/c', '/EHsc', '/nologo', $sourcePath, "/Fo$(Join-Path $WorkDir $ObjName)")
    $proc = Start-Process -FilePath $Exe -ArgumentList $compileArgs `
                          -PassThru -NoNewWindow -Wait -WorkingDirectory $WorkDir
    return $proc
}

# ---------------------------------------------------------------------------
# Wrapper CPU time vs. child wall time, single compile
# ---------------------------------------------------------------------------
Write-Host '--- Single compile: wrapper CPU vs. wall time ---'
# warm the filesystem / compiler caches first
Invoke-Compile -Exe $Wrapper -ObjName 'warm.obj' | Out-Null

$sw = [Diagnostics.Stopwatch]::StartNew()
$proc = Invoke-Compile -Exe $Wrapper -ObjName 'single.obj'
$sw.Stop()
$wrapperCpuMs = $proc.TotalProcessorTime.TotalMilliseconds
$wallMs = $sw.Elapsed.TotalMilliseconds
$ratio = if ($wallMs -gt 0) { $wrapperCpuMs / $wallMs } else { 0 }

Write-Host ("  wall time            : {0,8:N1} ms" -f $wallMs)
Write-Host ("  wrapper process CPU  : {0,8:N1} ms" -f $wrapperCpuMs)
Write-Host ("  CPU / wall           : {0,8:P1}" -f $ratio)
if ($ratio -gt 0.5) {
    Write-Host "  -> The wrapper is burning a core while waiting on the child." -ForegroundColor Red
} else {
    Write-Host "  -> The wrapper is idle while the child runs." -ForegroundColor Green
}
Write-Host ''

# ---------------------------------------------------------------------------
# Batch wall clock, serial and parallel, wrapper vs. direct
# ---------------------------------------------------------------------------
function Measure-Batch {
    param([string] $Exe, [int] $Count, [int] $Parallel)
    $running = New-Object System.Collections.ArrayList
    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $Count; $i++) {
        $compileArgs = @('/c', '/EHsc', '/nologo', $sourcePath,
                         "/Fo$(Join-Path $WorkDir ("batch_$i.obj"))")
        $p = Start-Process -FilePath $Exe -ArgumentList $compileArgs `
                           -PassThru -NoNewWindow -WorkingDirectory $WorkDir
        [void]$running.Add($p)
        while ($running.Count -ge $Parallel) {
            $done = $running | Where-Object { $_.HasExited }
            if ($done) {
                foreach ($d in $done) { [void]$running.Remove($d) }
            } else {
                [void]($running[0].WaitForExit(50))
            }
        }
    }
    foreach ($p in $running) { $p.WaitForExit() }
    $sw.Stop()
    return $sw.Elapsed.TotalSeconds
}

foreach ($parallel in @(1, $Jobs)) {
    $label = if ($parallel -eq 1) { 'serial (-j1)' } else { "parallel (-j$parallel)" }
    Write-Host "--- $Iterations compiles, $label ---"
    $direct  = Measure-Batch -Exe $realCl  -Count $Iterations -Parallel $parallel
    $wrapped = Measure-Batch -Exe $Wrapper -Count $Iterations -Parallel $parallel
    $overhead = if ($direct -gt 0) { ($wrapped - $direct) / $direct } else { 0 }
    Write-Host ("  direct   : {0,7:N2} s" -f $direct)
    Write-Host ("  wrapped  : {0,7:N2} s" -f $wrapped)
    Write-Host ("  overhead : {0,7:P1}" -f $overhead)
    Write-Host ''
}

Write-Host "Artifacts left in $WorkDir"
