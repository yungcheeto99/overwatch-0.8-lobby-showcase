param([switch]$Preview, [switch]$Yes)

$ErrorActionPreference = 'Stop'
# The helper lives in misc; generated files belong to the parent lobby folder.
$cleanupRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$cleanupPrefix = $cleanupRoot + [IO.Path]::DirectorySeparatorChar
$generatedFolders = @('.venv', 'venv', 'data', 'captures', 'bootstrap', 'logs',
                      '.pytest_cache', '.mypy_cache', '.ruff_cache', 'build', 'dist')
$runtimeFiles = @('localip.crt', 'localip.cer', 'local-certificate.json',
                  'local-menu-server.json', 'remote-menu-invite.json', 'server-pins.json',
                  'events.jsonl', 'experiment.json', 'summary.json', 'client.jsonl',
                  'client.stdout.log', 'c2s.wire.bin', 's2c.wire.bin',
                  'c2s.frames.bin', 's2c.frames.bin')
$protectedFolders = @('.git', '.agents', '.codex', '.aws')

function Assert-LocalPath([string]$Path) {
    $absolute = [IO.Path]::GetFullPath($Path)
    if (-not $absolute.StartsWith($cleanupPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Cleanup target is outside the showcase folder: $absolute"
    }
    # Validate ancestors too: an ordinary file can sit below a linked folder.
    $ancestor = $absolute
    while ($ancestor) {
        $item = Get-Item -LiteralPath $ancestor -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Cleanup refuses linked paths: $ancestor"
        }
        if ($ancestor -eq $cleanupRoot) { break }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
}

function Find-GeneratedItems {
    $targets = [Collections.Generic.List[string]]::new()
    $pending = [Collections.Generic.Stack[object]]::new()
    $pending.Push(@{ Path = $cleanupRoot; Covered = $false })
    while ($pending.Count) {
        $directory = $pending.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $directory.Path -Force) {
            if ($item.PSIsContainer -and $item.Name -in $protectedFolders) {
                if ($directory.Covered) {
                    throw "A generated folder contains protected metadata: $($item.FullName)"
                }
                continue
            }
            Assert-LocalPath $item.FullName
            if ($item.PSIsContainer) {
                $generated = ($item.Name -eq '__pycache__') -or
                    (($directory.Path -eq $cleanupRoot) -and
                     (($item.Name -in $generatedFolders) -or ($item.Name -like '*.egg-info')))
                if ($generated -and -not $directory.Covered) { $targets.Add($item.FullName) }
                # Scan before deleting: never traverse a junction or symlink.
                $pending.Push(@{ Path = $item.FullName; Covered = ($directory.Covered -or $generated) })
            } elseif (-not $directory.Covered -and
                (($item.Name -in $runtimeFiles) -or ($item.Name -like '*.pyc') -or
                 ($item.Name -like '*.pyo') -or ($item.Name -like '*.sqlite3*') -or
                 ($item.Name -like '*.pem') -or ($item.Name -like '*.key') -or
                 ($item.Name -like 'bootstrap-*.jsonl'))) {
                $targets.Add($item.FullName)
            }
        }
    }
    return $targets.ToArray()
}

try {
    foreach ($required in @('launch.py', 'Start-Server.bat',
                            'Start-Client.bat', 'ow08\__main__.py')) {
        if (-not (Test-Path -LiteralPath (Join-Path $cleanupRoot $required) -PathType Leaf)) {
            throw 'Keep misc\CleanUp.bat and cleanup.ps1 inside a complete showcase lobby folder.'
        }
    }
    Write-Host "Showcase folder: $cleanupRoot"
    $targets = @(Find-GeneratedItems | Sort-Object)
    if (-not $targets.Count) {
        Write-Host 'No generated files found. The folder is already clean.'
        exit 0
    }
    Write-Host 'Generated items to remove:'
    foreach ($target in $targets) { Write-Host ('  ' + $target.Substring($cleanupPrefix.Length)) }
    if ($Preview) {
        Write-Host 'Preview only. Nothing was deleted.'
        exit 0
    }
    foreach ($process in Get-Process -Name python, pythonw -ErrorAction SilentlyContinue) {
        $executable = $process.Path
        if ($executable -and $executable.StartsWith($cleanupPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Close the showcase server, command window and client launchers before cleanup.'
        }
    }
    Write-Host 'This permanently deletes saved accounts, private keys, pins and captures in the listed targets.'
    Write-Host 'Back up anything you need outside this folder first.'
    if (-not $Yes -and (Read-Host 'Type CLEAN to delete these items') -cne 'CLEAN') {
        Write-Host 'Cancelled. Nothing was deleted.'
        exit 0
    }
    # Recheck the complete plan after confirmation and before the first delete.
    $currentTargets = @(Find-GeneratedItems | Sort-Object)
    if (@(Compare-Object $targets $currentTargets).Count) {
        throw 'The folder changed during confirmation. Run cleanup again to review the new targets.'
    }
    foreach ($target in $targets) {
        Assert-LocalPath $target
        Remove-Item -LiteralPath $target -Recurse -Force
    }
    Write-Host 'Cleanup complete.'
    Write-Host 'Review any custom output folders; locations outside this folder were not cleaned.'
} catch {
    Write-Host ('Cleanup failed: ' + $_.Exception.Message)
    Write-Host 'Cleanup is incomplete. Resolve the error and run cleanup again.'
    exit 2
}
