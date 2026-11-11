param([string]$Python = "python")
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & $Python build_release.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller 构建失败 ($LASTEXITCODE)" }
} finally {
    Pop-Location
}
