param([string]$Python = "python")
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $env:PYINSTALLER_CONFIG_DIR = Join-Path $PSScriptRoot ".pyi-cache"
    & $Python -m PyInstaller --noconfirm --clean --onefile --windowed --noupx --name NetDoctorLite main.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller 构建失败 ($LASTEXITCODE)" }
} finally {
    Pop-Location
}
