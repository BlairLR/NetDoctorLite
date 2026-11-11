"""Build consistently named Windows release artifacts from one version source."""

import hashlib
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from zipfile import ZIP_DEFLATED, ZipFile

from netdoctor.version import __version__


def main():
    root = Path(__file__).resolve().parent
    os.chdir(root)
    if sys.platform != "win32" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise SystemExit("请使用 Windows x64 Python 构建")
    if not re.fullmatch(r"\d+\.\d+\.\d+", __version__):
        raise SystemExit("版本号须采用 主版本.次版本.修订版本")

    dist = root / "dist"
    work = root / "build" / f"v{__version__}"
    work.mkdir(parents=True, exist_ok=True)
    dist.mkdir(exist_ok=True)
    version = tuple(int(part) for part in __version__.split(".")) + (0,)
    resource = work / "version-info.txt"
    resource.write_text(
        "VSVersionInfo(\n"
        f"  ffi=FixedFileInfo(filevers={version!r}, prodvers={version!r}, "
        "mask=0x3f, flags=0, OS=0x40004, fileType=1, subtype=0, date=(0, 0)),\n"
        "  kids=[StringFileInfo([StringTable('040904B0', [\n"
        "    StringStruct('ProductName', 'NetDoctor Lite'),\n"
        "    StringStruct('FileDescription', 'NetDoctor Lite'),\n"
        f"    StringStruct('FileVersion', '{__version__}'),\n"
        f"    StringStruct('ProductVersion', '{__version__}')\n"
        "  ])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])])\n",
        encoding="utf-8",
    )
    stem = f"NetDoctorLite-v{__version__}"
    name = f"{stem}-windows-x64-portable"
    env = os.environ.copy()
    env["PYINSTALLER_CONFIG_DIR"] = str(root / ".pyi-cache")
    subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile",
         "--windowed", "--noupx", "--name", name, "--version-file", str(resource),
         "--distpath", str(dist), "--workpath", str(work),
         "--specpath", str(work), str(root / "main.py")],
        env=env, check=True,
    )

    source = dist / f"{stem}-source.zip"
    files = [root / name for name in (
        ".gitignore", "README.md", "CHANGELOG.md", "main.py", "build.ps1",
        "build_release.py", "requirements.txt", "requirements-build.txt",
        "requirements-lock.txt",
    )]
    files += sorted((root / "netdoctor").glob("*.py"))
    files += sorted((root / "tests").glob("*.py"))
    files += sorted((root / "tests" / "fixtures").glob("*.json"))
    with ZipFile(source, "w", ZIP_DEFLATED) as archive:
        for file in files:
            archive.write(file, f"{stem}/{file.relative_to(root).as_posix()}")
    artifacts = [dist / f"{name}.exe", source]
    sums = []
    for file in artifacts:
        with file.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        sums.append(f"{digest}  {file.name}")
    (dist / f"{stem}-SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="ascii")
    print(f"发布文件已生成于 {dist}")


if __name__ == "__main__":
    main()
