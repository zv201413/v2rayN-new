#!/usr/bin/env python3
"""Stage the rebuilt v2rayN GUI into official deb structure and re-package."""

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path


def stage_package(publish_dir: Path, official_deb: Path, stage_dir: Path, output_deb: Path, version: str):
    publish_dir = publish_dir.resolve()
    official_deb = official_deb.resolve()
    stage_dir = stage_dir.resolve()
    output_deb = output_deb.resolve()

    # 1. 检查构建产物核心文件
    for name in ("v2rayN", "ServiceLib.dll", "AmazTool"):
        if not (publish_dir / name).is_file():
            raise RuntimeError(f"构建产物缺失: {name}")

    # 2. 清理并用官方 deb 作为模板解包
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True)

    print(f"▸ 解包官方 deb: {official_deb} -> {stage_dir}")
    subprocess.check_call(["dpkg-deb", "-R", str(official_deb), str(stage_dir)])

    # 3. 覆盖 publish 产物到 opt/v2rayN/
    app_dir = stage_dir / "opt/v2rayN"
    if not app_dir.is_dir():
        raise RuntimeError(f"官方 deb 中未发现 opt/v2rayN 目录: {stage_dir}")

    print(f"▸ 复制构建产物到 {app_dir}")
    for item in publish_dir.iterdir():
        dest = app_dir / item.name
        if item.is_dir():
            shutil.copytree(item, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest)

    # 4. 确保关键二进制执行权限
    for relative in ("v2rayN", "AmazTool"):
        target = app_dir / relative
        if target.is_file():
            target.chmod(0o755)

    for binary in app_dir.glob("bin/**/*"):
        if binary.is_file():
            with binary.open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    binary.chmod(0o755)

    # 5. 修改 DEBIAN/control 中的 Version
    control_file = stage_dir / "DEBIAN/control"
    if not control_file.is_file():
        raise RuntimeError("缺失 DEBIAN/control 文件")

    lines = control_file.read_text(encoding="utf-8").splitlines()
    new_lines = []
    for line in lines:
        if line.startswith("Version:"):
            new_lines.append(f"Version: {version}")
        else:
            new_lines.append(line)
    control_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    # 6. 重新生成 DEBIAN/md5sums
    control_dir = stage_dir / "DEBIAN"
    sums = []
    for file in sorted(stage_dir.rglob("*")):
        if file.is_file() and not file.is_symlink() and control_dir not in file.parents:
            with file.open("rb") as stream:
                digest = hashlib.file_digest(stream, "md5").hexdigest()
            rel_path = file.relative_to(stage_dir)
            sums.append(f"{digest}  {rel_path}")

    (control_dir / "md5sums").write_text("\n".join(sums) + "\n", encoding="utf-8")

    # 7. 打包输出 deb
    output_deb.parent.mkdir(parents=True, exist_ok=True)
    if output_deb.exists():
        output_deb.unlink()
    print(f"▸ 打包 deb -> {output_deb}")
    subprocess.check_call([
        "dpkg-deb", "--root-owner-group", "--build", str(stage_dir), str(output_deb)
    ])
    print(f"✓ 成功生成 {output_deb}")


if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("Usage: stage_cloud.py <publish_dir> <official_deb> <stage_dir> <output_deb> <version>")
        sys.exit(1)
    stage_package(
        Path(sys.argv[1]),
        Path(sys.argv[2]),
        Path(sys.argv[3]),
        Path(sys.argv[4]),
        sys.argv[5],
    )
