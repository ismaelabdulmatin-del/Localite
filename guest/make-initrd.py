#!/usr/bin/env python3
import gzip
import os
import stat
import sys


def entry(name, mode, data=b"", rdevmajor=0, rdevminor=0, ino=1, nlink=1):
    encoded_name = name.encode("utf-8") + b"\0"
    fields = (
        ino, mode, 0, 0, nlink, 0, len(data),
        0, 0, rdevmajor, rdevminor, len(encoded_name), 0,
    )
    header = b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields)
    result = header + encoded_name
    result += b"\0" * (-len(result) % 4)
    result += data
    result += b"\0" * (-len(data) % 4)
    return result


def append_rootfs(archive, rootfs, next_ino):
    archive.write(entry("moto-rootfs", stat.S_IFDIR | 0o755, ino=next_ino, nlink=2))
    next_ino += 1
    for directory, dirs, files in os.walk(rootfs, topdown=True, followlinks=False):
        dirs.sort()
        files.sort()
        relative = os.path.relpath(directory, rootfs)
        prefix = "moto-rootfs" if relative == "." else f"moto-rootfs/{relative}"
        if relative != ".":
            mode = stat.S_IMODE(os.stat(directory, follow_symlinks=False).st_mode)
            archive.write(entry(prefix, stat.S_IFDIR | mode, ino=next_ino, nlink=2))
            next_ino += 1

        for name in dirs + files:
            path = os.path.join(directory, name)
            relative_path = os.path.relpath(path, rootfs)
            archive_name = f"moto-rootfs/{relative_path}"
            info = os.lstat(path)
            mode = info.st_mode
            if stat.S_ISDIR(mode):
                continue
            if stat.S_ISLNK(mode):
                data = os.readlink(path).encode("utf-8")
                archive.write(entry(archive_name, stat.S_IFLNK | 0o777, data, ino=next_ino))
            elif stat.S_ISREG(mode):
                with open(path, "rb") as source:
                    data = source.read()
                archive.write(entry(archive_name, stat.S_IFREG | stat.S_IMODE(mode), data, ino=next_ino))
            else:
                continue
            next_ino += 1
    return next_ino


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: make-initrd.py INIT_BINARY OUTPUT_GZ [MOTO_ROOTFS]")
    binary_path, output_path = sys.argv[1:3]
    rootfs = sys.argv[3] if len(sys.argv) == 4 else None
    with open(binary_path, "rb") as binary:
        data = binary.read()

    with open(output_path, "wb") as target:
        with gzip.GzipFile(fileobj=target, mode="wb", compresslevel=9, mtime=0) as compressed:
            compressed.write(entry("dev", stat.S_IFDIR | 0o755, ino=1, nlink=2))
            compressed.write(entry("dev/console", stat.S_IFCHR | 0o600, rdevmajor=5, rdevminor=1, ino=2))
            compressed.write(entry("init", stat.S_IFREG | 0o755, data, ino=3))
            next_ino = 4
            if rootfs:
                next_ino = append_rootfs(compressed, rootfs, next_ino)
            compressed.write(entry("TRAILER!!!", 0, ino=next_ino))
    print(f"built {output_path} ({os.path.getsize(output_path)} bytes)")


if __name__ == "__main__":
    main()
