#!/usr/bin/env python3
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request


REPOSITORY = "motoserver/moto"
VERSION = "5.2.5"
ARM64_MANIFEST = "sha256:bbad22bdb90ad79b5d8d510558a77226d5d6c4aa737851a45b613f80452fe254"
REGISTRY = "https://registry-1.docker.io/v2"


def fetch(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def checked_json(data, expected_digest, description):
    actual = "sha256:" + hashlib.sha256(data).hexdigest()
    if actual != expected_digest:
        raise RuntimeError(f"{description} digest mismatch: {actual}")
    return json.loads(data)


def remove_path(path):
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)


def extract_layer(archive_path, rootfs):
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            parts = member.name.split("/")
            if member.name.startswith("/") or any(part == ".." for part in parts):
                raise RuntimeError(f"unsafe path in pinned Moto layer: {member.name}")
            name = member.name.rstrip("/")
            if not name:
                continue
            parent, _, base = name.rpartition("/")
            if base == ".wh..wh..opq":
                target = os.path.join(rootfs, parent)
                if os.path.isdir(target):
                    for child in os.listdir(target):
                        remove_path(os.path.join(target, child))
            elif base.startswith(".wh."):
                target = os.path.join(rootfs, parent, base[4:])
                remove_path(target)

        # This archive is content-addressed by the pinned official image manifest.
        subprocess.run(
            ["tar", "-xzf", archive_path, "-C", rootfs, "--no-same-owner"],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    for current, dirs, files in os.walk(rootfs, topdown=True, followlinks=False):
        for name in list(dirs) + files:
            if name.startswith(".wh."):
                remove_path(os.path.join(current, name))


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: fetch-moto-rootfs.py OUTPUT_ROOTFS")
    rootfs = os.path.abspath(sys.argv[1])
    cache = os.path.join(os.path.dirname(__file__), ".cache", f"moto-{VERSION}")
    os.makedirs(cache, exist_ok=True)

    token_url = "https://auth.docker.io/token?" + urllib.parse.urlencode(
        {"scope": f"repository:{REPOSITORY}:pull", "service": "registry.docker.io"}
    )
    token = json.loads(fetch(token_url))["token"]
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.oci.image.manifest.v1+json, "
        "application/vnd.docker.distribution.manifest.v2+json",
    }

    manifest_data = fetch(f"{REGISTRY}/{REPOSITORY}/manifests/{ARM64_MANIFEST}", headers)
    manifest = checked_json(manifest_data, ARM64_MANIFEST, "Moto ARM64 manifest")
    config_desc = manifest["config"]

    def get_blob(descriptor):
        digest = descriptor["digest"]
        path = os.path.join(cache, digest.split(":", 1)[1])
        if os.path.isfile(path):
            with open(path, "rb") as cached:
                if "sha256:" + hashlib.sha256(cached.read()).hexdigest() == digest:
                    return path
        data = fetch(f"{REGISTRY}/{REPOSITORY}/blobs/{digest}", {
            "Authorization": f"Bearer {token}"
        })
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError(f"blob digest mismatch: {digest}")
        temporary = path + ".tmp"
        with open(temporary, "wb") as target:
            target.write(data)
        os.replace(temporary, path)
        return path

    config = checked_json(
        open(get_blob(config_desc), "rb").read(), config_desc["digest"], "Moto config"
    )
    if config.get("architecture") != "arm64" or config.get("os") != "linux":
        raise RuntimeError("pinned Moto image is not linux/arm64")
    if config.get("config", {}).get("Entrypoint", [None])[0] != "/usr/local/bin/moto_server":
        raise RuntimeError("unexpected Moto image entrypoint")

    if os.path.lexists(rootfs):
        shutil.rmtree(rootfs)
    os.makedirs(rootfs)
    for layer in manifest["layers"]:
        extract_layer(get_blob(layer), rootfs)

    executable = os.path.join(rootfs, "usr", "local", "bin", "moto_server")
    if not os.path.isfile(executable):
        raise RuntimeError("Moto image did not contain moto_server")
    print(f"prepared motoserver/moto:{VERSION} linux/arm64 rootfs at {rootfs}")


if __name__ == "__main__":
    main()
