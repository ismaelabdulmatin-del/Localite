# Third-party notices

Localite bundles third-party software in its Linux guest. Localite's MIT License does not replace the licenses for these components.

## Moto runtime image

The guest root filesystem is assembled from the ARM64 image `motoserver/moto:5.2.5`, pinned in `guest/fetch-moto-rootfs.py` to manifest digest:

`sha256:bbad22bdb90ad79b5d8d510558a77226d5d6c4aa737851a45b613f80452fe254`

The installed Moto package identifies itself as `5.2.5.dev0` and is licensed under Apache-2.0. Its license is bundled at `/moto-rootfs/usr/local/lib/python3.13/site-packages/moto-5.2.5.dev0.dist-info/licenses/LICENSE` in the guest image.

The image also contains Python, boto3/botocore, and their dependencies. Their installed package metadata and license files are under `/moto-rootfs/usr/local/lib/python3.13/` and `/moto-rootfs/usr/local/lib/python3.13/site-packages/`. The Python license is `usr/local/lib/python3.13/LICENSE.txt`; package-specific license and notice files are retained in each distribution's `.dist-info` directory where provided.

## Alpine Linux runtime

The pinned image contains Alpine Linux 3.24.3 packages. Package names, versions, and SPDX-style license identifiers are recorded in `/moto-rootfs/lib/apk/db/installed`. Alpine publishes package and source information at <https://pkgs.alpinelinux.org/> and source packaging at <https://gitlab.alpinelinux.org/alpine/aports>.

## Rust dependencies and vendored models

Rust dependencies are listed in `Cargo.lock`; their declared licenses are MIT, Apache-2.0, or both. The vendored botocore service models are Apache-2.0; retain `vendor/botocore/LICENSE.txt` and `vendor/botocore/NOTICE`.

The DMG is a bundled distribution of these components. Review the license files and upstream notices before modifying or redistributing the bundled runtime.
