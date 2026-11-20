# Localite

Localite runs a local AWS-compatible API endpoint in an Apple Virtualization Linux VM. It does not need or start Docker. The app forwards `localhost:4566` to Moto Server from the pinned `motoserver/moto:5.2.5` ARM64 image, running inside the guest's Linux namespaces; the Rust guest supervisor applies the filesystem, process, capability, and seccomp isolation. The package metadata inside that image reports Moto `5.2.5.dev0`, so the image tag should not be read as a guarantee of a stable Moto package release.

The ARM64 Moto root filesystem is assembled from a pinned, digest-verified upstream image during the guest build. The image is a filesystem payload only: no Docker daemon, container runtime, image pull, or package installation runs when Localite starts.

## Build the macOS DMG

On an Apple Silicon Mac with Xcode Command Line Tools, Rust, the `aarch64-unknown-linux-musl` target, and Zig:

```sh
cd app
ZIG=/path/to/zig ./build-dmg.sh
```

The first build downloads the Kata guest kernel and pinned Moto image layers. The result is `app/build/Localite.dmg`. Locally built app bundles are ad-hoc signed, not notarized.

## Use it from an editor or AWS SDK

Start Localite and wait for **Running**. Click **Copy AWS env**, then run your normal AWS CLI, SDK, or test suite with those environment variables. For example:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r tests/requirements.txt
python tests/aws_sdk_smoke.py
```

The smoke test uses boto3 against `http://localhost:4566` and exercises:

- S3: create/delete bucket; put/get/list/delete object.
- SQS: create/delete queue; send/receive/delete message.
- DynamoDB: create/delete table; put/get/update/query/scan item.
- IAM: create/get/list/delete user.
- STS: get caller identity.

It makes no calls to AWS. Run it while Localite is **Running**.

The workbench provides direct requests for common S3, SQS, DynamoDB, IAM, and STS operations. It is not a general code editor or project runner. The selected workspace is isolated file storage mounted at `/workspace`; Localite does not execute project code inside the VM. Use your existing editor and tooling to run SDK clients against the local endpoint.

## Compatibility and limits

Moto implements AWS API behavior locally, but it is not AWS and does not provide full LocalStack or AWS parity. The checked-in smoke test is the compatibility contract Localite verifies; Moto's broader service support is version-dependent and not all operations have been tested here. State is in memory and resets when the VM stops. Do not point production credentials or workloads at this local test endpoint.

Lambda code invocation is intentionally not exposed: Moto's Lambda runtime requires Docker for actual function execution. Localite does not execute user code. The Rust service handlers remain available for development/self-tests but are not the app's default API backend.

## Workspaces

- **Import private project copy** copies the chosen folder to `~/Library/Application Support/Localite/Workspaces/` and shares only that copy with the guest. The original folder is not mounted. Imported changes stay in the private copy.
- **Share folder** is a separate, explicit opt-in that gives the guest read/write access to the chosen host folder.
- Stop the VM before changing its workspace. Private imports reject symbolic links.

## Development and verification

```sh
cargo test --workspace --exclude localite-sandbox
cargo check --target aarch64-unknown-linux-musl -p localite-sandbox
python3 -m py_compile guest/fetch-moto-rootfs.py guest/make-initrd.py tests/aws_sdk_smoke.py
```

On Linux, `cargo test --workspace` also runs the Linux sandbox tests. `guest/test-in-qemu.sh /path/to/vmlinux` boots the guest under QEMU when available. `guest/build-initrd.sh` rebuilds the ARM64 guest and its pinned Moto rootfs.

The DMG is a local build artifact; this repository does not publish a downloadable release.
