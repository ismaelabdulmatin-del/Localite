# Localite

Localite provides a local AWS-compatible API endpoint for development and integration tests on Apple Silicon Macs. It runs in an isolated Linux VM and does not require Docker.

**[Download the macOS DMG](https://github.com/ismaelabdulmatin-del/Localite/releases/latest/download/Localite.dmg)** · **[Project website](https://ismaelabdulmatin-del.github.io/Localite/)**

> **Interim build:** the current DMG is ad-hoc signed, not notarized. macOS may block it or require explicit approval in Privacy & Security. Only install it if you trust this project and verify the checksum listed with the release.

The app exposes `http://localhost:4566` while running. The verified boto3 workflows cover S3 bucket/object basics, SQS queues/messages, DynamoDB tables/items, IAM users, and STS identity. This is a tested subset—not full AWS or LocalStack parity. State resets when the app stops; Lambda execution and project-code execution are not supported.

See [README-LOCALITE.md](README-LOCALITE.md) for setup, SDK/CLI examples, workspace isolation, compatibility details, and development instructions.

## Build from source

On an Apple Silicon Mac with Xcode Command Line Tools, Rust, the `aarch64-unknown-linux-musl` target, and Zig:

```sh
cd app
ZIG=/path/to/zig ./build-dmg.sh
```

The first build downloads the pinned Moto ARM64 image and Kata guest kernel. See the [build and verification guide](README-LOCALITE.md).

## License

Localite source code is available under the MIT License. Third-party components retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the bundled runtime's license files.
