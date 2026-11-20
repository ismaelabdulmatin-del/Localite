# Vendored botocore service models

These are the AWS service models that `xtask codegen` reads to generate `crates/models`.
They are checked in so that **a build never needs the network and never needs Python**.

## Pin

| | |
|---|---|
| Upstream | `botocore` (PyPI) |
| Version | **1.42.97** |
| Artifact | `botocore-1.42.97-py3-none-any.whl` (14,950,367 bytes) |
| License | Apache-2.0 — `LICENSE.txt` and `NOTICE` are copied alongside |
| Contents | `botocore/data/<service>/<api-version>/service-2.json.gz` from that wheel |

`service-2.json.gz` is vendored **decompressed** as `services/<service>/service-2.json`. Three reasons: model updates produce reviewable diffs instead of an opaque binary change, the codegen needs no inflate step, and the archive crate stays reserved for Lambda payloads rather than build data. Total footprint is 3.2 MB.

## Services (Tier 1)

| Service | apiVersion | Protocol | Ops | Target prefix / notes | SHA-256 |
|---|---|---|---|---|---|
| s3 | 2006-03-01 | `rest-xml` | 111 | — | `f11e9149d16fcc226a85456d1d5d4a2258041818f1a64027007f76ce535f2eb3` |
| sqs | 2012-11-05 | `json` | 23 | `AmazonSQS`, json 1.0, **`awsQueryCompatible`** | `282d08c85a2003ab91ed400a81339fe81952e446ae40a599877705903e870c0f` |
| dynamodb | 2012-08-10 | `json` | 57 | `DynamoDB_20120810`, json 1.0 | `b180021688e8721f44d4f03a033b75370b5e4b969d9556a2cbd086d09a6ae746` |
| sts | 2011-06-15 | `query` | 11 | — | `b2c35d56d093494a539db6af3ddbcb601d614260b82e1351932323bd40cf9921` |
| iam | 2010-05-08 | `query` | 176 | global per account | `bd1c8b61ff7e557edf27c4ed1c977cad8dc6279335e2384d9fd054d4b6b0a6bd` |
| lambda | 2015-03-31 | `rest-json` | 85 | — | `39dedcf72ef0d4cc7d69f916d93c9c13dbb7286da9aa09dfffb191f7cf9b213e` |

**Tier 1 total: 463 operations.** That is the denominator in `/_emulator/coverage`; the numerator only ever goes up.

Two API versions ship in the wheel for some services and are deliberately **not** vendored: `dynamodb/2011-12-05` (pre-2012) and `lambda/2014-11-11` (pre-2015). The plan's kernel is the current model only.

## Verified against the data, not assumed

- **SQS is `json` with `awsQueryCompatible`.** This confirms §2.2's dual-codec requirement: modern SDKs send JSON 1.0 with `X-Amz-Target: AmazonSQS.*`, while older clients still send form-encoded Query. The generated `QUERY_COMPATIBLE` constant comes from that trait, not from a hardcoded table.
- **S3 is `rest-xml` with 111 operations** — the largest protocol surface in Tier 1 and the reason M1 is where the codec gets built.
- **IAM is 176 operations of `query`**, which is why it is generated and mostly `run: None` in v1: Terraform needs a subset, and protocol-correct `NotImplemented` beats missing operations.

## Updating

1. `pip3 download --no-deps -d /tmp/bcdl botocore==<new-version>`
2. Unzip the wheel, and for each service in the table above: `gunzip -c botocore/data/<svc>/<api-version>/service-2.json.gz > services/<svc>/service-2.json`
3. Refresh `LICENSE.txt` / `NOTICE` from the wheel's `.dist-info`.
4. Recompute the hashes above (`shasum -a 256 services/*/service-2.json`).
5. Regenerate the models and run `cargo test -p models`: the coverage report will print the new per-service op counts, and any operation that changed shape will fail a fixture test. Both are expected to be reviewed in the same commit, together with this table.
6. Update §5.2 of `PLAN.md` if the pin or the op counts are quoted there.

A model bump is never a silent change: the generated files are checked in, so the diff is the review.
