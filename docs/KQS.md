# Running kachat-domains in Kaspa Quick Start (2026-10-07)

**For:** the Kaspa Quick Start (KQS) session. **From:** the iOS session.

The owner's goal is that **".kachat domains" is an installable app in KQS**, so anyone can run it.
When the contracts or the deployed registry change, the operator clicks **Update**. KQS then:
- rebuilds this repo;
- checks the new manifest against the contract source;
- hands it to the testnet indexer;
- restarts the indexer if the registry changed.

That replaces the manifest copy KQS ships today (`manager/lib/names/kachat-names-testnet-10.json`
and "Use the testnet-10 manifest"), which needs a KQS commit for every deployment.

The repo is **public** (since 2026-10-07), so KQS can build it from a git context like the bot.

## 1. The image

`Dockerfile` at the repo root. It's a multi-stage build: the Rust `kachat-names` CLI, then a
`debian:bookworm-slim` runtime holding the binary plus `contracts/`, `params/`, `artifacts/` and
`manifests/`.

```sh
docker build -t kaspa-one-click/kachat-domains:main \
  --build-arg KACHAT_DOMAINS_COMMIT=<sha> \
  https://github.com/KaspaSilver/kachat-domains.git#main
```

- **First build:** it compiles rusty-kaspa crates, rocksdb and gRPC, so expect it to be slow
  (15+ minutes on a small server, several GB of build cache).
- **Later builds** reuse BuildKit cache mounts (cargo registry, git and target).
- **Runtime image:** small, with no compiler.
- **Commit label:** pass the commit as `KACHAT_DOMAINS_COMMIT`. It's echoed by `version`, written
  into `kachat-domains.json`, and set as the OCI label `org.opencontainers.image.revision`. That's
  how KQS tells which commit an installed image is.

## 2. Commands (`docker run --rm …`)

| Command | What it does | Writes |
|---|---|---|
| `publish` (mount a dir at `/names`) | For each network with a deployed manifest (testnet-10, and mainnet once it exists): runs `verify`; if it passes, copies `manifests/kachat-names-<network>.json` into `/names/` and writes `/names/kachat-domains-<network>.json` (its verify summary). The testnet-10 summary is also written as `/names/kachat-domains.json`, as before. Writes are atomic (temp file + rename). | Per network, only on success; exit 1 if any network failed |
| `verify` (`--json` for machines; `--network mainnet` for mainnet) | Recompiles the name, gap and offer from `contracts/*.sil` + `params/<network>.json` with the pinned silverscript library. It then requires the committed artifacts, the manifest's templates, its genesis binding (registry id = covenant id of the genesis outpoint and gap) and every manifest param to match. Offline: no node, no key. | Nothing |
| `verify --live --indexer <url> --node grpc://<host>:16210` | Also **proves the indexer's name list is exactly the registry on chain**. It reads `/names/all`, works out every gap and name address from it, and requires each to hold a registry UTXO of the right value (section 2.1). Needs a node with `--utxoindex`. | Nothing |
| `version` | The commit the image was built from | Nothing |
| anything else | Passed to `kachat-names`, e.g. `prices`, `status --node grpc://kaspad-testnet:16210` | See the CLI |

`kachat-domains.json` (from `verify --json`):

```json
{
  "ok": true,
  "network": "testnet-10",
  "registryVersion": 4,
  "registryCovenantId": "e6b72448…7f0d",
  "genesisTxid": "5ffdd006…a777",
  "scanFrom": "f08cac7e…2161",
  "templateHashes": { "KachatGap": "…", "KachatName": "…", "KachatOffer": "…" },
  "params": { "bond": …, "periodMs": 86400000, "graceMs": 21600000, "renewWindowMs": 7200000, "prices": {…}, … },
  "manifest": "manifests/kachat-names-testnet-10.json",
  "manifestSha256": "da65845a…",
  "commit": "<sha>"
}
```

### 2.1 `verify --live`: the indexer, proven against the chain

The approach is taken from supertypo/dotk-covenants' verifier. The registry's live gaps and names
partition the key space, and all of them carry the registry covenant id. So from the indexer's
full list of names:
- every gap between the sorted keys must exist on chain, which proves no name is hidden or
  invented;
- every name must exist with exactly the listed owner, price and dates.

Without `--indexer` it proves this CLI's own scan (`state/`) instead.

With `--json`, the summary gains
`"live": {"ok": true, "source": <url>, "names": N, "gaps": N+1, "node": <url>}`.

KQS can run it on a schedule against its own indexer and node:
`docker run --rm kaspa-one-click/kachat-domains:<ref> verify --live --json --indexer http://kachat-app-testnet:3080 --node grpc://kaspad-testnet:16210`.
Show the result as "Indexer proven against chain" on the status card.

- **A transient failure is possible right after a block** that registers or exits a name, if the
  list and the node answer are taken at different moments. Retry once before alerting.
- **It needs the indexer's `GET /names/all`** (kachat-indexer `docs/KACHAT_NAMES_ALL.md`). Until
  that endpoint exists, `--indexer` fails with a 404.

`verify` fails on all of the following, each tested in `tools/kachat-names-cli/tests/verify.rs`:
- a manifest param that differs from params;
- params that don't compile to the committed artifacts;
- a manifest whose templates or registry id don't match.

## 3. What KQS needs

An app entry next to `bot`, using the patterns the panel already has:

- **Definition.** `repo: 'KaspaSilver/kachat-domains'` and image
  `kaspa-one-click/kachat-domains:${KACHAT_DOMAINS_REF:-main}`.
  - It's a **tool, not a service.** There is no long-running container and no port. Every action
    is a `docker run --rm`, like `botGenerateWallet`.
  - Gate it on the testnet indexer (`kachat-testnet`) being installed. Today the registry exists
    only on testnet-10.
- **Install** = build the image, then **publish**:
  1. `docker run --rm -v ${STACK_DIR}/conf/names:/names kaspa-one-click/kachat-domains:<ref> publish`
  2. `applyNamesManifest('kachat-names-testnet-10.json')`. This is the existing function; it sets
     `KACHAT_NAMES_MANIFEST_TESTNET` and restarts the indexer.
- **Update.** The update check compares the GitHub API commit of `KaspaSilver/kachat-domains@<ref>`
  with the image's `org.opencontainers.image.revision`, as the other apps do. Then:
  1. rebuild the image with `--pull`;
  2. run `publish` again;
  3. restart the indexer **only if** `registryCovenantId` or `manifestSha256` in the new
     `kachat-domains.json` differs from the previous one. A docs-only commit must not restart it.
  - If `publish` fails, keep the previous manifest and show the error. Never hand the indexer an
    unverified one.
- **Status card**, from `conf/names/kachat-domains.json`:
  - network, registry id, genesis, commit, template hashes, timing, and the price tables;
  - next to the indexer's `/names/status`, with a warning when the indexer reports another
    registry id.
- **Retire** the bundled manifest and "Use the testnet-10 manifest" once this works. Keep "Use a
  manifest file" for operators who pin their own.
- **Network switch.** See section 5: `publish` already handles both networks.

## 4. Owner tools (later, testnet only)

The CLI has a mainnet mode since 2026-10-09 (`--network mainnet`), but the panel should offer
these on testnet only. It can run a registry from a server:
- `keygen`, `address` and `balance`;
- `genesis` (a dry run unless `--submit`), `status` and `scan`.

It needs two persistent mounts:
- `${STACK_DIR}/conf/kachat-domains/secrets:/opt/kachat-domains/.secrets` (the deployer key, mode 600);
- `${STACK_DIR}/conf/kachat-domains/state:/opt/kachat-domains/state`.

Not now, for two reasons:
- **Mainnet:** never. A mainnet genesis stays a deliberate, audited step outside the panel.
- **A KQS genesis isn't read by any app on its own.** The apps pin template hashes and bundle the
  manifest, so a new deployment goes live only when its manifest is committed here and the app is
  updated. So the panel would save only the command-line step. Its other operators would only be
  spending their own TKAS on registries nobody reads, which is harmless but pointless.

## 5. Mainnet (2026-10-09)

**For:** the KQS session. **From:** the kachat-domains session. Nothing changes for KQS until the
mainnet genesis (`docs/MAINNET.md`). When it lands, `manifests/kachat-names-mainnet.json` appears in
this repo, and the next **Update** publishes it.

**What `publish` does now** (`docker/entrypoint.sh`):
- **testnet-10:** as before. `kachat-names-testnet-10.json` and `kachat-domains.json` are written,
  plus the new `kachat-domains-testnet-10.json` (the same summary).
- **mainnet**, once its manifest exists: `kachat-names-mainnet.json` and
  `kachat-domains-mainnet.json`.
- **Each network is verified on its own.** A network that fails `verify` gets nothing written, the
  other is still published, and `publish` exits 1.

**What KQS needs:**
1. **A mainnet manifest for the mainnet indexer**, the counterpart of `applyNamesManifest` /
   `KACHAT_NAMES_MANIFEST_TESTNET`. For example, `KACHAT_NAMES_MANIFEST_MAINNET` pointing at
   `conf/names/kachat-names-mainnet.json`, applied only when that file exists.
2. **Gate on the mainnet indexer being installed**, as the testnet manifest is gated on
   `kachat-testnet`.
3. **Restart rule per network:** restart an indexer only when its own network's `registryCovenantId`
   or `manifestSha256` changed (`kachat-domains-<network>.json`).
4. **Status card:** one block per network, keyed on `network`. Before the mainnet genesis there's
   no `kachat-domains-mainnet.json`; show "mainnet: not deployed".
5. **Owner tools stay testnet-only** in the panel. The mainnet genesis is run by hand
   (`docs/MAINNET.md`), never from the panel.

