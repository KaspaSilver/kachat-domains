#!/bin/sh
# kachat-domains image entrypoint (docs/KQS.md).
#
#   publish [DIR]  for every network with a deployed manifest (testnet-10, mainnet):
#                  verify it, then copy it into DIR (default /names) and write
#                  DIR/kachat-domains-<network>.json (its verify summary). The testnet-10
#                  summary is also written as DIR/kachat-domains.json (the name KQS has
#                  read since before mainnet). A network whose verify fails gets nothing
#                  written, and publish exits 1.
#   verify         check the manifest against contracts/ + params/ (exit 1 on a mismatch;
#                  --network mainnet for mainnet)
#   version        the commit this image was built from
#   anything else  passed to `kachat-names` (prices, status --node ..., ...)
set -eu

cmd="${1:-verify}"
[ $# -gt 0 ] && shift

case "$cmd" in
  publish)
    dir="${1:-/names}"
    [ -d "$dir" ] || { echo "publish: $dir is not a directory (mount one at /names)" >&2; exit 2; }
    published=0
    failed=0
    for net in testnet-10 mainnet; do
      [ -f "$KACHAT_DOMAINS_ROOT/manifests/kachat-names-$net.json" ] || continue
      summary="$(kachat-names --network "$net" verify --json)" || {
        echo "publish: $net verify failed, nothing published for $net" >&2
        failed=1
        continue
      }
      net_manifest="$(printf '%s' "$summary" | sed -n 's/^  "manifest": "\(.*\)",$/\1/p')"
      [ -n "$net_manifest" ] || { echo "publish: no manifest path in the $net verify summary" >&2; failed=1; continue; }
      name="$(basename "$net_manifest")"
      # write next to the target, then rename: the indexer never reads half a file
      cp "$KACHAT_DOMAINS_ROOT/$net_manifest" "$dir/.$name.tmp"
      mv "$dir/.$name.tmp" "$dir/$name"
      printf '%s\n' "$summary" > "$dir/.kachat-domains-$net.json.tmp"
      mv "$dir/.kachat-domains-$net.json.tmp" "$dir/kachat-domains-$net.json"
      if [ "$net" = testnet-10 ]; then
        printf '%s\n' "$summary" > "$dir/.kachat-domains.json.tmp"
        mv "$dir/.kachat-domains.json.tmp" "$dir/kachat-domains.json"
      fi
      echo "published $name and kachat-domains-$net.json to $dir"
      printf '%s\n' "$summary" | grep -E '^  "(network|registryCovenantId|manifestSha256|commit)":' | sed 's/,$//'
      published=$((published + 1))
    done
    [ "$published" -gt 0 ] || [ "$failed" -ne 0 ] || { echo "publish: no deployed manifest in manifests/" >&2; exit 1; }
    exit "$failed"
    ;;
  verify)
    exec kachat-names verify "$@"
    ;;
  version)
    echo "${KACHAT_DOMAINS_COMMIT:-unknown}"
    ;;
  *)
    exec kachat-names "$cmd" "$@"
    ;;
esac
