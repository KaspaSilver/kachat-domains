#!/bin/sh
# kachat-domains image entrypoint (docs/KQS.md).
#
#   publish [DIR]  verify, then copy the deployed manifest into DIR (default /names)
#                  and write DIR/kachat-domains.json (the verify summary). Nothing is
#                  written if verify fails.
#   verify         check the manifest against contracts/ + params/ (exit 1 on a mismatch)
#   version        the commit this image was built from
#   anything else  passed to `kachat-names` (prices, status --node ..., ...)
set -eu

cmd="${1:-verify}"
[ $# -gt 0 ] && shift

case "$cmd" in
  publish)
    dir="${1:-/names}"
    [ -d "$dir" ] || { echo "publish: $dir is not a directory (mount one at /names)" >&2; exit 2; }
    summary="$(kachat-names verify --json)" || { echo "publish: verify failed, nothing published" >&2; exit 1; }
    net_manifest="$(printf '%s' "$summary" | sed -n 's/^  "manifest": "\(.*\)",$/\1/p')"
    [ -n "$net_manifest" ] || { echo "publish: no manifest path in the verify summary" >&2; exit 1; }
    name="$(basename "$net_manifest")"
    # write next to the target, then rename: the indexer never reads half a file
    cp "$KACHAT_DOMAINS_ROOT/$net_manifest" "$dir/.$name.tmp"
    mv "$dir/.$name.tmp" "$dir/$name"
    printf '%s\n' "$summary" > "$dir/.kachat-domains.json.tmp"
    mv "$dir/.kachat-domains.json.tmp" "$dir/kachat-domains.json"
    echo "published $name and kachat-domains.json to $dir"
    printf '%s\n' "$summary" | grep -E '^  "(network|registryCovenantId|manifestSha256|commit)":' | sed 's/,$//'
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
