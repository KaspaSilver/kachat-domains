#!/usr/bin/env bash
# Mutation check: delete (or weaken) one security check at a time, rebuild the
# artifacts, run the engine-backed suite, and report which tests catch it.
# A mutation nobody catches is either redundant (defense in depth, labelled
# "redundant" below, with what covers it) or a hole in the tests. Restores contracts/ and artifacts/ after
# each mutation. Usage: scripts/mutation-check.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ -n "$(git status --porcelain contracts artifacts)" ]]; then
  echo "contracts/ or artifacts/ have uncommitted changes; commit first" >&2; exit 1
fi

mutate() { # file old new label
  python3 - "$1" "$2" "$3" <<'PY'
import sys
f, old, new = sys.argv[1:4]
s = open(f).read()
assert old in s, f"not found in {f}: {old}"
open(f, 'w').write(s.replace(old, new, 1))
PY
  ./scripts/build.sh >/dev/null 2>&1 || { echo "  $4: BUILD FAILED"; git checkout -q -- contracts artifacts; return; }
  local out killed
  out="$(cd harness && cargo test --no-fail-fast 2>/dev/null)"
  killed="$(grep -E '^test .* FAILED$' <<<"$out" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/' | tr '\n' ' ')"
  if [[ -z "$killed" ]]; then echo "SURVIVED  $4"; else echo "killed    $4  <- $killed"; fi
  git checkout -q -- contracts artifacts
}

G=contracts/KachatGap.sil; N=contracts/KachatName.sil; O=contracts/KachatOffer.sil
mutate $G 'require(relativeLock >= tCommit, "commit matured");' '' "gap: commit maturity"
mutate $G 'require(unsigned(seq[7]) < 128, "commit sequence lock enabled");' '' "gap: sequence-lock disable bit"
mutate $G 'require(tx.inputs[1].scriptPubKey == byte[](commitLock), "commit script");' '' "gap: commit script"
mutate $G 'require(tx.time >= temporal(now));' '' "gap: now <= lock time"
mutate $G 'require(years <= maxYears, "years <= maxYears");' '' "gap: max years"
mutate $G 'require(minerFee() >= priceFor(len) * years, "price paid as miner fee");' 'require(minerFee() >= priceFor(len), "price paid as miner fee");' "gap: price x years"
mutate $G 'require(lessThan(lo, newKey), "lo < key");' '' "gap: lo < key"
mutate $G 'require(lessThan(newKey, hi), "key < hi");' '' "gap: key < hi"
mutate $G 'require(charset[unsigned(n[i])] == 0x01, "name charset");' '' "gap: charset"
mutate $G 'require(n[0] != 0x2d, "no leading hyphen");' '' "gap: leading hyphen"
mutate $G 'require(n[n.length - 1] != 0x2d, "no trailing hyphen");' '' "gap: trailing hyphen"
mutate $G 'require(OpCovOutputCount(covId) == 3, "three registry outputs");' '' "gap: register output count (redundant with AuthOutputCount(0) == 3 + one registry input)"
mutate $G 'require(tx.outputs[2].value == bond, "name bond");' '' "gap: name bond value"
mutate $G 'require(tx.inputs.length <= MAX_INPUTS, "at most 8 inputs");' '' "gap: input bound (redundant with the compiler loop guard, which TUTORIAL.md says not to rely on)"
mutate $G 'require(seated.key == hi, "name at hi");' '' "gap: merge name adjacency"
mutate $G 'require(succ.lo == hi, "successor starts at hi");' '' "gap: merge successor adjacency"
mutate $G 'require(tx.outputs[0].value == gapValue, "merged gap value");' '' "gap: merged gap value"
mutate $N 'return raw[64] == 0x01 && checkSig' 'return checkSig' "name: SIGHASH_ALL only"
mutate $N 'require(OpCovInputCount(covId) == 1, "one registry input");' '' "name: one registry input (redundant with one registry output; the pair is tested below)"
mutate $N 'require(OpCovOutputCount(covId) == 1, "one registry output");' '' "name: one registry output (redundant with one registry input + one continuation)"
mutate $N 'require(OpCovInputCount(covId) == 1, "one registry input");
        require(OpCovOutputCount(covId) == 1, "one registry output");' '' "name: one registry input AND one registry output (both removed)"
mutate $N 'require(tx.outputs[out].value == bond, "continuation keeps the bond");' '' "name: continuation value"
mutate $N 'require(tx.outputs[payout].value >= price, "payout covers the price");' '' "name: buy payout value"
mutate $N 'require(tx.outputs[payout].scriptPubKey == byte[](sellerLock), "payout to the seller");' '' "name: buy payout script"
mutate $N 'require(years <= maxYears, "years <= maxYears");' '' "name: renew max years"
mutate $N 'require(minerFee() >= renewPrice() * years, "renewal paid as miner fee");' 'require(minerFee() >= renewPrice(), "renewal paid as miner fee");' "name: renew price x years"
mutate $N 'require(tx.time >= temporal(expiresAt + graceMs));' '' "name: reclaim after grace"
mutate $N 'require(tx.outputs[1].scriptPubKey == byte[](ownerLock), "bond to the last owner");' '' "name: reclaim bond script"
mutate $N 'require(tx.outputs[1].value >= bond, "bond returned");' '' "name: reclaim bond value"
mutate $N 'require(this.activeInputIndex == 1, "seat 1");' '' "name: exit seat"
mutate $O 'require(this.activeInputIndex == nameIdx + 1, "offer right after its name");' '' "offer: adjacency"
mutate $O 'require(OpInputCovenantId(nameIdx) == registryCovId, "registry name");' '' "offer: registry id"
mutate $O 'require(cur.key == key, "the wanted name");' '' "offer: wanted key (redundant: the continuation is validated with key = the offer key)"
mutate $O 'require(tx.outputs[payout].value >= tx.inputs[this.activeInputIndex].value - maxFee, "payout covers the offer");' '' "offer: accept payout value"
mutate $O 'require(tx.daa >= refundAfter);' '' "offer: refund after"
mutate $O 'require(tx.inputs.length == 1, "refund alone");' '' "offer: refund alone"
mutate $O 'require(tx.outputs[0].scriptPubKey == byte[](buyerLock), "refund to the buyer");' '' "offer: refund script"
