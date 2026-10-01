#!/usr/bin/env python3
"""Compile the .kachat contracts for one network with the pinned silverc.

usage: build.py <silverc> <params.json> <out_dir>

Order (no template-hash cycles):
  1. KachatName   (bakes: bond, maxYears, graceMs, renewPrices)
  2. KachatGap    (bakes: name template hash + layout, bond, gapValue, tCommit, maxYears, prices)
  3. KachatOffer  (bakes: registry covenant id, name template hash + layout, offerMaxFee)
     -- only once params.registryCovenantId is set (after the genesis transaction).

Writes <out_dir>/KachatName.json, KachatGap.json, [KachatOffer.json], build-info.json.
"""
import hashlib, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ZERO32 = [0] * 32


def I(v):
    return {"kind": "int", "value": v}


def B(v):
    return {"kind": "bytes", "value": list(v)}


def compile_contract(silverc, source, ctor, out_path):
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(ctor, f)
        ctor_path = f.name
    try:
        subprocess.run([silverc, source, '--constructor-args', ctor_path, '-o', out_path], check=True)
    finally:
        os.unlink(ctor_path)
    art = json.load(open(out_path))
    (name, contract), = art['contracts'].items()
    return contract


def layout(contract):
    bc = contract['compiled']['bytecode']
    span = contract['compiled']['state_span']
    prefix_len = span['offset']
    suffix_len = len(bc) - span['offset'] - span['len']
    return {
        'bytecodeLen': len(bc),
        'stateSpan': span,
        'prefixLen': prefix_len,
        'suffixLen': suffix_len,
        'templateHash': bytes(contract['compiled']['template_hash']).hex(),
        'dispatchTags': {k: v['dispatch_tag'] for k, v in contract['entries'].items()},
        'bytecodeSha256': hashlib.sha256(bytes(bc)).hexdigest(),
    }


def main():
    silverc, params_path, out_dir = sys.argv[1:4]
    p = json.load(open(params_path))
    os.makedirs(out_dir, exist_ok=True)
    src = lambda n: os.path.join(ROOT, 'contracts', n + '.sil')
    pr = p['prices']
    if not 1 <= p['maxYears'] <= 31:
        sys.exit('maxYears must be 1..31 (renew adds at most maxYears * YEAR_MS < 1e12 to expiresAt)')

    rp = p['renewPrices']
    name = compile_contract(silverc, src('KachatName'), [
        B(ZERO32), B(ZERO32), B(ZERO32), I(0), I(0),
        I(p['bond']), I(p['maxYears']), I(p['graceMs']),
        I(rp['len1']), I(rp['len2']), I(rp['len3']), I(rp['len4']), I(rp['len5plus']),
    ], os.path.join(out_dir, 'KachatName.json'))
    nl = layout(name)

    gap = compile_contract(silverc, src('KachatGap'), [
        B(bytes.fromhex(p['genesisGap']['lo'])), B(bytes.fromhex(p['genesisGap']['hi'])),
        B(bytes.fromhex(nl['templateHash'])), I(nl['prefixLen']), I(nl['suffixLen']),
        I(p['bond']), I(p['gapValue']), I(p['tCommit']), I(p['maxYears']),
        I(pr['len1']), I(pr['len2']), I(pr['len3']), I(pr['len4']), I(pr['len5plus']),
    ], os.path.join(out_dir, 'KachatGap.json'))
    gl = layout(gap)

    info = {
        'network': p['network'],
        'compiler': p['compiler'],
        'params': {k: p[k] for k in ('bond', 'gapValue', 'tCommit', 'maxYears', 'graceMs', 'prices', 'renewPrices', 'offerMaxFee', 'genesisGap')},
        'registryCovenantId': p.get('registryCovenantId'),
        'contracts': {'KachatName': nl, 'KachatGap': gl},
    }

    cov = p.get('registryCovenantId')
    offer_path = os.path.join(out_dir, 'KachatOffer.json')
    if cov:
        cov_bytes = bytes.fromhex(cov)
        if len(cov_bytes) != 32 or cov_bytes == bytes(32):
            sys.exit('registryCovenantId must be 32 non-zero bytes')
        offer = compile_contract(silverc, src('KachatOffer'), [
            B(ZERO32), B(ZERO32), I(0), B(cov_bytes),
            B(bytes.fromhex(nl['templateHash'])), I(nl['prefixLen']), I(nl['suffixLen']),
            I(p['offerMaxFee']),
        ], offer_path)
        info['contracts']['KachatOffer'] = layout(offer)
    else:
        if os.path.exists(offer_path):
            os.unlink(offer_path)
        info['contracts']['KachatOffer'] = 'not built: set registryCovenantId after the genesis transaction'

    with open(os.path.join(out_dir, 'build-info.json'), 'w') as f:
        json.dump(info, f, indent=2)
        f.write('\n')
    print(f"{p['network']}: name {nl['bytecodeLen']} B ({nl['templateHash'][:16]}..), "
          f"gap {gl['bytecodeLen']} B ({gl['templateHash'][:16]}..)"
          + (f", offer {info['contracts']['KachatOffer']['bytecodeLen']} B" if cov else ', offer pending genesis'))


if __name__ == '__main__':
    main()
