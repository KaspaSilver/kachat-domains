#!/usr/bin/env python3
"""Disassemble a silverc artifact (or raw hex) using the opcode table of rusty-kaspa a41a333.
usage: disasm.py artifact.json | disasm.py --hex <hex>"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
OPS = {}
for line in open(os.path.join(HERE, 'opcodes.txt')):
    c, n, _ = line.split(); OPS[int(c, 16)] = n
def num(b):
    if not b: return 0
    v = int.from_bytes(b, 'little')
    if b[-1] & 0x80:
        v &= ~(0x80 << (8 * (len(b) - 1))); v = -v
    return v
def dis(bc):
    i = 0; out = []
    while i < len(bc):
        op = bc[i]; start = i; i += 1
        if 1 <= op <= 0x4b:
            d = bytes(bc[i:i+op]); i += op
            extra = f' (num {num(d)})' if op <= 8 else ''
            out.append(f'{start:5d}: PUSH{op} {d.hex()}{extra}')
        elif op in (0x4c, 0x4d, 0x4e):
            w = {0x4c: 1, 0x4d: 2, 0x4e: 4}[op]; n = int.from_bytes(bytes(bc[i:i+w]), 'little'); i += w
            d = bytes(bc[i:i+n]); i += n
            out.append(f'{start:5d}: PUSHDATA{w} len={n} {d.hex()[:200]}{"..." if n > 100 else ""}')
        else:
            out.append(f'{start:5d}: {OPS.get(op, hex(op))}')
    return out
if __name__ == '__main__':
    if sys.argv[1] == '--hex':
        bc = bytes.fromhex(sys.argv[2])
    else:
        a = json.load(open(sys.argv[1]))
        bc = bytes(list(a['contracts'].values())[0]['compiled']['bytecode'])
    print('\n'.join(dis(bc)))
