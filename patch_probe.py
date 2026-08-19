p = 'tpt-ed25519/src/point.rs'
s = open(p, encoding='utf-8').read()
old = '        eprintln!("PK = {:?}", sk.verifying_key().to_bytes());\n    }'
new = (
    '        eprintln!("PK = {:?}", sk.verifying_key().to_bytes());\n'
    '        eprintln!("OC base = {}", on_curve(&b));\n'
    '        eprintln!("OC d2   = {}", on_curve(&b.add(&b)));\n'
    '    }'
)
assert old in s, 'old not found'
s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
print('patched')
