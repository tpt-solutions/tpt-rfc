p = 'tpt-ed25519/src/point.rs'
s = open(p, encoding='utf-8').read()
old = (
    '        eprintln!("OC base = {}", on_curve(&b));\n'
    '        eprintln!("OC d2   = {}", on_curve(&b.add(&b)));\n'
    '    }'
)
new = (
    '        eprintln!("OC base = {}", on_curve(&b));\n'
    '        let d2 = b.add(&b);\n'
    '        eprintln!("OC d2   = {}", on_curve(&d2));\n'
    '        let zin = d2.z.invert();\n'
    '        eprintln!("d2 aff x = {:?}", d2.x.mul(&zin).to_bytes());\n'
    '        eprintln!("d2 aff y = {:?}", d2.y.mul(&zin).to_bytes());\n'
    '    }'
)
assert old in s, 'anchor not found'
s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
print('patched tmp_probe affine')
