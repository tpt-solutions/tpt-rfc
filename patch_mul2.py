p = 'tpt-ed25519/src/field.rs'
s = open(p, encoding='utf-8').read()
old = (
    '        let c = FieldElement::from_u64(u64::MAX);\n'
    '        let cp = c.mul(&c);\n'
    '        assert_eq!(cp.limbs[0], 38, "(2^64-1)^2 mod p low limb");'
)
new = (
    '        let c = FieldElement::from_u64(u64::MAX);\n'
    '        let cp = c.mul(&c);\n'
    '        assert_eq!(cp.limbs, [1, 18446744073709551614, 0, 0], "(2^64-1)^2 mod p");'
)
assert old in s, 'anchor not found'
s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
print('fixed')
