p = 'tpt-ed25519/src/field.rs'
s = open(p, encoding='utf-8').read()

old = (
    '    #[test]\n'
    '    fn ref_mul_matches() {'
)
new = (
    '    #[test]\n'
    '    fn mul_known_products() {\n'
    '        // 2^60 * 2^60 = 2^120\n'
    '        let a = FieldElement::from_u64(1u64 << 60);\n'
    '        let b = FieldElement::from_u64(1u64 << 60);\n'
    '        assert_eq!(a.mul(&b).limbs, [0, 72057594037927936, 0, 0], "2^120");\n'
    '        // (2^64-1)^2 mod p\n'
    '        let c = FieldElement::from_u64(u64::MAX);\n'
    '        let cp = c.mul(&c);\n'
    '        assert_eq!(cp.limbs[0], 38, "(2^64-1)^2 mod p low limb");\n'
    '        // big product\n'
    '        let mut la = [0u64; 4];\n'
    '        let mut lb = [0u64; 4];\n'
    '        la[0] = 0x6789_0123_4567_89ab; la[1] = 0x0123_4567_89ab_cdef;\n'
    '        lb[0] = 0x4321_0987_6543_21fe; lb[1] = 0x1234_5678_9abc_def0;\n'
    '        let fa = FieldElement { limbs: la };\n'
    '        let fb = FieldElement { limbs: lb };\n'
    '        let got = fa.mul(&fb).limbs;\n'
    '        let exp = [5028810136116278185u64, 13116507783923719358, 11529394757068899353, 4639];\n'
    '        assert_eq!(got, exp, "big product mismatch");\n'
    '    }\n'
    '\n'
    '    #[test]\n'
    '    fn ref_mul_matches() {'
)
assert old in s, 'anchor not found'
s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
print('patched mul_known_products')
