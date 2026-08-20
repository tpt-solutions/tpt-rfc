p = 'tpt-ed25519/src/field.rs'
s = open(p, encoding='utf-8').read()
old = (
    '        let mut la = [0u64; 4];\n'
    '        let mut lb = [0u64; 4];\n'
    '        la[0] = 0x6789_0123_4567_89ab; la[1] = 0x0123_4567_89ab_cdef;\n'
    '        lb[0] = 0x4321_0987_6543_21fe; lb[1] = 0x1234_5678_9abc_def0;\n'
    '        let fa = FieldElement { limbs: la };\n'
    '        let fb = FieldElement { limbs: lb };\n'
    '        let got = fa.mul(&fb).limbs;\n'
    '        let exp = [5028810136116278185u64, 13116507783923719358, 11529394757068899353, 4639];\n'
    '        assert_eq!(got, exp, "big product mismatch");'
)
new = (
    '        let la = [0xabcdef0123456789, 0x1234567890, 0x0, 0x0];\n'
    '        let lb = [0x6543210987654321, 0xfedcba0987, 0x0, 0x0];\n'
    '        let fa = FieldElement { limbs: la };\n'
    '        let fb = FieldElement { limbs: lb };\n'
    '        let got = fa.mul(&fb).limbs;\n'
    '        let exp = [0x45c9ec2cce1833a9, 0xb6073255d26b5cbe, 0xa000a3723a57c419, 0x121f];\n'
    '        assert_eq!(got, exp, "big product mismatch");'
)
assert old in s, 'anchor not found'
s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
print('patched big product')
