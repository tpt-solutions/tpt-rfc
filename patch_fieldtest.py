p = 'tpt-ed25519/src/field.rs'
s = open(p, encoding='utf-8').read()

old = '''
    #[test]
    fn ref_mul_matches() {'''
new = (
    '    #[test]\n'
    '    fn curve_equation_holds() {\n'
    '        // For the base point y = 4/5, the recovered x must satisfy\n'
    '        // -x^2 + y^2 == 1 + d*x^2*y^2 (mod p).\n'
    '        let y = FieldElement::from_u64(4).mul(&FieldElement::from_u64(5).invert());\n'
    '        let d = FieldElement::from_u64(121665)\n'
    '            .neg()\n'
    '            .mul(&FieldElement::from_u64(121666).invert());\n'
    '        let y2 = y.square();\n'
    '        let den = y2.mul(&d).add(&FieldElement::ONE);\n'
    '        let x2 = y2.sub(&FieldElement::ONE).mul(&den.invert());\n'
    '        let lhs = y2.sub(&x2);\n'
    '        let rhs = FieldElement::ONE.add(&d.mul(&x2));\n'
    '        assert_eq!(lhs, rhs, "base x^2 fails curve equation");\n'
    '    }\n'
    '\n'
    '    #[test]\n'
    '    fn ref_mul_matches() {'
)
assert old in s, 'anchor not found'
s = s.replace(old, new)
open(p, 'w', encoding='utf-8').write(s)
print('patched field tests')
