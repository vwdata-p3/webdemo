import ed25519
import elgamal
import schnorr
import common
import _ristretto as ristretto

import unittest
import os
import random

class ristrettotest(unittest.TestCase):
    def test_triple_rsk(self):
        m = ed25519.Point.random()
        y = ed25519.Point.random()
        r = ed25519.scalar_random()
        s = ed25519.scalar_random()
        k = ed25519.scalar_random()
        r2 = ed25519.scalar_random()

        triple = elgamal.encrypt(m,y,r2)
        
        ctriple = ristretto.ffi.new("elgamal_triple*")
        ck = ristretto.ffi.new("group_scalar*")
        cs = ristretto.ffi.new("group_scalar*")
        cr = ristretto.ffi.new("group_scalar*")

        ristretto.lib.elgamal_triple_unpack(ctriple, 
                triple.blinding.pack() + 
                triple.core.pack() + 
                triple.target.pack())
        ristretto.lib.group_scalar_unpack(ck, ed25519.scalar_pack(k))
        ristretto.lib.group_scalar_unpack(cs, ed25519.scalar_pack(s))
        ristretto.lib.group_scalar_unpack(cr, ed25519.scalar_pack(r))

        ristretto.lib.elgamal_triple_rsk(ctriple, ctriple, ck, cs, cr)

        cbuf = ristretto.ffi.new("unsigned char []", 96)
        ristretto.lib.elgamal_triple_pack(cbuf, ctriple)
        
        buf = ristretto.ffi.buffer(cbuf)

        triple2 = elgamal.Triple(
                ed25519.Point.unpack(buf[0:32]),
                ed25519.Point.unpack(buf[32:64]),
                ed25519.Point.unpack(buf[64:96]))
        
        triple = triple.rsk(k,s,r)
        
        self.assertEqual(triple.blinding, triple2.blinding)
        self.assertEqual(triple.core, triple2.core)
        self.assertEqual(triple.target, triple2.target)

    def test_triples_rsk(self):
        n = 5

        target = ed25519.Point.random()

        triples = [ elgamal.encrypt(
                    ed25519.Point.random(),
                    target,
                    ed25519.scalar_random()) for i in range(n) ]

        cblindings = ristretto.ffi.new("group_ge[]", n) 
        ccores = ristretto.ffi.new("group_ge[]", n) 
        ctarget = ristretto.ffi.new("group_ge*")

        for i in range(n):
            self.assertEqual(0, ristretto.lib.group_ge_unpack(
                ristretto.ffi.addressof(cblindings, i),
                triples[i].blinding.pack()))
            self.assertEqual(0, ristretto.lib.group_ge_unpack(
                ristretto.ffi.addressof(ccores, i),
                triples[i].core.pack()))

        self.assertEqual(0, 
                ristretto.lib.group_ge_unpack(ctarget, target.pack()))

        s = ed25519.scalar_random()
        k = ed25519.scalar_random()
        rs = [ ed25519.scalar_random() for i in range(n) ]
        
        cs = ristretto.ffi.new("group_scalar*")
        ck = ristretto.ffi.new("group_scalar*")
        crs = ristretto.ffi.new("group_scalar[]", n)

        self.assertEqual(0, ristretto.lib.group_scalar_unpack(cs, 
            ed25519.scalar_pack(s)))
        self.assertEqual(0, ristretto.lib.group_scalar_unpack(ck, 
            ed25519.scalar_pack(k)))

        for i in range(n):
            self.assertEqual(0, ristretto.lib.group_scalar_unpack(
                ristretto.ffi.addressof(crs, i), 
                ed25519.scalar_pack(rs[i])))

        ristretto.lib.elgamal_triples_rsk(
                cblindings, ccores, cblindings, ccores,
                ctarget, ctarget, ck, cs, crs, n)
        
        cbuf = ristretto.ffi.new("unsigned char[]", 32)
        buf = ristretto.ffi.buffer(cbuf)

        for i in range(n):
            triple = triples[i].rsk(k,s,rs[i])

            ristretto.lib.group_ge_pack(cbuf,
                    ristretto.ffi.addressof(cblindings, i))
            self.assertEqual( buf[:], triple.blinding.pack())
            
            ristretto.lib.group_ge_pack(cbuf,
                    ristretto.ffi.addressof(ccores, i))
            self.assertEqual( buf[:], triple.core.pack())

            ristretto.lib.group_ge_pack(cbuf, ctarget)
            self.assertEqual( buf[:], triple.target.pack())


    def test_triples_pack_and_unpack(self):
        n = 5

        triples = [ elgamal.encrypt(
                    ed25519.Point.random(),
                    ed25519.Point.random(),
                    ed25519.scalar_random()) for i in range(n) ]
        
        cbuf1 = ristretto.ffi.new("unsigned char[]", n*96)

        for i in range(n):
            ristretto.ffi.memmove(cbuf1 + 96*i, triples[i].pack(), 96) 

        ctriples = ristretto.ffi.new("elgamal_triple[]", n)
        cerror_codes = ristretto.ffi.new("int[]", n)

        ristretto.lib.elgamal_triples_unpack(ctriples, cbuf1, cerror_codes, n)
        
        for i in range(n):
            self.assertEqual(cerror_codes[i], 0)

        cbuf2 = ristretto.ffi.new("unsigned char[]", n*96)

        ristretto.lib.elgamal_triples_pack(cbuf2, ctriples, n)

        self.assertEqual(
                [ cbuf1[i] for i in range(96*n) ], 
                [ cbuf2[i] for i in range(96*n) ])

    
    def test_triple_encrypt(self):
        a = ed25519.Point.random()
        t = ed25519.Point.random()
        r = ed25519.scalar_random()

        ca = point_to_c(a)
        ct = point_to_c(t)
        cr = scalar_to_c(r)

        ctriple = ristretto.ffi.new("elgamal_triple*")
        
        ristretto.lib.elgamal_triple_encrypt(ctriple, ca, ct, cr)

        triple = triple_from_c(ctriple)

        self.assertEqual(triple, elgamal.encrypt(a,t,r))


    def test_triple_decrypt(self):
        key = ed25519.scalar_random()

        t = elgamal.encrypt( ed25519.Point.random(), ed25519.Point.B_times(key))

        ckey = scalar_to_c(key)
        ct = triple_to_c(t)
        cresult = point_to_c(ed25519.Point.Zero())
        
        ristretto.lib.elgamal_triple_decrypt(cresult, ct, ckey)

        result = point_from_c(cresult)

        self.assertEqual(result, t.decrypt(key))


    def test_scalar_unpack(self):
        for i in range(10):
            data = os.urandom(32)

            cscalar = ristretto.ffi.new("group_scalar*")
            ristretto.lib.group_scalar_unpack(cscalar, data)

            cbuf = ristretto.ffi.new("unsigned char[]", 32)
            ristretto.lib.group_scalar_pack(cbuf, cscalar)

            buf = ristretto.ffi.buffer(cbuf)
            self.assertEqual(ed25519.scalar_unpack(data),
                    ed25519.scalar_unpack(buf[:]))

    def test_invsqrti(self):
        for i in range(10):
            data = os.urandom(32)
            cbuf = ristretto.ffi.new("unsigned char[]", 32)
            ca = ristretto.ffi.new('fe25519*')
            cb = ristretto.ffi.new('fe25519*')
            ristretto.lib.fe25519_unpack(ca, data)
            iss = ristretto.lib.fe25519_invsqrti(cb, ca)
            ristretto.lib.fe25519_pack(cbuf, cb)
            a = ed25519.fe_unpack(data)
            b = ed25519.fe_unpack(ristretto.ffi.buffer(cbuf)[:])
            if iss:
                a2 = a
            else:
                a2 = (a * ed25519.i) % ed25519.q
            self.assertEqual( (b*a2*b*a2) % ed25519.q, a2)

    def test_sqrti(self):
        for i in range(10):
            data = os.urandom(32)
            cbuf = ristretto.ffi.new("unsigned char[]", 32)
            ca = ristretto.ffi.new('fe25519*')
            cb = ristretto.ffi.new('fe25519*')
            ristretto.lib.fe25519_unpack(ca, data)
            iss = ristretto.lib.fe25519_sqrti(cb, ca)
            ristretto.lib.fe25519_pack(cbuf, cb)
            a = ed25519.fe_unpack(data)
            b = ed25519.fe_unpack(ristretto.ffi.buffer(cbuf)[:])
            if iss:
                a2 = a
            else:
                a2 = (a * ed25519.i) % ed25519.q
            self.assertEqual( (b*b) % ed25519.q, a2)


    def test_elligator2(self):
        for i in range(100):
            data = os.urandom(32)
            cfe = ristretto.ffi.new('fe25519*')
            ristretto.lib.fe25519_unpack(cfe, data)
            res = ristretto.ffi.new('group_ge*')
            ristretto.lib.group_ge_elligator(res, cfe)
            cbuf = ristretto.ffi.new('unsigned char[]', 32)
            ristretto.lib.group_ge_pack(cbuf, res)
            buf = ristretto.ffi.buffer(cbuf)
            a = ed25519.ReferencePoint.unpack(buf[:])
            self.assertEqual(a, 
                    ed25519.ReferencePoint.elligator2(ed25519.fe_unpack(data)))

    def test_component_public_part(self):
        x = ed25519.scalar_random()
        cy = ristretto.ffi.new('group_ge[]',253)
        ristretto.lib.component_public_part(cy, scalar_to_c(x))
        y = points_from_c(cy, 253)
        for i in range(253):
            self.assertEqual(y[i],
                    ed25519.Point.B_times(pow(x,2**i,ed25519.l)))

    def test_sha256(self):
        for i in range(10):
            n = random.randint(10,200)
            data = os.urandom(n)
            cbuf = ristretto.ffi.new("unsigned char[]", 32)
            buf = ristretto.ffi.buffer(cbuf)
            ristretto.lib.sha256(data, n, cbuf)
            self.assertEqual(buf[:], common.sha256(data))

    def test_dht_proof_create(self):
        cbuf = ristretto.ffi.new("unsigned char[]", 96)
        buf = ristretto.ffi.buffer(cbuf)

        for i in range(10):
            a = ed25519.scalar_random()
            m = ed25519.scalar_random()
            A = ed25519.Point.B_times(a)
            M = ed25519.Point.B_times(m)
            N = M*a

            if i%2==0:
                cm = scalar_to_c(m)
                cM = ristretto.ffi.NULL
            else:
                cm = ristretto.ffi.NULL
                cM = point_to_c(M)
            
            ristretto.lib.dht_proof_create(
                    cbuf, 
                    scalar_to_c(a), ed25519.scalar_pack(a), A.pack(),
                    cm, cM, M.pack(),
                    point_to_c(N), N.pack())

            self.assertEqual(schnorr.DHTProof.create(a,M).pack(),
                    buf[:])

    def test_dht_proof_is_valid(self):
        M = ed25519.Point.random()
        a = ed25519.scalar_random()

        ct = schnorr.DHTProof.create(a, M)

        A = ed25519.Point.B_times(a)
        N = M*a

        cA = point_to_c(A)
        cM = point_to_c(M)
        cN = point_to_c(N)

        A_packed = A.pack()
        M_packed = M.pack()
        N_packed = N.pack()

        ct_packed = ct.pack()

        self.assertTrue(ristretto.lib.dht_proof_is_valid_for(
                ct_packed, cA, cM, cN, A_packed, M_packed, N_packed))

        R = ed25519.Point.random()
        cR = point_to_c(R)
        R_packed = R.pack()

        self.assertFalse(ristretto.lib.dht_proof_is_valid_for(
                ct_packed, cR, cM, cN, R_packed, M_packed, N_packed))
        self.assertFalse(ristretto.lib.dht_proof_is_valid_for(
                ct_packed, cA, cR, cN, A_packed, R_packed, N_packed))
        self.assertFalse(ristretto.lib.dht_proof_is_valid_for(
                ct_packed, cA, cM, cR, A_packed, M_packed, R_packed))

        self.assertFalse(ristretto.lib.dht_proof_is_valid_for(
                os.urandom(32)+ct_packed[32:], 
                cA, cM, cN, A_packed, M_packed, N_packed))

        self.assertFalse(ristretto.lib.dht_proof_is_valid_for(
                ct_packed[:32] + os.urandom(32) + ct_packed[64:],
                cA, cM, cN, A_packed, M_packed, N_packed))

        self.assertFalse(ristretto.lib.dht_proof_is_valid_for(
                ct_packed[:64] + os.urandom(32),
                cA, cM, cN, A_packed, M_packed, N_packed))

    def test_product_proof_create(self):
        N = 10

        factors_scalar = [ ed25519.scalar_random() for i in range(N) ]
        product_scalar = 1

        cfactors_scalar_packed = ristretto.ffi.new("unsigned char[]", 32*N)
        cfactors_packed = ristretto.ffi.new("unsigned char[]", 32*N)
        cfactors = ristretto.ffi.new("group_ge[]", N)
        cfactors_scalar_packed_buf \
                = ristretto.ffi.buffer(cfactors_scalar_packed)
        cfactors_packed_buf  = ristretto.ffi.buffer(cfactors_packed)

        for i in range(N):
            factor_scalar = factors_scalar[i]
            product_scalar *= factor_scalar

            factor_scalar_packed = ed25519.scalar_pack(factor_scalar)
            cfactors_scalar_packed_buf[32*i:32*(i+1)] = factor_scalar_packed

            factor = ed25519.Point.B_times(factor_scalar)
            cfactors_packed_buf[32*i:32*(i+1)] = factor.pack()

        cerror_codes = ristretto.ffi.new("int[]", N)
        ristretto.lib.group_ges_unpack(cfactors, cfactors_packed, 
                cerror_codes, N)

        cfactors_scalar = ristretto.ffi.new("group_scalar[]", N)

        ristretto.lib.group_scalars_unpack(cfactors_scalar,
                cfactors_scalar_packed, cerror_codes, N)

        product = ed25519.Point.B_times(product_scalar)
        cproduct = point_to_c(product)
        
        cpp = ristretto.ffi.new("product_proof*")
        cpp.number_of_factors = N

        cpartial_products = ristretto.ffi.new("unsigned char[]", 32*max(N-2,0))
        cpp.partial_products = cpartial_products
        # if we don't use the variable "cpartial_products" to keep
        # the python object returned by ffi.new(...) alive, the memory
        # will be freed immediately (and possibly overriden in the next
        # lines leading to strange bugs).

        cdht_proofs = ristretto.ffi.new("unsigned char[]", 96*max(N-1,0))
        cpp.dht_proofs = cdht_proofs

        ristretto.lib.product_proof_create(cpp, cfactors_scalar,
                cfactors_scalar_packed, cfactors_packed)

        pp, _, _ = schnorr.ProductProof.create(factors_scalar)
        
        dht_proofs_buf = ristretto.ffi.buffer(cpp.dht_proofs, 96*max(N-1,0))
        partial_products_buf = ristretto.ffi.buffer(
                cpp.partial_products, 32*max(N-2,0))

        for i in range(max(N-1,0)):
            self.assertEqual(pp._dht_proofs[i].pack(),
                    dht_proofs_buf[96*i:96*(i+1)])
            if i<N-2:
                self.assertEqual(pp._partial_products[i].pack(),
                        partial_products_buf[32*i:32*(i+1)])

        self.assertTrue(ristretto.lib.product_proof_is_valid_for(cpp,
                cfactors, cfactors_packed, cproduct, product.pack()))


        # wrong product
        R = ed25519.Point.random()
        R_packed = R.pack()
        cR = point_to_c(R)

        self.assertFalse(ristretto.lib.product_proof_is_valid_for(cpp,
                cfactors, cfactors_packed, cR, R_packed))


        # wrong factor
        i = random.randint(0,N-1)

        cT = ristretto.ffi.new("group_ge*")
        cT[0] = cfactors[i]
        T_packed = cfactors_packed_buf[i*32:(i+1)*32]

        cfactors[i] = cR[0]
        cfactors_packed_buf[i*32:(i+1)*32] = R_packed

        self.assertFalse(ristretto.lib.product_proof_is_valid_for(cpp,
                cfactors, cfactors_packed, cproduct, product.pack()))

        cfactors[i] = cT[0]
        cfactors_packed_buf[i*32:(i+1)*32] = T_packed
        
        # wrong partial product
        i = random.randint(0,N-3)

        T_packed = partial_products_buf[i*32:(i+1)*32]
        partial_products_buf[i*32:(i+1)*32] = os.urandom(32)
        self.assertFalse(ristretto.lib.product_proof_is_valid_for(cpp,
                cfactors, cfactors_packed, cproduct, product.pack()))
        partial_products_buf[i*32:(i+1)*32] = T_packed

        # wrong dht proof
        i = random.randint(0,N-2)

        T_packed = dht_proofs_buf[i*96:(i+1)*96]
        dht_proofs_buf[i*96:(i+1)*96] = os.urandom(96)
        self.assertFalse(ristretto.lib.product_proof_is_valid_for(cpp,
                cfactors, cfactors_packed, cproduct, product.pack()))
        dht_proofs_buf[i*96:(i+1)*96] = T_packed


    def test_group_scalar_tstbit(self):
        s = ed25519.scalar_random()
        ones = set(schnorr.ones_of(s))
        cs = scalar_to_c(s)
        for i in range(253):
            result, = ristretto.lib.scalar_tstbit(cs, i),
            if i in ones:
                self.assertEqual(result, 1)
            else:
                self.assertEqual(result, 0)

    def test_certified_component_create(self):
        k = ed25519.scalar_random()
        e = ed25519.scalar_random()

        ones = schnorr.ones_of(e)
        N = len(list(ones))

        ccc = ristretto.ffi.new("certified_component*")
        cpp = ccc.product_proof

        # prepare cpp
        cpp.number_of_factors = N
        cpartial_products = ristretto.ffi.new("unsigned char[]", 
                32*max(N-2,0))
        cpp.partial_products = cpartial_products
        cdht_proofs = ristretto.ffi.new("unsigned char[]", 96*max(N-1,0))
        cpp.dht_proofs = cdht_proofs

        # prepare cbase_powers_packed
        cbase_powers_packed = ristretto.ffi.new("unsigned char[]", 32*253)
        cbase_powers = ristretto.ffi.new("group_ge[]", 253)
        ristretto.lib.component_public_part(cbase_powers, scalar_to_c(k))
        ristretto.lib.group_ges_pack(cbase_powers_packed, cbase_powers, 253)

        ristretto.lib.certified_component_create(ccc,
                cbase_powers_packed,
                scalar_to_c(k),
                scalar_to_c(e))

        cc = schnorr.CertifiedComponent.create(k, e)
        pp = cc._product_proof

        self.assertEqual(cc._component.pack(), 
                ristretto.ffi.buffer(ccc.component)[:])


        dht_proofs_buf = ristretto.ffi.buffer(cpp.dht_proofs, 96*max(N-1,0))
        partial_products_buf = ristretto.ffi.buffer(
                cpp.partial_products, 32*max(N-2,0))

        for i in range(max(N-1,0)):
            self.assertEqual(pp._dht_proofs[i].pack(),
                    dht_proofs_buf[96*i:96*(i+1)])
            if i<N-2:
                self.assertEqual(pp._partial_products[i].pack(),
                        partial_products_buf[32*i:32*(i+1)])

        self.assertTrue(ristretto.lib.certified_component_is_valid_for(
                ccc, cbase_powers_packed, scalar_to_c(e)))

        # wrong exponent
        self.assertFalse(ristretto.lib.certified_component_is_valid_for(
                ccc, cbase_powers_packed, 
                scalar_to_c(ed25519.scalar_random())))

        # TODO: add tests for wrong product proof and base powers

def fe_to_c(fe):
    result = ristretto.ffi.new("fe25519*")
    ristretto.lib.fe25519_unpack(result, ed25519.fe_pack(fe))
    return result

def scalar_to_c(scalar):
    result = ristretto.ffi.new("group_scalar*")
    assert(0==ristretto.lib.group_scalar_unpack(result,
            ed25519.scalar_pack(scalar)))
    return result

def point_to_c(p):
    result = ristretto.ffi.new("group_ge*")
    assert(0==ristretto.lib.group_ge_unpack(result,p.pack()))
    return result

def point_from_c(cp):
    cbuf = ristretto.ffi.new("unsigned char[]", 32)
    ristretto.lib.group_ge_pack(cbuf, cp)
    return ed25519.Point.unpack([ cbuf[i] for i in range(len(cbuf))])

def points_from_c(cp, N):
    cbuf = ristretto.ffi.new("unsigned char[]", 32*N)
    ristretto.lib.group_ges_pack(cbuf, cp, N)
    return [ ed25519.Point.unpack(cbuf[i*32:(i+1)*32]) for i in range(N) ]

def triple_to_c(t):
    result = ristretto.ffi.new("elgamal_triple*")
    assert(0==ristretto.lib.elgamal_triple_unpack(result,t.pack()))
    return result

def triple_from_c(ct):
    cbuf = ristretto.ffi.new("unsigned char[]", 96)
    ristretto.lib.elgamal_triple_pack(cbuf, ct)
    return elgamal.Triple.unpack([ cbuf[i] for i in range(len(cbuf)) ])

if __name__ == '__main__':
    unittest.main(verbosity=3)
