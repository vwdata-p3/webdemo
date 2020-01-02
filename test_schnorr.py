import unittest
import copy
import random

import elgamal
import schnorr
import ed25519

import pep3_pb2

class DHTProof(unittest.TestCase):
    def test_create(self):
        M = ed25519.Point.random()
        a = ed25519.scalar_random()

        ct = schnorr.DHTProof.create(a, M)
        
        A = ed25519.Point.B_times(a)
        N = M*a

        self.assertTrue(ct.is_valid_proof_for(A, M, N))

        self.assertFalse(ct.is_valid_proof_for(ed25519.Point.random(), M, N))
        self.assertFalse(ct.is_valid_proof_for(A, ed25519.Point.random(), N))
        self.assertFalse(ct.is_valid_proof_for(A, M, ed25519.Point.random()))

        ct_ = copy.deepcopy(ct)
        ct_._R_M = ed25519.Point.random()
        self.assertFalse(ct_.is_valid_proof_for(A, M, N))

        ct_ = copy.deepcopy(ct)
        ct_._R_B = ed25519.Point.random()
        self.assertFalse(ct_.is_valid_proof_for(A, M, N))

        ct_ = copy.deepcopy(ct)
        ct_._s = ed25519.scalar_random()
        self.assertFalse(ct_.is_valid_proof_for(A, M, N))

    def test_pack(self):
        M = ed25519.Point.random()
        a = ed25519.scalar_random()

        ct = schnorr.DHTProof.create(a, M)
        self.assertEqual(schnorr.DHTProof.unpack(ct.pack()), ct)


class RSKProof(unittest.TestCase):
    def test_create(self):
        M = ed25519.Point.random()
        y = ed25519.Point.random()
        r = ed25519.scalar_random()
        n = ed25519.scalar_random()
        k = ed25519.scalar_random()
        triple_in = elgamal.encrypt(M, y)
        rskp, triple_out = schnorr.RSKProof.create(triple_in, k, n, r)
        
        self.assertEqual(triple_out,
                triple_in.rerandomize(r).reshuffle(n).rekey(k))

        self.assertTrue(rskp.is_valid_proof_for( triple_in, 
                ed25519.Point.B_times(k), ed25519.Point.B_times(n),
                triple_out))

    def test_pack(self):
        M = ed25519.Point.random()
        y = ed25519.Point.random()
        r = ed25519.scalar_random()
        n = ed25519.scalar_random()
        k = ed25519.scalar_random()
        triple_in = elgamal.encrypt(M, y)
        rskp, triple_out = schnorr.RSKProof.create(triple_in, k, n, r)
        
        self.assertEqual(rskp, schnorr.RSKProof.unpack(rskp.pack()))

class RSProof(unittest.TestCase):
    def test_create(self):
        M = ed25519.Point.random()
        y = ed25519.Point.random()
        r = ed25519.scalar_random()
        n = ed25519.scalar_random()
        triple_in = elgamal.encrypt(M, y)
        rsp, triple_out = schnorr.RSProof.create(triple_in, n, r)
        
        self.assertEqual(triple_out,
                triple_in.rerandomize(r).reshuffle(n))

        self.assertTrue(rsp.is_valid_proof_for( triple_in, 
                ed25519.Point.B_times(n), triple_out))

    def test_pack(self):
        M = ed25519.Point.random()
        y = ed25519.Point.random()
        r = ed25519.scalar_random()
        n = ed25519.scalar_random()
        triple_in = elgamal.encrypt(M, y)
        rsp, triple_out = schnorr.RSProof.create(triple_in, n, r)
        
        self.assertEqual(rsp, schnorr.RSProof.unpack(rsp.pack()))


class CertifiedComponent(unittest.TestCase):
    def test_create(self):
        k = ed25519.scalar_random()
        k_powers = [ ed25519.Point.B_times(pow(k,2**i,ed25519.l))
                for i in range(253) ]

        e = 0
        cc = schnorr.CertifiedComponent.create(k,e)
        self.assertTrue(cc.is_valid_proof_for(e, k_powers))

        i = random.choice(range(253))
        e = 2**i
        cc = schnorr.CertifiedComponent.create(k,e)
        self.assertTrue(cc.is_valid_proof_for(e, k_powers))

        e = ed25519.scalar_random()
        cc = schnorr.CertifiedComponent.create(k,e)
        self.assertTrue(cc.is_valid_proof_for(e, k_powers))
        
        cc_ = copy.deepcopy(cc)
        cc_._component = ed25519.Point.random()
        self.assertFalse(cc_.is_valid_proof_for(e, k_powers))

    def test_to_protobuf(self):
        msg = pep3_pb2.CertifiedComponent()
        k = ed25519.scalar_random()
        e = ed25519.scalar_random()
        cc = schnorr.CertifiedComponent.create(k,e)
        cc.to_protobuf(msg)
        self.assertEqual(cc, schnorr.CertifiedComponent.from_protobuf(msg))
        

class ProductProof(unittest.TestCase):
    def test_create(self):
        # N = 0
        dht_proof, factors, product = schnorr.ProductProof.create( () )
        self.assertEqual(len(factors), 0)
        self.assertEqual(product, ed25519.Point.B_times(1))
        self.assertTrue(dht_proof.is_valid_proof_for(product, factors))

        # N = 1
        a = ed25519.scalar_random()
        dht_proof, factors, product = schnorr.ProductProof.create( (a,) )
        self.assertEqual(len(factors), 1)
        self.assertEqual(factors[0], product)
        self.assertEqual(product, ed25519.Point.B_times(a))
        self.assertTrue(dht_proof.is_valid_proof_for(product, factors))

        self.assertFalse(dht_proof.is_valid_proof_for(product, ()))
        factors[0] = ed25519.Point.random()
        self.assertFalse(dht_proof.is_valid_proof_for(product, factors))
        
        N = 10  ##
        factors_scalars = [ ed25519.scalar_random() for i in range(N) ]
        dht_proof, factors, product = \
                schnorr.ProductProof.create(factors_scalars)
        self.assertTrue(dht_proof.is_valid_proof_for(product, factors))

        product_scalar = 1
        for factor in factors_scalars:
            product_scalar *= factor

        self.assertEqual(product, ed25519.Point.B_times(product_scalar))

        self.assertFalse(dht_proof.is_valid_proof_for(
            ed25519.Point.random(), factors))

        i = random.choice(range(N))
        self.assertFalse(dht_proof.is_valid_proof_for(
            product, factors[:i]+factors[i+1:]))
        self.assertFalse(dht_proof.is_valid_proof_for(
            product, factors[:i]+[ed25519.Point.random()]+factors[i:]))

    def test_to_protobuf(self):
        msg = pep3_pb2.ProductProof()
        pp, factors, product = schnorr.ProductProof.create( 
                [ ed25519.scalar_random() for i in range(10) ] )
        pp.to_protobuf(msg)
        self.assertEqual(pp, schnorr.ProductProof.from_protobuf(msg))

if __name__ == '__main__':
    unittest.main()
