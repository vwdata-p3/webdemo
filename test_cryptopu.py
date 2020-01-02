import cryptopu
import ed25519
import unittest
import elgamal
import schnorr
import pep3_pb2

class cryptoputest(unittest.TestCase):
    def setUp(self):
        self.pu = cryptopu.CryptoPU()

    def test_rsk(self):
        N = 5
        
        n = ed25519.scalar_random()
        k = ed25519.scalar_random()
        r = [ ed25519.scalar_random() for i in range(N) ]

        target = ed25519.Point.random()

        triples = [ elgamal.encrypt(
            ed25519.Point.random(),
            target) for i in range(N) ]

        pseudonyms = [ pep3_pb2.Pseudonymizable() for i in range(N) ]

        for i in range(N):
            pseudonyms[i].data = triples[i].pack()

        self.pu.rsk(pseudonyms, k, n, r)

        for i in range(N):
            triples[i] = triples[i].rsk(k,n,r[i])

        self.assertEqual(
                [ triples[i] for i in range(N) ],
                [ elgamal.Triple.unpack(pseudonyms[i].data)
                    for i in range(N) ]
            )

    def test_component_public_part(self):
        scalar = ed25519.scalar_random()
        y = self.pu.component_public_part(scalar)
        self.assertEqual(y,
                [ ed25519.Point.B_times(pow(scalar, 2**i, ed25519.l)).pack()
                    for i in range(253) ]
                )

    def test_certified_component_create(self):
        k = ed25519.scalar_random()
        e = ed25519.scalar_random()
        
        cc_protobuf = pep3_pb2.CertifiedComponent() 
        self.pu.certified_component_create(cc_protobuf,
                self.pu.component_public_part(k),
                k, e)

        cc = schnorr.CertifiedComponent.create(k,e)
        cc_protobuf2 = pep3_pb2.CertifiedComponent() 
        cc.to_protobuf(cc_protobuf2)

        self.assertEqual(cc_protobuf2, cc_protobuf)

        self.assertTrue(self.pu.certified_component_is_valid_for(
            cc_protobuf, self.pu.component_public_part(k), e))


if __name__ == '__main__':
    unittest.main(verbosity=3)
