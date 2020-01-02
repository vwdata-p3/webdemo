import elgamal
import ed25519
import unittest

class triple(unittest.TestCase):
    def test_encryption(self):
        m = ed25519.Point.random()
        x = ed25519.scalar_random()
        y = ed25519.Point.B() * x
        self.assertEqual(m, elgamal.encrypt(m, y).decrypt(x))

    def test_rerandomization(self):
        m = ed25519.Point.random()
        y = ed25519.Point.random()
        r = ed25519.scalar_random()
        s = ed25519.scalar_random()
        
        self.assertEqual(
                elgamal.encrypt(m,y,r).rerandomize(s),
                elgamal.encrypt(m,y,r+s)
            )

    def test_rekey(self):
        m = ed25519.Point.random()
        y = ed25519.Point.random()
        r = ed25519.scalar_random()
        k = ed25519.scalar_random()

        self.assertEqual(
                elgamal.encrypt(m,y,r).rekey(k),
                elgamal.encrypt(m,y*k,ed25519.scalar_inv(k)*r)
            )       
        
    def test_reshuffle(self):
        m = ed25519.Point.random()
        y = ed25519.Point.random()
        r = ed25519.scalar_random()
        n = ed25519.scalar_random()

        self.assertEqual(
                elgamal.encrypt(m,y,r).reshuffle(n),
                elgamal.encrypt(m*n,y,r*n)
            )       

    def test_rsk(self):
        m = ed25519.Point.random()
        y = ed25519.Point.random()
        r = ed25519.scalar_random()
        n = ed25519.scalar_random()
        k = ed25519.scalar_random()
        r2 = ed25519.scalar_random()

        triple = elgamal.encrypt(m,y,r)

        self.assertEqual(
                triple.rsk(k,n,r2),
                triple.rekey(k).reshuffle(n).rerandomize(r2)
            )

    def test_invalid_decryption(self):
        m = ed25519.Point.random()
        x = ed25519.scalar_random()
        y = ed25519.Point.B() * x
        with self.assertRaises(elgamal.WrongPrivateKey):
            elgamal.encrypt(m,y).decrypt(x+1)
        

if __name__ == '__main__':
    unittest.main(verbosity=3)
