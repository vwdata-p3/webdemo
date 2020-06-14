from ed25519 import *
import unittest
import os
import functools

class testfe(unittest.TestCase):
    def testpack(self):
        f = fe_random()
        self.assertEqual(fe_unpack(fe_pack(f)),f)

    def testsqrt(self):
        for i in range(20):
            f = fe_random()
            self.assertEqual(fe_sqrt(f**2%q)**2%q,f**2%q)

    def testinv(self):
        f = fe_random()
        if f!=0:
            self.assertEqual((f*fe_inv(f))%q,1)
        self.assertRaises(DivisionByZero, lambda: fe_inv(0))
        self.assertEqual(fe_inv(-f),q-fe_inv(f))

    def testfactorization_of_ell_minus_1(self):
        f = [2, 2, 3, 11, 
                198211423230930754013084525763697,
                276602624281642239937218680557139826668747]
        self.assertEqual(functools.reduce(lambda x,y: x*y, f, 1), l-1)

class testReferencePoint(unittest.TestCase):
    def test_basepoint(self):
        self.assertTrue(ReferencePoint.B.is_exactly(
            ReferencePoint.unpack(ReferencePoint.B.pack())))

    def test_basepoint_x(self):
        UnnormalizedB = ReferencePoint.from_y_and_sign(
                        4*fe_inv(5), True, check=False)
        self.assertTrue(
            ( 8*fe_inv(547505)-1 - UnnormalizedB.x**2) % q ==0)

        self.assertFalse(fe_is_positive(
            UnnormalizedB.x*UnnormalizedB.y))

        self.assertEqual(ReferencePoint.B.x,
                (-i*fe_inv(5)*4 )%q)

    def test_order_of_the_baseReferencePoint(self):
        self.assertEqual(ReferencePoint.B*l, ReferencePoint.Zero)

    def test_neg(self):
        a = ReferencePoint.random()
        self.assertTrue((a-a).is_exactly(ReferencePoint.Zero))

    def test_odd(self):
        self.assertRaises(Odd, lambda: ReferencePoint( 3000226150035073529908023436571072806992287498960698235119705265207080648378, 8665657100173288816593402575771921995144513349282114765923171703131048775885 ))

    def test_pack(self):
        for i in range(5):
            a = ReferencePoint.random()
            self.assertEqual(ReferencePoint.unpack(a.pack()),a)

    def test_even_when_sqrt_exists(self):
        for i in range(10):
            y = fe_random()
            x2 = ( (y**2-1)*fe_inv(d*y**2+1) ) % q
            s2 = ( (1-y)*fe_inv(1+y) )%q
            try:
                x = fe_sqrt(x2)
            except NotASquare as e:
                continue
            self.assertEqual(0, (y**2-x**2-1-d*x**2*y**2)%q)
            odd = False
            try:
                ReferencePoint(x,y)
            except Odd as e:
                odd = True
            self.assertEqual(not odd, fe_is_sqrt(s2))


    def test_zero_neutral(self):
        a = ReferencePoint.random()
        self.assertEqual(a+ReferencePoint.Zero, a)

    def test_sum_assoc(self):
        a = ReferencePoint.random()
        b = ReferencePoint.random()
        c = ReferencePoint.random()
        self.assertEqual((a+b)+c,a+(b+c))

    def test_sum_com(self):
        a = ReferencePoint.random()
        b = ReferencePoint.random()
        self.assertEqual(a+b,b+a)

    def test_scalar_one(self):
        a = ReferencePoint.random()
        self.assertEqual(a * 1,a)
        self.assertEqual(a*0,ReferencePoint.Zero)

    def test_scalar_additive(self):
        s = fe_random()
        t = fe_random()
        a = ReferencePoint.random()
        self.assertEqual(a*s + a*t,a*(s+t))

    def test_montgomery(self):
        a = ReferencePoint.random()
        (u,v) = a.montgomery()
        self.assertEqual( (v**2)%q, (u**3+486662*u**2+u)%q )
        b = ReferencePoint.from_montgomery(u,v)
        self.assertEqual(a,b)
        self.assertEqual( ReferencePoint(0,-1).montgomery(), ReferencePoint.Zero.montgomery() )
    
    def test_equivalence_class(self):
        for i in range(5):
            a = ReferencePoint.random()
            for b in a.equivalence_class():
                self.assertEqual(a,b)

    def test_jacobi_quartic_eq(self):
        for i in range(5):
            a = ReferencePoint.random()
            for b in a.equivalence_class():
                self.assertEqual(
                        a.jacobi_quartic(),
                        b.jacobi_quartic())

    def test_jacobi_quartic_add(self):
        for i in range(5):
            if i==0:
                a = ReferencePoint(0,-1,check=False)
            elif j==1:
                a = ReferencePoint(0,1,check=False)
            else:
                a = ReferencePoint.random()
            for j in range(5):
                if j==0:
                    b = ReferencePoint(0,-1,check=False)
                elif j==1:
                    b = ReferencePoint(0,1,check=False)
                else:
                    b = ReferencePoint.random()

                self.assertTrue(
                        (a+b).jacobi_quartic().is_exactly_or_dual(
                            a.jacobi_quartic() + b.jacobi_quartic()))

    def test_jacobi_quartic(self):
        for i in range(5):
            a = ReferencePoint.random()
            jc = a.jacobi_quartic()
            jc.check()
            self.assertTrue(a._jacobi_quartic_slow().is_exactly_or_dual(jc))

    def test_elligator_inv_sound(self):
        for i in range(10):
            if i==0:    a=ReferencePoint(0,1)
            if i==1:    a=ReferencePoint(0,-1)
            else:       a = ReferencePoint.random()
            for x in a.elligator2_inv():
                self.assertEqual(a,ReferencePoint.elligator2(x))

    def test_elligator_inv_complete(self):
        for j in range(10):
            if j==0:    x=0
            elif j==1:  x=fe_inv(i*d)
            else:       x=fe_random()

            if not fe_is_positive(x):
                x = q-x
            a = ReferencePoint.elligator2(x)
            preimage =  set(a.elligator2_inv())
            self.assertIn(x,preimage)
            
            for b in a.equivalence_class():
                self.assertEqual(preimage, set(b.elligator2_inv()))

    def test_vectors_elligator(self):
        self.assertEqual(
                ReferencePoint.elligator2(0),
                ReferencePoint.Zero
            )
        self.assertEqual(
                ReferencePoint.elligator2(1),
                ReferencePoint(17038878585347986768021303549519759439676382507827068040125689651013072529301,15230320631590039580979663173198108071753105466334302150961433644360598089897, check=False)
            )
        self.assertEqual(
                ReferencePoint.elligator2(2),
                ReferencePoint(1335590479826203857246232570199730890826925083796062191270611349584872410064,47657002845471692740411082244280207988476146161922146202597930022203326266525, check=False)

            )
        self.assertEqual(
                ReferencePoint.elligator2(3),
                ReferencePoint(22882958585688737307984762219110293283341183846752716971618030508922484076184,28482820381801306826493551477645936426868527672949180042757655085093782860496, check=False)
            )
        self.assertEqual(
                ReferencePoint.elligator2(4),
                ReferencePoint(51249134547538547108243238284984120501190567480038570796306077359558385821835,57040261483818956997066720241160185225662349583538669866709113165314909246211, check=False)
            )

    def test_lizard(self):
        for i in range(10):
            data = os.urandom(16)
            a = ReferencePoint.lizard(data)
            a.normalize() # without this the first or second preimage
                          # will always work
            self.assertEqual(data, a.lizard_inv()) 
    
    def _test_lizard_collisions(self):
        N = 30
        collision_count = 0
        # I suspect the chance of a collision is about (1-2^-15)^3.5
        for i in range(10000):
            data = os.urandom(N)
            a = ReferencePoint.lizard(data, N=N)
            a.normalize()
            if a.lizard_inv(N=N)!=data:
                print(f"collision: {data}")
                collision_count += 1
        print(collision_count)

    def test_hyperbolic_equation(self):
        a1 = ReferencePoint.random()
        u = pow(a1.x,2,q)
        v = pow(a1.y,2,q)
        self.assertEqual(
                ( (v-u+2*fe_inv(d))**2 - (u+v)**2 )%q ,
                ( 4*fe_inv(d**2)*(1+d) )%q
                )


class testPoint(unittest.TestCase):
    def test_addition(self):
        a = Point.random()
        b = Point.random()
        a_ = a.refpoint()
        b_ = b.refpoint()
        a_plus_b_ = a_ + b_

        self.assertEqual(a_plus_b_, (a+b).refpoint() )
        
        # test in-place addition
        a += b
        self.assertEqual(a.refpoint(), a_plus_b_)

    def test_double(self):
        a = Point.random()
        self.assertEqual( a.double().refpoint(), a.refpoint().double() )

    def test_B_times(self):
        s = scalar_random()
        self.assertEqual( Point.B() * s, Point.B_times(s) )

    def test_jacobi_quartic(self):
        for i in range(10):
            if i==0:
                a = Point(0,1,1,1)
            elif i==1:
                a = Point(0,-1,1,-1)
            else:
                a = Point.random()
            self.assertTrue(a.jacobi_quartic().is_exactly_or_dual(
                a.refpoint().jacobi_quartic()))

    def test_is_zero(self):
        a = Point.random()
        self.assertEqual(a.is_zero(), a==Point.Zero())
        for a in Point.Zero().equivalence_class():
            self.assertTrue(a.is_zero()) 


    def test_four_finite_jacobi_quartics(self):
        for i_ in range(10):
            a = Point.random()
            jc1, jc2, jc3, jc4 = list(a.four_finite_jacobi_quartics())
            self.assertTrue(a.jacobi_quartic().is_exactly_or_dual(jc1))
            self.assertTrue(Point(a.X,a.Y,-a.Z,a.T).jacobi_quartic()\
                    .is_exactly_or_dual(jc2))
            self.assertTrue(Point(a.Y,a.X,i*a.Z,-a.T).jacobi_quartic()\
                    .is_exactly_or_dual(jc3))
            self.assertTrue(Point(a.Y,a.X,-i*a.Z,-a.T).jacobi_quartic()\
                    .is_exactly_or_dual(jc4))

class testJacobiQuartic(unittest.TestCase):
    def test_to_jacobi_and_back(self):
        for i in range(10):
            if i==0: a = ReferencePoint(0,1)
            elif i==1: a = ReferencePoint(0,-1)
            else: a = ReferencePoint.random()

            self.assertTrue(a.jacobi_quartic().refpoint().is_exactly(a))

    def test_from_jacobi_and_back(self):
        for i in range(5):
            a = JacobiQuartic.random().re_z()
            self.assertTrue(a.refpoint().jacobi_quartic()\
                    .is_exactly_or_dual(a))
        for i in range(5):
            a = JacobiQuartic.random_infinite().re_z()
            self.assertTrue(a.refpoint().jacobi_quartic()\
                    .is_exactly_or_dual(a))

    def test_zero(self):
        for i in range(5):
            a = JacobiQuartic.random()
            self.assertTrue(a.is_exactly(a+JacobiQuartic.Zero()))

    def test_neg(self):
        for i in range(5):
            a = JacobiQuartic.random()
            self.assertTrue((a-a).is_exactly(JacobiQuartic.Zero()))

    def test_eq1(self):
        for i in range(5):
            a = JacobiQuartic.random()
            z = fe_random()
            b = JacobiQuartic( a._sz*z, a._tz2*z*z, a._z*z)
            self.assertEqual(a, b)
            self.assertEqual(a.st(),b.st())

    def test_eq2(self):
        for i in range(5):
            a = JacobiQuartic.random()
            ap = a.refpoint()
            for b in a.equivalence_class():
                bp = b.refpoint()
                self.assertEqual(ap,bp)

    def test_eq3(self):
        for i in range(5):
            a = JacobiQuartic.random()
            for b in a.equivalence_class():
                self.assertEqual(a,b)

    def test_elligator(self):
        for j in range(10):

            if j==0:    x = 0
            elif j==1:  x = fe_sqrt(i*d)
            else:       x = fe_random()

            y = JacobiQuartic.elligator2(x).elligator2_inv()
            
            if fe_is_positive(x):
                self.assertEqual(x,y)
            else:
                self.assertEqual(x,q-y)

    def test_elligator_inv(self):
        for j in range(10):

            if j==0:    a = JacobiQuartic(0,1)
            elif j==1:  a = JacobiQuartic(0,-1)
            elif j==2:  a = JacobiQuartic(1,1,0)
            elif j==3:  a = JacobiQuartic(1,-1,0)
            else:       a = JacobiQuartic.random()

            try:
                b = JacobiQuartic.elligator2(a.elligator2_inv())
            except NoPreimage:
                continue
            a.is_exactly(b)

    def test_random(self):
        JacobiQuartic.random().check()

    def test_refpoint(self):
        for i in range(5):
            a = JacobiQuartic.random()
            rp = a.refpoint()
            rp.check()
            self.assertEqual(rp, a._refpoint_st())

    def test_point(self):
        for i in range(10):
            if i%2==0:
                a = JacobiQuartic.random_infinite().re_z()
            else:
                a = JacobiQuartic.random()
            self.assertTrue(a.point().is_exactly(
                    Point.from_refpoint(a.refpoint())))

    def test_is_exactly(self):
        for i in range(5):
            # finite points
            a = JacobiQuartic.random()
            a1 = a.re_z()
            a2 = a.re_z()
            self.assertTrue(a1.is_exactly(a2))
            self.assertTrue(a1._is_exactly_st(a2))
            b = JacobiQuartic.random().re_z()
            self.assertFalse(a1.is_exactly(b))
            self.assertFalse(a1._is_exactly_st(b))
            
            # infinite points
            a = JacobiQuartic(1,1,0)
            b = JacobiQuartic(1,-1,0)
            self.assertFalse(a.is_exactly(b))
            self.assertFalse(b.is_exactly(a))
            a1 = a.re_z()
            a2 = a.re_z()
            b1 = b.re_z()
            b2 = b.re_z()
            self.assertTrue(a1.is_exactly(a2))
            self.assertTrue(b1.is_exactly(b2))
            self.assertFalse(a1.is_exactly(b1))


    def test_add(self):
        for i in range(5):
            a = JacobiQuartic.random()
            b = JacobiQuartic.random()
            a_plus_b = a+b
            a_plus_b.check()
            self.assertTrue(
                    a_plus_b.refpoint().is_exactly(a.refpoint()+b.refpoint()))
            self.assertTrue(a_plus_b.is_exactly(a._add_st(b)))

            b = JacobiQuartic.random_infinite()
            a_plus_b = a+b
            a_plus_b.check()
            self.assertTrue(
                    a_plus_b.refpoint().is_exactly(a.refpoint()+b.refpoint()))

            a = JacobiQuartic.random_infinite()
            a_plus_b = a+b
            a_plus_b.check()
            self.assertTrue(
                    a_plus_b.refpoint().is_exactly(a.refpoint()+b.refpoint()))


class test_small_subgroup(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        self.alpha = fe_sqrt((1+fe_sqrt(1+d))*fe_inv(d))

    def test_alpha(self):
        self.assertEqual(0, (d*self.alpha**4 - 2 * self.alpha**2-1)%q)
        y = self.alpha*i
        x = self.alpha
        self.assertEqual(0, (y**2-x**2-1-d*x**2*y**2)%q)
        a = ReferencePoint(x,y,check=False)
        self.assertTrue((a*2).is_exactly(ReferencePoint(-i,0)))
        self.assertTrue((a*3).is_exactly(ReferencePoint(
            self.alpha,-i*self.alpha, check=False)))
        self.assertTrue((a*4).is_exactly(ReferencePoint(0,-1)))
        self.assertTrue((a*5).is_exactly(ReferencePoint(
            -self.alpha, -i*self.alpha, check=False)))
        self.assertTrue((a*6).is_exactly(ReferencePoint(i, 0)))
        self.assertTrue((a*7).is_exactly(ReferencePoint(
            -self.alpha, i*self.alpha, check=False)))
        self.assertTrue((a*8).is_exactly(ReferencePoint(0,1)))
        

if __name__ == '__main__':
    unittest.main(verbosity=3)
