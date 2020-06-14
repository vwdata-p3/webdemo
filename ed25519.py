import random
import common

q = 2**255-19 # order of the field---hence the name ed25519

# order of the baseReferencePoint
l = 2**252 + 27742317777372353535851937790883648493 

d = (-121665 * pow(121666,q-2,q))%q

# (d+1)^-1 = 121666

def scalar_pack(s):
    s %= l
    result = 32*[0]
    for i in range(32):
        result[i] = s % (2**8)
        s //= (2**8)
    return bytes(result)

def scalar_unpack(data):
    if(len(data)!=32):
        raise Error("invalid encoding of scalar: length is not 32,"
                f" but {len(data)}.")

    s = 0
    for i in range(31):
        s += data[i]*pow(2, 8*i, l)
        s %= l
    # ignore first three bits
    s += (data[31]&0x1f)*pow(2,8*31,l)
    s %= l

    return s

def scalar_random():
    return random.randint(0,l-1)

def scalar_inv(s):
    s %= l
    if s==0:
        raise DivisionByZero()
    return pow(s,l-2,l) # (Fermat's little theorem)

def fe_is_positive(f):
    return (f%q)%2==0

def fe_inv(f):
    f%=q
    if f==0:
        raise DivisionByZero()
    return pow(f,q-2,q) # (Fermat's little theorem)

# returns a positive square root of f
def fe_sqrt(f):
    g = fe_sqrt_any(f)
    if fe_is_positive(g):
        return g
    return q-g

# TODO: add ref to Legendre
def fe_sqrt_any(f):
    f = f % q
    g = pow(f,(q+3)//8,q)  
    gg = g**2%q
    if gg==f:
        return g
    elif q-gg==f:
        return (pow(2,(q-1)//4,q)*g)%q
    raise NotASquare()

def fe_is_sqrt(f):
    try:
        fe_sqrt_any(f)
    except NotASquare as e:
        return False
    return True

def fe_random():
    return random.randint(0,q-1)

def fe_pack(f):
    result = 32*[0]
    f %= q
    for i in range(32):
        result[i] = f % (2**8)
        f //= (2**8)
    return bytes(result)

def fe_unpack(data):
    assert(len(data)==32)
    f = 0
    for i in range(31):
        f += data[i]*(2**(8*i))
    # ignore final bit
    f += (0b01111111 & data[31])*(2**(8*31))
    return f

i = fe_sqrt(-1)
magic = fe_inv(-fe_sqrt_any(-d-1))
# magic is the _negative_ square root of -121666

# ReferencePoint on the twisted edwards curve
#   y^2 - x^2 = 1 + dx^2y^2
class ReferencePoint:
    # TODO: correct this method to yield a proper representative
    @staticmethod
    def from_y_and_sign(y,x_is_positive,check=True):
        try:
            x = fe_sqrt((y**2-1)*fe_inv(d*y**2+1))
        except NotASquare:
            raise NotOnCurve()
        if x_is_positive!=fe_is_positive(x):
            x = -x%q
        return ReferencePoint(x,y, check=check)

    @staticmethod
    def from_s(s):
        if not fe_is_positive(s):
            raise SIsNegative()

        try:
            x = fe_sqrt( 4*s**2 * fe_inv(-d*(1-s**2)**2 - (1+s**2)**2) )
        except NotASquare:
            raise Odd()
        y = (1-s**2)*fe_inv(1+s**2)

        if not fe_is_positive(x*y):
            raise InvalidRepresentative("x*y is negative")
        if y%q==0:
            raise InvalidRepresentative("y=0")

        return ReferencePoint(x,y,check=False)

    @staticmethod
    def unpack(data):
        if len(data)!=32:
            raise InvalidEncoding(f"length={len(data)} != 32")
        elif data[31]//128!=0: # the C library ignores this last bit
            raise InvalidEncoding("last bit is not 0")
        
        return ReferencePoint.from_s(fe_unpack(data))

    @staticmethod
    def hash(data):
        return ReferencePoint.elligator2(fe_unpack(common.sha256(data)))

    @staticmethod
    def random():
        while True:
            try:
                y = fe_random()
                x_is_positive = True #(random.randint(0,1)==1)
                half = ReferencePoint.from_y_and_sign(y,x_is_positive, check=False)
            except InvalidPoint:
                continue
            return half + half

    def __init__(self,x,y, check=True):
        self.x = x % q
        self.y = y % q
        if check:
            self.check()

    def check(self):
        if (self.y**2-self.x**2)%q != (1+d*self.x**2*self.y**2)%q:
            raise NotOnCurve()
        if not (self * (4*l)).is_exactly(ReferencePoint.Zero):
            raise Odd()

    def Copy(self):
        return ReferencePoint(self.x, self.y, check=False)

    def point(self):
        return Point.from_refpoint(self)

    def normalized(self):
        x = self.x
        y = self.y

        if not fe_is_positive(x*y) or y==0:
            x,y = (y*i)%q, (x*i)%q
        if (y+1) % q == 0:  # i.e. y = -1 mod q
            y=1
        if not fe_is_positive(x):
            x,y = q-x,q-y 

        return (x,y)

    def normalize(self):
        self.x, self.y = self.normalized()

    def s(self):
        x,y = self.normalized()
        try:
            return fe_sqrt( (1-y)*fe_inv(1+y) )
        except NotASquare:
            assert(False) # should not happen if the ReferencePoint is even

    def pack(self):
        return fe_pack(self.s())
    
    def __add__(self, other):
        xden = fe_inv(1+d*self.x*other.x*self.y*other.y)
        yden = fe_inv(1-d*self.x*other.x*self.y*other.y)

        return ReferencePoint( (self.x*other.y + other.x*self.y)*xden,
                (self.y*other.y+self.x*other.x)*yden, check=False )

    def __eq__(self, other):
        if not isinstance(other, ReferencePoint):
            return NotImplemented
        return (self.x*other.y - other.x*self.y)%q==0 or \
                (self.x*other.x - self.y*other.y)%q==0

    def equivalence_class(self):
        # doesn't include the odd points
        x,y = self.x,self.y
        yield self
        yield ReferencePoint(-x,-y,check=False)
        yield ReferencePoint(i*y,i*x, check=False)
        yield ReferencePoint(-i*y,-i*x, check=False)

    def is_exactly(self,other):
        if not isinstance(other, ReferencePoint):
            return NotImplemented
        return (self.x==other.x) and (self.y==other.y)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __sub__(self, other):
        if isinstance(other,ReferencePoint):
            return self + -other
        return NotImplemented

    def double(self):
        return self+self

    def double_in_place(self):
        double = self+self
        self.x = double.x
        self.y = double.y

    def __neg__(self):
        return ReferencePoint(-self.x, self.y, check=False)

    def __mul__(self, other):
        return double_and_add_multiplication(self, other, ReferencePoint.Zero)

    def __repr__(self):
        return "ReferencePoint(%s,%s)" % (self.x, self.y)


    # The curve ed25519 is equivalent to the montgomery curve
    #      v**2 + = u**3 + 486662 u**2 + u 
    # known as curve25519.  The following methods provide the 
    # translation.
    def montgomery(self):
        x,y = self.normalized()
        u = (1-y)*fe_inv(1+y)
        v = u*fe_inv(x)*fe_sqrt(-486664) if x!=0 else 0
        return (u%q,v%q)

    @staticmethod
    def from_montgomery(u, v):
        x = (fe_sqrt(-486664)*u*fe_inv(v))%q if v!=0 else 0
        y = ((1-u)*fe_inv(1+u))%q
        return ReferencePoint(x,y)

    def _jacobi_quartic_slow(self):
        x,y = self.x, self.y
        if x==0:
            # y is now either +1 or -1
            if y==1:
                return JacobiQuartic(0,1,check=False)
            elif y==q-1:
                return JacobiQuartic(1,1,0,check=False)
            else:
                assert(False)
            return JacobiQuartic(0,y,check=False)
        s = fe_sqrt( (1-y)*fe_inv(1+y) ) # y won't be -1 here
        t = (2*s*magic * fe_inv(x))%q
        return JacobiQuartic(s,t, check=False)

    def jacobi_quartic(self):
        x,y = self.x, self.y
        if x==0:
            # y is now either +1 or -1
            if y==1:
                return JacobiQuartic(0,1,check=False)
            elif y==q-1:
                return JacobiQuartic(1,1,0,check=False)
            else:
                assert(False)

        z = ( fe_sqrt(1-pow(y,2,q))*x ) % q
        sz = ( (1-y)*x ) % q
        tz2 = ( 2*z*(1-y)*magic ) % q

        return JacobiQuartic(sz, tz2, z, check=False)

    def t(self):
        x,y = self.normalized()
        return (2*self.s()*magic*fe_inv(x)) % q

    @staticmethod
    def elligator2(x):
        return JacobiQuartic.elligator2(x).refpoint()

    def elligator2_inv(self):
        return self.point().elligator2_inv()

    @staticmethod
    def lizard(payload, N=16):
        return Point.lizard(payload,N).refpoint()

    def lizard_inv(self, N=16):
        return self.point().lizard_inv(N)

# The curve ed25519 is also equivalent to the jacobi quartic
#     s^4 + 2( 1-2d/(d+1) )s^2 + 1 = t^2
# which becomes
#     (sz)^4 + 2( 1-2d/(d+1) )(sz)^2z^2 + z^4 = (tz^2)^2
# in projective coordinates.
a_quartic = ( 1- (2*d)*fe_inv(d+1) ) % q

class JacobiQuartic:
    def __init__(self, sz, tz2, z=1, check=True):
        self._sz = sz % q
        self._tz2 = tz2 % q
        self._z = z % q

        if check: self.check()

    def Copy(self):
        return JacobiQuartic(self._sz, self._tz2, self._z, check=False)

    def check(self):
        sz,tz2,z = self._sz,self._tz2,self._z
        if ( pow(sz,4,q) + 2*a_quartic*pow(sz,2,q)*pow(z,2,q) 
                + pow(z,4,q) )%q != pow(tz2,2,q):
            raise InvalidPoint()

    def st(self):
        """Returns (s,t)-coordinates for this point when they exist. """
        """Otherwise throws an Infinite exception."""
        if self._z==0:
            raise Infinite()
        zinv = fe_inv(self._z)
        return ((zinv*self._sz)%q, (zinv**2*self._tz2)%q)

    @staticmethod
    def from_s(s,positive_t=True):
        a = (pow(s,4,q) + 2*a_quartic*pow(s,2,q)+1)%q
        t = fe_sqrt(a)
        if not positive_t:
            t = q - t
        return JacobiQuartic(s,t,check=False)

    @staticmethod
    def random():
        """returns a random non-infinite point on the jacobi quartic"""
        positive_t = (random.getrandbits(1)==0)
        while True:
            try:
                # has 50% chance to succeed
                return JacobiQuartic.from_s(fe_random(),positive_t)
            except NotASquare:
                continue

    def random_infinite():
        """returns a random infinite point on the jacobi quartic"""
        if random.getrandbits(1)==0:
            return JacobiQuartic(1,1,0,check=False)
        else:
            return JacobiQuartic(1,-1,0,check=False)

    def re_z(self):
        """Scales the projective point by a random scalar z """
        """(which doesn't essentially change the point)."""
        w = fe_random()
        return JacobiQuartic(self._sz*w, self._tz2*w*w, self._z*w, check=False)

    def point(self):
        sz,tz2,z = self._sz,self._tz2,self._z
        _2szzmagic = (2*sz*z*magic)%q
        z2 = pow(z,2,q)
        sz_2 = pow(sz,2,q)

        X = _2szzmagic * ( z2 + sz_2 )
        Y = tz2 * ( z2 - sz_2 )
        Z = tz2 * ( z2 + sz_2 )
        T = _2szzmagic * (z2 - sz_2 )

        return Point(X,Y,Z,T)

    def refpoint(self):
        sz,tz2,z = self._sz,self._tz2,self._z
        x = (2*sz*z*magic * fe_inv(tz2)) % q  # tz^2 will never be 0
        y = ((z*z - sz*sz) * fe_inv(z*z + sz*sz)) % q 
        #                       \_ z^2 and -(sz)^2 will never be equal  
        return ReferencePoint(x, y, check=False)

    def _refpoint_st(self):
        s,t = self.st()
        x = (2*s*magic * fe_inv(t)) % q  # t will never be 0
        y = ((1 - s*s) * fe_inv(1 + s*s)) % q 
        #                       \_ 1 and -s^2 will never be equal  
        return ReferencePoint(x, y, check=False)

    def is_exactly(self, other):
        if self._z == 0:
            if other._z != 0:
                return False
            return (self._sz**2 * other._tz2 
                    - other._sz**2 * self._tz2) % q == 0
        return ( (self._sz * other._z - other._sz * self._z)%q==0 ) \
                and ( (self._tz2 * other._z**2 - other._tz2 * self._z**2)%q==0 )

    def _is_exactly_st(self, other):
        if self._z == 0:
            if other._z != 0:
                return False
            return (self._sz**2 * other._tz2 
                    - other._sz**2 * self._tz2) % q == 0
        s1,t1 = self.st()
        s2,t2 = other.st()
        return (s1==s2) and (t1==t2)

    def dual(self):
        return JacobiQuartic(-self._sz, -self._tz2, self._z, check=False)

    def is_exactly_or_dual(self, other):
        return self.is_exactly(other) or self.is_exactly(other.dual())
    
    def equivalence_class(self):
        for a in self._equivalence_class_part():
            yield a
        for a in (self+JacobiQuartic(1, fe_sqrt(486664), check=False))\
                ._equivalence_class_part():
            yield a

    def _equivalence_class_part(self):
        sz,tz2,z = self._sz,self._tz2,self._z
        yield self.Copy()
        yield JacobiQuartic( -sz, -tz2, z, check=False)
        yield JacobiQuartic( z, -tz2, sz, check=False)
        yield JacobiQuartic( -z, tz2, sz, check=False)

    def __eq__(self, other):
        for a in self.equivalence_class():
            if a.is_exactly(other):
                return True
        return False

    def __repr__(self):
        return f"JacobiQuartic({self._sz}, {self._tz2}, {self._z})"

    def __add__(self, other):
        sz_1, tz2_1, z_1 = self._sz, self._tz2, self._z
        sz_2, tz2_2, z_2 = other._sz, other._tz2, other._z

        z = (pow(z_1,2,q)*pow(z_2,2,q) - pow(sz_1,2,q)*pow(sz_2,2,q) )%q
        s = ( sz_1*z_1*tz2_2 + sz_2*z_2*tz2_1 )%q
        t = ( (tz2_1*tz2_2 + 2*a_quartic*z_1*z_2*sz_1*sz_2)
            * ( pow(z_1,2,q)*pow(z_2,2,q) + pow(sz_1,2,q)*pow(sz_2,2,q) )
            + 2*z_1*z_2*sz_1*sz_2 
                * ( pow(sz_1,2,q)*pow(z_2,2,q) + pow(sz_2,2,q)*pow(z_1,2,q) )
            )%q

        return JacobiQuartic(s,t,z,check=False)

    def _add_st(self, other):
        s1,t1 = self.st()
        s2,t2 = other.st()

        den = fe_inv( 1 - pow(s1,2,q)*pow(s2,2,q) )
        
        s3 = ( (s1*t2 + t1*s2) * den ) % q
        t3 = ( ( (t1*t2+2*a_quartic*s1*s2)*(1+ s1*s1*s2*s2) \
                + 2*s1*s2*(s1*s1+s2*s2) ) * den*den ) % q

        return JacobiQuartic(s3,t3,check=False)

    def __neg__(self):
        return JacobiQuartic(-self._sz,self._tz2,self._z,check=False)

    def __sub__(self,other):
        return self+(-other)

    @staticmethod
    def Zero():
        return JacobiQuartic(0,1,check=False)

    @staticmethod
    def elligator2(x):
        """Provides an injection from the positive scalars below q """
        """to the points of the JacobiQuartic."""
        """Further, elligator(x)=elligator(-x)"""
        r = (i * x * x) % q
        if (d+r)%q==0:
            return JacobiQuartic(0,1,check=False)
        den = fe_inv(((d * r + 1) * (-d - r)) % q)
        n1 = -(r + 1) * (-1 + d) * (d + 1) * den
        n2 = r * n1
        try:
            s, t = fe_sqrt(n1), (-(r-1)*(-1 + d)**2 * den - 1) %q
            # s will be positive
        except NotASquare:
            s, t = -fe_sqrt(n2) % q, (r*(r-1)*(-1 + d)**2 * den - 1) %q
            # s is negative
        return JacobiQuartic(s,t,check=False)

    def _elligator2_inv_slow(self):
        """Returns positive x such that self=elligator2(x)=elligator2(-x)
        if it exists; otherwise throws NoPreimage."""
        try:
            s,t = self.st()
        except Infinite:
            raise NoPreimage()
        
        if s==0:
            # now either t=1 or t=-1
            if t==1: 
                return fe_sqrt(i*d)
            else:
                assert(q-t==1)
                return 0

        # b will be +- (r-1)/(r+1) depending on the sign of s
        b = ( ((t+1)*(d+1)) * fe_inv(s*s*(d-1)) ) % q
        if not fe_is_positive(s):
            b = q - b

        r = ( -(b+1) * fe_inv((b-1)%q) ) % q # b won't be 1
        
        try:
            return fe_sqrt(-i * r)
        except NotASquare:
            raise NoPreimage()

    def elligator2_inv(self, s_is_positive=None):
        """Returns positive x such that self=elligator2(x)=elligator2(-x)
        if it exists; otherwise throws NoPreimage."""
        sz,tz2,z = self._sz, self._tz2, self._z
        z2 = pow(z,2,q)
        
        if z==0:
            raise NoPreimage()
        if sz==0:
            if tz2==z2: # that is, t=1
                return fe_sqrt(i*d)
            else:
                assert( (tz2+z2)%q==0 ) # that is, t=-1
                return 0

        sz_2 = pow(sz,2,q)
        a = ( tz2+z2 ) * (d+1)*fe_inv(d-1)
        a2 = pow(a,2,q)
        sz_4 = pow(sz,4,q)
        try:
            y =  fe_inv(fe_sqrt( i* (sz_4 - a2)))
        except NotASquare:
            raise NoPreimage()
    
        if s_is_positive==None:
            s = ( fe_inv(z)*sz ) % q
            s_is_positive = fe_is_positive(s)

        if s_is_positive:
            x = ( y * (a+sz_2) ) % q
        else:
            x = ( y * (a-sz_2) ) % q

        if fe_is_positive(x):
            return x
        else:
            return q-x


class Error(Exception):
    pass

class NoPreimage(Error):
    pass

class DivisionByZero(Error):
    """raised by fe_inv and scalar_inv"""
    pass

class NotASquare(Error):
    pass

class Invalid(Error):
    pass

class Infinite(Error):
    pass

class InvalidPoint(Invalid):
    pass

class NotOnCurve(InvalidPoint):
    pass

class Odd(InvalidPoint):
    pass

class InvalidEncoding(Invalid):
    pass

class InvalidRepresentative(InvalidEncoding):
    pass

class SIsNegative(InvalidEncoding):
    pass


# the base ReferencePoint
ReferencePoint.Zero = ReferencePoint(0,1, check=False)
ReferencePoint.B = ReferencePoint.from_y_and_sign(
        4*fe_inv(5), True, check=False)
ReferencePoint.B.normalize()

# faster implementation 
class Point:
    @staticmethod
    def from_refpoint(a, Z=1):
        return Point(X=a.x*Z, Y=a.y*Z, Z=Z, T=a.x*a.y*Z)

    @staticmethod
    def random():
        return Point.from_refpoint(ReferencePoint.random(),Z=fe_random())

    @staticmethod
    def hash(data):
        return Point.from_refpoint(ReferencePoint.hash(data))

    def __init__(self, X, Y, Z, T):
        # TODO: what should we make of the case that Z=0?
        self.X = X % q
        self.Y = Y % q
        self.Z = Z % q
        self.T = T % q

    def Copy(self):
        return Point(X=self.X, Y=self.Y, Z=self.Z, T=self.T)

    def __repr__(self):
        return f"Point({self.X}, {self.Y}, {self.Z}, {self.T})"

    def __iadd__(self, other):
        if not isinstance(other, Point):
            return NotImplemented

        A = (self.X * other.X)%q
        B = (self.Y * other.Y)%q
        C = (d * (self.T * other.T)%q)%q
        D = (self.Z * other.Z)%q
        E = ( (self.X + self.Y)%q ) * ( (other.X + other.Y)%q ) 
        E = (E-A-B)%q
        F = (D-C)%q
        G = (D+C)%q
        H = (B+A)%q

        self.X=E*F
        self.Y=G*H
        self.Z=F*G
        self.T=E*H
        return self

    def __add__(self, other):
        result = self.Copy()
        result.__iadd__(other)
        return result

    def __neg__(self):
        return Point(X=-self.X,Y=self.Y,T=-self.T,Z=self.Z)


    def __sub__(self, other):
        return self + -other

    def double_in_place(self):
        A = (self.X * self.X)%q
        B = (self.Y * self.Y)%q
        C = (2 * self.Z * self.Z)%q
        D = -A
        E = (self.X + self.Y)%q
        E = (E*E)%q
        E = (E - A - B)%q
        G = (D+B)%q
        F = (G-C)%q
        H = (D-B)%q

        self.X=E*F
        self.Y=G*H
        self.T=E*H
        self.Z=F*G

        return self

    def double(self):
        result = self.Copy()
        result.double_in_place()
        return result

    def __mul__(self, other):
        return double_and_add_multiplication(self, other, Point.Zero())

    def equivalence_class(self):
        # doesn't include the odd points
        X,Y,Z,T = self.X,self.Y,self.Z,self.T
        yield self.Copy()
        yield Point(X,Y,-Z,T)
        yield Point(Y,X,i*Z,-T)
        yield Point(Y,X,-i*Z,-T)

    def is_exactly(self, other):
        return ( self.X*other.Z - other.X*self.Z )%q==0 and \
                ( self.Y*other.Z - other.Y*self.Z )%q==0  

    def __eq__(self, other):
        if not isinstance(other, Point):
            return NotImplemented
        return (self.X*other.Y - other.X*self.Y)%q==0 or \
                (self.X*other.X - self.Y*other.Y)%q==0

    def is_zero(self):
        return self.X==0 or self.Y==0

    def refpoint(self):
        zinv = fe_inv(self.Z)
        return ReferencePoint(self.X * zinv, self.Y * zinv,check=False)

    @staticmethod
    def unpack(data):
        return Point.from_refpoint(ReferencePoint.unpack(data))

    def pack(self):
        return self.refpoint().pack()

    @staticmethod
    def B_times(scalar):
        scalar %= l 
        result = Point.Zero()
        i = 0

        while(scalar>0):
            if scalar&1==1:
                result += Point.B_times_two_to_the_power[i]

            scalar >>= 1
            i += 1

        return result

    # since B is passed by-reference, and "+=" is implemented in place,
    # code like 
    #
    #   result = self.Point.B
    #   result += result
    #
    # will change the value of B, which is undesirable.
    @staticmethod
    def B():
        return Point._B.Copy()

    @staticmethod
    def Zero():
        return Point._Zero.Copy()

    def jacobi_quartic(self):
        X,Y,Z = self.X, self.Y, self.Z
        if X==0:  
            # Y/Z is now either +1 or -1
            if Y==Z:
                return JacobiQuartic(0,1,check=False)
            elif Y==q-Z:
                return JacobiQuartic(1,1,0,check=False)
            else:
                assert(False)

        z = ( fe_sqrt(pow(Z,2,q)-pow(Y,2,q))*X ) % q
        sz = ( (Z-Y)*X ) % q
        tz2 = ( 2*z*Z*(Z-Y)*magic ) % q

        return JacobiQuartic(sz, tz2, z, # check=False
                )


    def four_finite_jacobi_quartics(self):
        """computes the (up to dual) four jacobi quartics associated"""
        """ to this point"""
        X,Y,Z = self.X, self.Y, self.Z
        if X==0 or Y==0:
            yield JacobiQuartic(0,1,check=False)
            yield JacobiQuartic(1,2*magic*i, check=False)
            yield JacobiQuartic(-1,2*magic*i, check=False)
            return

        gamma = fe_inv(fe_sqrt( pow(Y,4,q) * pow(X,2,q) \
                    * (pow(Z,2,q)-pow(Y,2,q))))

        den = gamma*pow(Y,2,q)
        s_X_inv = ( den * (Z-Y) ) % q
        s = (s_X_inv * X) % q
        t = (2*magic*s_X_inv*Z) % q
        sp_Xp_inv = ( den * (Z+Y) ) % q
        sp = (- sp_Xp_inv * X) % q
        tp = (2*magic*sp_Xp_inv*Z) % q

        yield JacobiQuartic(s, t, check=False)
        yield JacobiQuartic(sp, tp, check=False)

        den = fe_inv(fe_sqrt(1+d)) * (pow(Y,2,q)-pow(Z,2,q)) * gamma
        X,Y,Z = Y,X,(i*Z)%q
        s_X_inv = ( den * (Z-Y) ) % q
        s = (s_X_inv * X) % q
        t = (2*magic*s_X_inv*Z) % q
        sp_Xp_inv = ( den * (Z+Y) ) % q
        sp = (- sp_Xp_inv * X) % q
        tp = (2*magic*sp_Xp_inv*Z) % q

        yield JacobiQuartic(s, t, check=False)
        yield JacobiQuartic(sp, tp, check=False)

    @staticmethod
    def elligator2(x):
        return JacobiQuartic.elligator2(x).point()

    def elligator2_inv(self):
        for jc in self.four_finite_jacobi_quartics():
            assert(jc._z==1)
            s_is_positive = fe_is_positive( jc._sz )
            try:
                yield jc.elligator2_inv(s_is_positive)
            except NoPreimage:
                pass
            try:
                yield jc.dual().elligator2_inv(not s_is_positive)
            except NoPreimage:
                pass


    def elligator2_inv_old(self):
        """returns all positive x for which elligator2(x)=elligator2(-x)=self"""
        for b in self.equivalence_class():
            jc = b.jacobi_quartic()
            if jc._z==0: # the result of elligator2 is always finite
                continue
            s_is_positive = fe_is_positive( fe_inv(jc._z)*jc._sz )
            try:
                yield jc.elligator2_inv(s_is_positive)
            except NoPreimage:
                pass
            try:
                yield jc.dual().elligator2_inv(not s_is_positive)
            except NoPreimage:
                pass

    @staticmethod
    def lizard(payload, N=16):
        """provides what is in all probability an injection from """
        """the bytes of length 16 to points on the edwards curve"""
        assert(len(payload)==N)
        assert( N<=30 and N%2==0 )
        return Point.elligator2(fe_unpack(
                lizard_without_elligator(payload, N=N)))

    def lizard_inv(self, N=16):
        assert( N<=30 and N%2==0 )
        for x in self.elligator2_inv():
            data = fe_pack(x)
            payload = data[ 16-N//2 : 16+N//2 ]
            data_hash = bytearray(common.sha256(payload))

            data_hash[0]  &= 0b11111110
            data_hash[31] &= 0b00111111
            
            if data[:16-N//2]==data_hash[:16-N//2] \
                    and data[16+N//2:]==data_hash[16+N//2:]:
                return payload
        raise NoPreimage()
    
def lizard_without_elligator(payload, N=16):
    assert( N<=30 and N%2==0 )
    assert(len(payload)==N)
    data = bytearray(common.sha256(payload))
    data[ 16-N//2 : 16+N//2 ] = payload
    data[0] &= 0b11111110
    data[31] &= 0b00111111
    return bytes(data)
     



Point._Zero = Point.from_refpoint(ReferencePoint.Zero)
Point._B = Point.from_refpoint(ReferencePoint.B)

def double_and_add_multiplication(self, other, zero):
    if not isinstance(other, int):
        return NotImplemented
    other %= 8*l
    result = zero
    power_of_two_times_self = self.Copy()

    while(other>0):
        if other&1==1:
            result += power_of_two_times_self

        power_of_two_times_self.double_in_place()
        other >>= 1

    return result

# TODO: hardcode these values
Point.B_times_two_to_the_power = []
_tmp = Point.B()
for _some_name_not_i in range(253): 
    Point.B_times_two_to_the_power.append(_tmp)
    _tmp = _tmp.double()
del _tmp
