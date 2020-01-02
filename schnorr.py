import common
import elgamal
import ed25519

class DHTProof:
    def __init__(self, R_M, R_B, s, R_M_packed=None, R_B_packed=None):
        if R_M_packed==None:
            R_M_packed = R_M.pack()
        if R_B_packed==None:
            R_B_packed = R_B.pack()

        self._R_M = R_M
        self._R_B = R_B
        self._s = s

        self._R_M_packed = R_M_packed
        self._R_B_packed = R_B_packed

    def is_valid_proof_for(self, A, M, N,
            A_packed=None, M_packed=None, N_packed=None):
        R_M,R_B,s = self._R_M, self._R_B, self._s
        R_M_packed = self._R_M_packed
        R_B_packed = self._R_B_packed

        if A_packed==None:
            A_packed = A.pack()
        if M_packed==None:
            M_packed = M.pack()
        if N_packed==None:
            N_packed = N.pack()

        h = ed25519.scalar_unpack(common.sha256(
            A_packed + M_packed + N_packed + R_M_packed + R_B_packed))

        if ed25519.Point.B_times(s) != R_B + A * h:
            return False
        if M*s != R_M + N * h:
            return False

        return True

    @staticmethod
    def create(a, M, A=None, N=None, m=None,
            a_packed=None, M_packed=None, A_packed=None, N_packed=None):
        if A==None:
            A = ed25519.Point.B_times(a)
        if N==None:
            N = M * a

        if A_packed==None:
            A_packed = A.pack()
        if N_packed==None:
            N_packed = N.pack()
        if M_packed==None:
            M_packed = M.pack()
        if a_packed==None:
            a_packed = ed25519.scalar_pack(a)
        
        r = ed25519.scalar_unpack(common.sha256(
            b"DHTProof" + a_packed + M_packed))
        R_B = ed25519.Point.B_times(r)

        if m==None:
            R_M = M * r 
        else:
            R_M = ed25519.Point.B_times(m*r)

        R_M_packed = R_M.pack()
        R_B_packed = R_B.pack()

        h = ed25519.scalar_unpack(common.sha256(
            A_packed + M_packed + N_packed + R_M_packed + R_B_packed))

        s = (r + h * a) % ed25519.l

        return DHTProof(R_M, R_B, s, 
                R_M_packed=R_M_packed, R_B_packed=R_B_packed)

    def pack(self):
        return self._R_M_packed + self._R_B_packed \
                + ed25519.scalar_pack(self._s)

    @staticmethod
    def unpack(data):
        assert(len(data)==3*32)
        
        R_M_packed = data[0:32]
        R_B_packed = data[32:64]
        s_packed = data[64:96]

        return DHTProof(
                ed25519.Point.unpack(R_M_packed),
                ed25519.Point.unpack(R_B_packed),
                ed25519.scalar_unpack(data[64:96]),
                R_M_packed=R_M_packed,
                R_B_packed=R_B_packed)

    def __eq__(self, other):
        return ( self._R_M == other._R_M and
                self._R_B == other._R_B and
                self._s == other._s )


class RSKProof:
    def __init__(self, 
            R_B, R_y, T_B, beta_, gamma_,
            pR_y, ptau, pN_B, pbeta, pgamma):
        
        self._R_B = R_B
        self._R_y = R_y
        self._T_B = T_B
        self._beta_ = beta_
        self._gamma_ = gamma_

        self._pR_y = pR_y
        self._ptau = ptau
        self._pN_B = pN_B
        self._pbeta = pbeta
        self._pgamma = pgamma

    @staticmethod
    def create(triple, k, n, r):
        c = triple.core
        b = triple.blinding
        y = triple.target

        nkinv = ( n * ed25519.scalar_inv(k) ) % ed25519.l
        nkinvB = ed25519.Point.B_times(nkinv)
        
        R_B = ed25519.Point.B_times(r)
        R_y = y * r

        K_B = ed25519.Point.B_times(k)

        beta_ = b+R_B
        gamma_ = c+R_y

        beta = beta_*nkinv
        gamma = gamma_*n
        tau = y*k

        return ( RSKProof(R_B, R_y, nkinvB, beta_, gamma_,
                DHTProof.create(r, y, A=R_B, N=R_y),
                DHTProof.create(k, y, A=K_B, N=tau),
                DHTProof.create(k, nkinvB, A=K_B),
                DHTProof.create(nkinv, beta_, A=nkinvB, N=beta),
                DHTProof.create(n, gamma_, N=gamma) ),
                elgamal.Triple( beta, gamma, tau ) )

    def is_valid_proof_for(self, triple_in, K_B, N_B, triple_out):
        c = triple_in.core
        b = triple_in.blinding
        y = triple_in.target

        gamma = triple_out.core
        beta = triple_out.blinding
        tau = triple_out.target

        R_B, R_y, T_B  = self._R_B, self._R_y, self._T_B
        beta_, gamma_ = self._beta_, self._gamma_

        return (self._pR_y.is_valid_proof_for( R_B, y, R_y ) and
                self._ptau.is_valid_proof_for( K_B, y, tau ) and
                self._pN_B.is_valid_proof_for( K_B, T_B, N_B ) and
                self._pbeta.is_valid_proof_for( T_B, beta_, beta ) and
                self._pgamma.is_valid_proof_for( N_B, gamma_, gamma ) and
                beta_ == b + R_B and gamma_ == c + R_y )

    def pack(self):
        return ( self._R_B.pack() +
                self._R_y.pack() + 
                self._T_B.pack() + 
                self._beta_.pack() + 
                self._gamma_.pack() + 
                self._pR_y.pack() + 
                self._ptau.pack() + 
                self._pN_B.pack() +
                self._pbeta.pack() + 
                self._pgamma.pack() )

    @staticmethod
    def unpack(data):
        assert(len(data)==5*32+5*3*32)
        return RSKProof(
                ed25519.Point.unpack(data[0:32]),
                ed25519.Point.unpack(data[32:64]),
                ed25519.Point.unpack(data[64:96]),
                ed25519.Point.unpack(data[96:128]),
                ed25519.Point.unpack(data[128:160]),
                DHTProof.unpack(data[160:256]),
                DHTProof.unpack(data[256:352]),
                DHTProof.unpack(data[352:448]),
                DHTProof.unpack(data[448:544]),
                DHTProof.unpack(data[544:640]))

    def __eq__(self, other):
        return ( self._R_B == other._R_B and 
                self._R_y  == other._R_y and 
                self._T_B  == other._T_B and 
                self._beta_  == other._beta_ and 
                self._gamma_  == other._gamma_ and 
                self._pR_y  == other._pR_y and 
                self._ptau  == other._ptau and 
                self._pN_B == other._pN_B and 
                self._pbeta  == other._pbeta and 
                self._pgamma == other._pgamma )

class RSProof:
    def __init__(self,  R_B, R_y, beta_, gamma_, pR_y, pbeta, pgamma):
        self._R_B = R_B
        self._R_y = R_y
        self._beta_ = beta_
        self._gamma_ = gamma_

        self._pR_y = pR_y
        self._pbeta = pbeta
        self._pgamma = pgamma

    @staticmethod
    def create(triple, n, r):
        c = triple.core
        b = triple.blinding
        y = triple.target

        N_B = ed25519.Point.B_times(n)
        
        R_B = ed25519.Point.B_times(r)
        R_y = y * r

        beta_ = b+R_B
        gamma_ = c+R_y

        beta = beta_*n
        gamma = gamma_*n

        return ( RSProof(R_B, R_y, beta_, gamma_,
                DHTProof.create(r, y, A=R_B, N=R_y),
                DHTProof.create(n, beta_, A=N_B, N=beta),
                DHTProof.create(n, gamma_, A=N_B, N=gamma) ),
                elgamal.Triple( beta, gamma, y ) )

    def is_valid_proof_for(self, triple_in, N_B, triple_out):
        c = triple_in.core
        b = triple_in.blinding
        y = triple_in.target

        gamma = triple_out.core
        beta = triple_out.blinding
        tau = triple_out.target

        R_B, R_y  = self._R_B, self._R_y
        beta_, gamma_ = self._beta_, self._gamma_

        return (self._pR_y.is_valid_proof_for( R_B, y, R_y ) and
                self._pbeta.is_valid_proof_for( N_B, beta_, beta ) and
                self._pgamma.is_valid_proof_for( N_B, gamma_, gamma ) and
                beta_ == b + R_B and gamma_ == c + R_y and tau == y )

    def pack(self):
        return ( self._R_B.pack() +
                self._R_y.pack() + 
                self._beta_.pack() + 
                self._gamma_.pack() + 
                self._pR_y.pack() + 
                self._pbeta.pack() + 
                self._pgamma.pack() )

    @staticmethod
    def unpack(data):
        assert(len(data)==416)
        return RSProof(
                ed25519.Point.unpack(data[0:32]),
                ed25519.Point.unpack(data[32:64]),
                ed25519.Point.unpack(data[64:96]),
                ed25519.Point.unpack(data[96:128]),
                DHTProof.unpack(data[128:224]),
                DHTProof.unpack(data[224:320]),
                DHTProof.unpack(data[320:416]))

    def __eq__(self, other):
        return ( self._R_B == other._R_B and 
                self._R_y  == other._R_y and 
                self._beta_  == other._beta_ and 
                self._gamma_  == other._gamma_ and 
                self._pR_y  == other._pR_y and 
                self._pbeta  == other._pbeta and 
                self._pgamma == other._pgamma )

class ProductProof:
    def __init__(self, dht_proofs, partial_products, partial_products_packed): 
        self._dht_proofs = dht_proofs
        self._partial_products = partial_products
        self._partial_products_packed = partial_products_packed

    def is_valid_proof_for(self, product, factors, factors_packed=None, 
            product_packed=None):
        N = len(factors)

        if factors_packed==None:
            factors_packed = [ factor.pack() for factor in factors ]
        if product_packed==None:
            product_packed = product.pack()

        if len(self._partial_products) != max(N-2,0)\
                or len(self._dht_proofs) != max(N-1,0):
            return False

        if len(factors)==0:
            return product==ed25519.Point.B_times(1)

        if len(factors)==1:
            return product==factors[0]

        partial_products = [ factors[0] ] \
                + list(self._partial_products) \
                + [ product ]
        partial_products_packed = [ factors_packed[0] ] \
                + list(self._partial_products_packed) \
                + [ product_packed ]

        for i, dht_proof in enumerate(self._dht_proofs):
            if not dht_proof.is_valid_proof_for(
                    A=factors[i+1], 
                    M=partial_products[i],
                    N=partial_products[i+1],
                    A_packed=factors_packed[i+1],
                    M_packed=partial_products_packed[i],
                    N_packed=partial_products_packed[i+1]):
                return False

        return True
    
    @staticmethod
    def create(factors_scalars):
        N = len(factors_scalars)

        if N==0:
            return ProductProof((),(),()), (), ed25519.Point.B_times(1)

        product_so_far = factors_scalars[0]
        partial_products = [ ed25519.Point.B_times(product_so_far) ]
        partial_products_packed = [ partial_products[0].pack() ]

        factors = [ partial_products[0] ]
        factors_packed = [ partial_products_packed[0] ]
        if N==1:
            return ProductProof((),(),()), factors, partial_products[0]

        dht_proofs = []
        for i in range(N-1):
            factor_scalar = factors_scalars[i+1]
            factor = ed25519.Point.B_times(factor_scalar)

            previous_product = product_so_far
            product_so_far *= factor_scalar

            factors.append(factor)
            factor_packed = factor.pack()
            factors_packed.append(factor_packed)

            partial_products.append( ed25519.Point.B_times(product_so_far) )
            partial_products_packed.append( partial_products[i+1].pack() )

            dht_proofs.append(DHTProof.create(factor_scalar, 
                    M=partial_products[i], 
                    A=factor, 
                    N=partial_products[i+1],
                    M_packed=partial_products_packed[i],
                    A_packed = factor_packed,
                    N_packed=partial_products_packed[i+1],
                    m=previous_product))

        product = partial_products[-1]

        return ( 
            ProductProof(dht_proofs, 
                partial_products[1:-1], partial_products_packed[1:-1]), 
            factors, product )

    def __eq__(self, other):
        return self._partial_products==other._partial_products \
                and self._dht_proofs==other._dht_proofs

    def to_protobuf(self, msg):
        # msg should have fields like pep3.ProductProof
        assert(len(msg.partial_products)==0)
        for partial_product_packed in self._partial_products_packed:
            msg.partial_products.append(partial_product_packed)
        assert(len(msg.dht_proofs)==0)
        for dht_proof in self._dht_proofs:
            msg.dht_proofs.append(dht_proof.pack())
    
    @staticmethod
    def from_protobuf(msg):
        return ProductProof(
                [ DHTProof.unpack(pdhp) for pdhp in msg.dht_proofs ],
                [ ed25519.Point.unpack(ppp) for ppp in msg.partial_products ],
                [ ppp for ppp in msg.partial_products ])


def ones_of(e):
    # returns the indices of the ones in the binary notation of e,
    # that is, returns i_1 < i_2 < ... < i_n with
    #
    #   2**i_1 + ... + 2**i_n.
    i = 0
    while e>0:
        if e%2==1:
            yield i
        e >>= 1
        i += 1

class CertifiedComponent:
    # Proof that  k**e B  is indeed that assuming knowledge of 
    #
    #   k**(2**0) B,  k**(2**1) B, ..., k**(2**252)
    #
    # consisting, writing e = 2**(i_1) + ... + 2**(i_n),
    # where i_1 < i_2 < ... < i_n, 
    # of proofs for the Diffie--Hellman triples
    # 
    #   ( k**(2**i_2)B, k**(2**i_1)B, k**(2**i_1+2**i_2) B )  
    #   ( k**(2**i_3)B, k**(2**i_1+2**i_2) B, k**(2**i_1+2**i_2+2**i_3) B )
    #       ...
    #   ( k**(2**i_1+...+2**i_(n-1) )B, k**(2**i_n) B, k**e B ) 
    #
    # together with the partial products
    #
    #   k**( 2**i_1 + 2**i_2 ) B,
    #   k**( 2**i_1 + 2**i_2 + 2**i_3 ) B,
    #       ...
    #   k**( 2**i_1 + ... + 2**i_(n-1) ) B.
    #
    def __init__(self, component, product_proof):
        self._component = component
        self._product_proof = product_proof

    def is_valid_proof_for(self, exponent, # e 
            base_times_two_to_the_power_of): #[ k**(2**i) B : i in [0,...,252] ]

        exponent %= ed25519.l

        factors = [ base_times_two_to_the_power_of[i] 
                for i in ones_of(exponent) ]

        return self._product_proof.is_valid_proof_for(self._component, factors)

    @staticmethod
    def create(base_scalar, exponent):
        factors_scalars = [ pow(base_scalar, 2**i, ed25519.l)
                for i in ones_of(exponent) ]

        product_proof, _, component  = ProductProof.create(factors_scalars)
        
        return CertifiedComponent(component, product_proof)

    def to_protobuf(self, msg): 
        # msg should be like a pep3.CertifiedComponent protobuf message
        msg.component = self._component.pack()
        self._product_proof.to_protobuf(msg.product_proof)

    @staticmethod
    def from_protobuf(msg):
        component = ed25519.Point.unpack(msg.component)
        product_proof = ProductProof.from_protobuf(msg.product_proof)

        return CertifiedComponent(component, product_proof)

    def __eq__(self, other):
        return ( self._component == other._component ) \
                and ( self._product_proof == other._product_proof )
