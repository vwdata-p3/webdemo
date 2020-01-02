import _ristretto as ristretto
import ed25519
import schnorr

class InvalidArgument(Exception):
    pass

class CryptoPU:
    def rsk(self, pseudonyms, k, s, rs):
        n = len(pseudonyms)
        assert(n==len(rs))

        if n==0:
            return;

        # fill cs and ck
        cs = ristretto.ffi.new("group_scalar*")
        ck = ristretto.ffi.new("group_scalar*")

        assert(ristretto.lib.group_scalar_unpack(cs, 
            ed25519.scalar_pack(s))==0)

        assert(ristretto.lib.group_scalar_unpack(ck, 
            ed25519.scalar_pack(k))==0)

        # fill crs
        crs = ristretto.ffi.new("group_scalar[]", n)
        cerror_codes = ristretto.ffi.new("int[]", n)

        ristretto.lib.group_scalars_unpack(crs, 
                b''.join([ ed25519.scalar_pack(rs[i]) for i in range(n)  ]), 
                cerror_codes, n)

        for i in range(n):
            assert(cerror_codes[i]==0)

        ccores = ristretto.ffi.new("group_ge[]", n)
        cblindings = ristretto.ffi.new("group_ge[]", n)
        ctarget = ristretto.ffi.new("group_ge*")

        packed_target = None

        cbuf = ristretto.ffi.new("unsigned char[]", 32*n)
        buf = ristretto.ffi.buffer(cbuf)

        for i in range(n):
            ristretto.ffi.memmove(cbuf+32*i, pseudonyms[i].data[0:32], 32)
        
        ristretto.lib.group_ges_unpack(cblindings, cbuf, cerror_codes, n)

        for i in range(n):
            if cerror_codes[i]!=0:
                raise InvalidArgument(f"couldn't unpack the {i}th triples' "
                        "blinding")

        for i in range(n):
            ristretto.ffi.memmove(cbuf+32*i, pseudonyms[i].data[32:64], 32)

        ristretto.lib.group_ges_unpack(ccores, cbuf, cerror_codes, n)

        for i in range(n):
            if cerror_codes[i]!=0:
                raise InvalidArgument(f"couldn't unpack the {i}th triples' "
                        "core")

        for i in range(n): 
            if i==0:
                packed_target = pseudonyms[i].data[64:96]
            elif pseudonyms[i].data[64:96] != packed_target:
                raise InvalidArgument("the triples' targets are not all "
                        f"the same; the {i}th triple's target differs "
                        "from the target of the first triple")

        if ristretto.lib.group_ge_unpack(ctarget, packed_target)!=0:
            raise InvalidArgument("couldn't unpack the target of the first "
                    "triple")

        if ristretto.lib.group_ge_isneutral(ctarget)!=0: 
            # ctarget==0
            raise InvalidArgument("target can't be zero")

        ristretto.lib.elgamal_triples_rsk(
                cblindings, ccores, cblindings, ccores,
                ctarget, ctarget,
                ck, cs, crs, n)

        cblindingbuf = ristretto.ffi.new("unsigned char[]", 32*n)
        blindingbuf = ristretto.ffi.buffer(cblindingbuf)
        ccorebuf = ristretto.ffi.new("unsigned char[]", 32*n)
        corebuf = ristretto.ffi.buffer(ccorebuf)
        ctargetbuf = ristretto.ffi.new("unsigned char[]", 32)
        targetbuf = ristretto.ffi.buffer(ctargetbuf)

        ristretto.lib.group_ge_pack(ctargetbuf, ctarget)

        ristretto.lib.group_ges_pack(cblindingbuf, cblindings, n)
        ristretto.lib.group_ges_pack(ccorebuf, ccores, n)

        for i in range(n):
            pseudonyms[i].data = b''.join(( 
                blindingbuf[32*i:32*(i+1)], 
                corebuf[32*i:32*(i+1)],
                targetbuf[:]))


    def encrypt(self, pseudonyms, target, rs):
        n = len(pseudonyms)
        assert(n==len(rs))

        ctarget = ristretto.ffi.new("group_ge*")
        crs = ristretto.ffi.new("group_scalar[]", n)
        cpoints = ristretto.ffi.new("group_ge[]", n)
        ctriples = ristretto.ffi.new("elgamal_triple[]", n)
        
        assert(0==ristretto.lib.group_ge_unpack(ctarget,target.pack()))

        for i in range(n):
            ristretto.lib.group_scalar_unpack(
                    ristretto.ffi.addressof(crs,i),
                    ed25519.scalar_pack(rs[i]))
        
        for i in range(n):
            ristretto.lib.group_ge_unpack(
                    ristretto.ffi.addressof(cpoints,i),
                    pseudonyms[i].data)

        ristretto.lib.elgamal_triples_encrypt(ctriples, cpoints, 
                ctarget, crs, n)

        cbuf = ristretto.ffi.new("unsigned char[]", 96*n)

        ristretto.lib.elgamal_triples_pack(cbuf, ctriples, n)

        buf = ristretto.ffi.buffer(cbuf)

        for i in range(n):
            pseudonyms[i].data = buf[ i*96 : (i+1)*96 ]

    
    def decrypt(self, pseudonyms, key):
        n = len(pseudonyms)

        ckey = ristretto.ffi.new("group_scalar*")
        cpoints = ristretto.ffi.new("group_ge[]", n)
        ctriples = ristretto.ffi.new("elgamal_triple[]", n)
        
        assert(0==ristretto.lib.group_scalar_unpack(ckey,
            ed25519.scalar_pack(key)))

        cerror_codes = ristretto.ffi.new("int[]", n)

        ristretto.lib.elgamal_triples_unpack(ctriples,
                b''.join([pseudonym.data for pseudonym in pseudonyms]),
                cerror_codes, n)

        for i in range(n):
            if cerror_codes[i]!=0:
                raise InvalidArgument(f"couldn't unpack {i}th triple")

        ristretto.lib.elgamal_triples_decrypt(cpoints, ctriples, ckey, n)

        cbuf = ristretto.ffi.new("unsigned char[]", 32*n)

        ristretto.lib.group_ges_pack(cbuf, cpoints, n)

        buf = ristretto.ffi.buffer(cbuf)

        for i in range(n):
            pseudonyms[i].data = buf[ i*32 : (i+1)*32 ]


    def elligator(self, names):
        n = len(names)

        cfes = ristretto.ffi.new("fe25519[]", n)
        cpoints = ristretto.ffi.new("group_ge[]", n)

        ristretto.lib.fe25519s_unpack(cfes, 
                b''.join([ name.data for name in names ]), n)

        ristretto.lib.group_ges_elligator(cpoints, cfes, n)

        cbuf = ristretto.ffi.new("unsigned char[]", 32*n)

        ristretto.lib.group_ges_pack(cbuf, cpoints, n)

        buf = ristretto.ffi.buffer(cbuf)

        for i in range(n):
            names[i].data = buf[ i*32: (i+1)*32 ]

    
    # given a scalar x gives a list of 253 packed points
    # of which the i-th is x**(2**i)
    def component_public_part(self, scalar):
        cy = ristretto.ffi.new("group_ge[]", 253)
        cx = ristretto.ffi.new("group_scalar*")
        
        assert(0==ristretto.lib.group_scalar_unpack(cx,
            ed25519.scalar_pack(scalar)))

        ristretto.lib.component_public_part(cy, cx)
        
        cbuf = ristretto.ffi.new("unsigned char[]", 32*253)
        ristretto.lib.group_ges_pack(cbuf, cy, 253)
        
        return [ bytes(cbuf[i*32:(i+1)*32]) for i in range(253) ]


    def certified_component_create(self, cc_protobuf, base_powers, 
            base_scalar, exponent):
        
        ccc = ristretto.ffi.new("certified_component*")
        
        N = len(list(schnorr.ones_of(exponent)))
        
        cdht_proofs = ristretto.ffi.new("unsigned char[]", 96*max(N-1,0))
        cpartial_products = ristretto.ffi.new("unsigned char[]", 32*max(N-2,0))
        ccc.product_proof.dht_proofs = cdht_proofs
        ccc.product_proof.partial_products = cpartial_products

        cbase_powers = ristretto.ffi.new("unsigned char[]", 32*253)
        cbase_powers_buffer = ristretto.ffi.buffer(cbase_powers)

        for i in range(253):
            cbase_powers[i*32:(i+1)*32] = base_powers[i]

        cbase_scalar = ristretto.ffi.new("group_scalar*")
        ristretto.lib.group_scalar_unpack(cbase_scalar,
                ed25519.scalar_pack(base_scalar))

        cexponent = ristretto.ffi.new("group_scalar*")
        ristretto.lib.group_scalar_unpack(cexponent,
                ed25519.scalar_pack(exponent))

        ristretto.lib.certified_component_create(ccc, 
                cbase_powers, cbase_scalar, cexponent)

        cc_protobuf.component = ristretto.ffi.buffer(ccc.component)[:]
        #N = ccc.product_proof.number_of_factors

        dht_proofs_buffer = ristretto.ffi.buffer(
                ccc.product_proof.dht_proofs, 96*max(N-1,0))
        partial_products_buffer = ristretto.ffi.buffer(
                ccc.product_proof.partial_products, 32*max(N-2,0))

        for i in range(max(N-1,0)):
            cc_protobuf.product_proof.dht_proofs.append(
                    dht_proofs_buffer[i*96:(i+1)*96])

        for i in range(max(N-2,0)):
            cc_protobuf.product_proof.partial_products.append(
                    partial_products_buffer[i*32:(i+1)*32])

    def certified_component_is_valid_for(self, cc_protobuf, base_powers,
            exponent):

        ccc = ristretto.ffi.new("certified_component*")
        
        ccc.component = cc_protobuf.component

        N = len(list(schnorr.ones_of(exponent)))
        
        cdht_proofs = ristretto.ffi.new("unsigned char[]", 96*max(N-1,0))
        cpartial_products = ristretto.ffi.new("unsigned char[]", 32*max(N-2,0))

        ccc.product_proof.dht_proofs = cdht_proofs
        ccc.product_proof.partial_products = cpartial_products
        ccc.product_proof.number_of_factors = N

        dht_proofs_buffer = ristretto.ffi.buffer(
                ccc.product_proof.dht_proofs, 96*max(N-1,0))
        partial_products_buffer = ristretto.ffi.buffer(
                ccc.product_proof.partial_products, 32*max(N-2,0))

        if len(cc_protobuf.product_proof.dht_proofs) != max(N-1,0):
            return False
        if len(cc_protobuf.product_proof.partial_products) != max(N-2,0):
            return False

        for i, data in enumerate(cc_protobuf.product_proof.dht_proofs):
            dht_proofs_buffer[96*i:96*(i+1)] = data

        for i, data in enumerate(cc_protobuf.product_proof.partial_products):
            partial_products_buffer[32*i:32*(i+1)] = data

        cbase_powers = ristretto.ffi.new("unsigned char[]", 32*253)
        cbase_powers_buffer = ristretto.ffi.buffer(cbase_powers)

        for i in range(253):
            cbase_powers[i*32:(i+1)*32] = base_powers[i]

        cexponent = ristretto.ffi.new("group_scalar*")
        ristretto.lib.group_scalar_unpack(cexponent,
                ed25519.scalar_pack(exponent))

        return ristretto.lib.certified_component_is_valid_for(
                ccc, cbase_powers, cexponent)!=0
