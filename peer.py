import queue
import threading

import pep3_pb2_grpc
import pep3_pb2

import grpc
from OpenSSL import crypto

import common
import ed25519
import elgamal
import schnorr
import cryptopu

MODE_OK = 0
MODE_FAULTY = 1
MODE_OFF = 2

class Peer(pep3_pb2_grpc.PeerServicer):
    def __init__(self, pep):
        self.pep = pep
        self._mode = 0

        # for monitoring
        self.messages_lock = threading.Lock()
        self.messages_queues = []

    def _dispatch_message(self, msg):
        msg.modePlusOne = self._mode+1
        with self.messages_lock:
            for q in self.messages_queues:
                q.put(msg)

    @common.switch
    def Relocalize(self, request, context):
        return self._mode

    @Relocalize.case(MODE_OK)
    def Relocalize(self, request, context):
        common_name = common.authenticate(context)

        self._dispatch_message(pep3_pb2.Message(text="Relocalizing", 
            code=pep3_pb2.Message.OK))

        # catch trivial errors
        if len(request.warrant.signature)==0:
            context.abort(grpc.StatusCode.PERMISSION_DENIED,
                    "warrant has empty signature")

        if len(request.which_shards)==0:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    "request.which_shards is empty")

        if len(request.names)==0:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    "request.names is empty")

        # verify warrant
        if common_name != request.warrant.act.actor:
            context.abort(grpc.StatusCode.PERMISSION_DENIED,
                    f"you, {common_name}, presented a warrant that "
                    f"was issued to {request.warrant.act.actor}")

        try:
            crypto.verify(crypto.load_certificate(crypto.FILETYPE_PEM,
                        self.pep.global_config.root_certificates.warrants),
                    request.warrant.signature,
                    request.warrant.act.SerializeToString(),'sha256')
        except crypto.Error as e:
            context.abort(grpc.StatusCode.PERMISSION_DENIED,
                    "the warrant's signature appears to be invalid")

        response = pep3_pb2.RelocalizationResponse()

        act = request.warrant.act

        k = s = 1
        for shard in request.which_shards:
            s *= pow(ed25519.scalar_unpack(self.pep.secrets.by_shard[shard]\
                        .pseudonym_component_secret), 
                ed25519.scalar_unpack(common.sha256(act.target)), ed25519.l)
            s %= ed25519.l

        if act.encrypt_for != b"":
            for shard in request.which_shards:
                k *= pow(ed25519.scalar_unpack(self.pep.secrets.by_shard[shard]\
                            .by_domain["pseudonym"].key_component_secret),
                    ed25519.scalar_unpack(common.sha256(act.encrypt_for)), 
                    ed25519.l)
                k %= ed25519.l

        k_inv_comp = 1
        encrypt_from = act.source
        if encrypt_from==b"plaintext":
            encrypt_from = act.actor
        for shard in request.which_shards:
            k_inv_comp *= \
                pow(ed25519.scalar_unpack(self.pep.secrets.by_shard[shard]\
                        .by_domain["pseudonym"].key_component_secret),
                ed25519.scalar_unpack(common.sha256(encrypt_from)), 
                ed25519.l)
            k_inv_comp %= ed25519.l
        k = ( k * ed25519.scalar_inv(k_inv_comp) ) % ed25519.l

        if act.source != b"plaintext":
            for shard in request.which_shards:
                s *= ed25519.scalar_inv(pow(ed25519.scalar_unpack(
                    self.pep.secrets.by_shard[shard]\
                            .pseudonym_component_secret), 
                    ed25519.scalar_unpack(common.sha256(act.source)),
                    ed25519.l))
                s %= ed25519.l

        names = request.names

        # reshuffle, rekey, and rerandomize
        try:
            self.pep._cryptopu.rsk(names, k, s, 
                    [ ed25519.scalar_random() for i in range(len(names)) ])
        except cryptopu.InvalidArgument as e:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
        
        # change the state of the names if we rekeyed
        if act.encrypt_for != b"":
            for i in range(len(names)):
                names[i].state \
                        = pep3_pb2.Pseudonymizable.ENCRYPTED_PSEUDONYM

        response.names.extend(names)

        return response

    @Relocalize.case(MODE_OFF)
    def Relocalize(self, request, context):
        context.abort(grpc.StatusCode.UNAVAILABLE, "Peer is OFF.")

    @Relocalize.case(MODE_FAULTY)
    def Relocalize(self, request, context):
        return pep3_pb2.RelocalizationResponse()


    def Enroll(self, request, context):
        common_name = common.authenticate(context)

        # TODO: have a smarter check
        return_components = ( common_name == b"PEP3 investigator" 
                or common_name == b"PEP3 researcher" )

        response = pep3_pb2.EnrollmentResponse()

        # 1. [ REMOVED ]

        # 2. set response.by_shard[...].private_local_keys
        #        and response.components[...].keys

        e = ed25519.scalar_unpack(common.sha256(common_name))
        # "e" is the exponent used to compute the key/pseudonym components

        for shard, shard_secrets in self.pep.secrets.by_shard.items():
            for domain, domain_secrets in shard_secrets.by_domain.items():
                x = ed25519.scalar_unpack(domain_secrets.private_master_key)
                k = ed25519.scalar_unpack(domain_secrets.key_component_secret)

                k_local = pow(k,e,ed25519.l)
                
                if return_components:
                    self.pep._cryptopu.certified_component_create(
                            response.components[shard].keys[domain],
                            self.pep.global_config.\
                                    components[shard].keys[domain].\
                                    base_times_two_to_the_power_of,
                            k, e)
                            
                x_local = (k_local * x) % ed25519.l
                
                response.by_shard[shard].private_local_keys[domain]\
                        = ed25519.scalar_pack(x_local)

        # 3. set response.components[...].pseudonym

        if return_components:
            for shard in self.pep.config.shards:
                s = ed25519.scalar_unpack(
                        self.pep.secrets.by_shard[shard]\
                                .pseudonym_component_secret)

                self.pep._cryptopu.certified_component_create(
                        response.components[shard].pseudonym,
                        self.pep.global_config.\
                                components[shard].pseudonym.\
                                base_times_two_to_the_power_of,
                        s, e)

        return response


    @common.switch
    def Depseudonymize(self, request, context):
        return self._mode

    @Depseudonymize.case(MODE_OFF)
    def Depseudonymize(self, request, context):
        context.abort(grpc.StatusCode.UNAVAILABLE, "Peer is OFF.")

    @Depseudonymize.case(MODE_FAULTY)
    def Depseudonymize(self, request, context):
        return pep3_pb2.DepseudonymizationResponse()

    @Depseudonymize.case(MODE_OK)
    def Depseudonymize(self, request, context):
        common_name = common.authenticate(context)
        e = ed25519.scalar_unpack(common.sha256(common_name))

        self._dispatch_message(pep3_pb2.Message(text="Depseudonymizing", 
            code=pep3_pb2.Message.OK))

        # catch trivial errors
        if len(request.warrant.signature)==0:
            context.abort(grpc.StatusCode.PERMISSION_DENIED,
                    "warrant has empty signature")

        if len(request.which_shards)==0:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                    "request.which_shards is empty")

        # verify warrant
        if common_name != request.warrant.act.actor:
            context.abort(grpc.StatusCode.PERMISSION_DENIED,
                    f"you, {common_name}, presented a warrant that "
                    f"was issued to {request.warrant.act.actor}")

        try:
            crypto.verify(crypto.load_certificate(crypto.FILETYPE_PEM,
                        self.pep.global_config.root_certificates.warrants),
                    request.warrant.signature,
                    request.warrant.act.SerializeToString(),'sha256')
        except crypto.Error as e:
            context.abort(grpc.StatusCode.PERMISSION_DENIED,
                    "the warrant's signature appears to be invalid")

        # verify reminders
        for i, reminder in enumerate(request.reminders):
            if not common.verify_protobuf_signature(reminder, 
                    self.pep.secrets.reminders_hmac_secret):
                context.abort(grpc.StatusCode.PERMISSION_DENIED,
                        f"could not verify reminder #{i}.")

        # verify chain
        name = request.warrant.act.name
        name_unpacked = elgamal.Triple.unpack(name.data)

        for i, link in enumerate(request.chain):
            if link.peer not in self.pep.global_config.peers:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                        f"unknown peer '{link.peer}' in link #{i}")

            for shard in link.which_shards:
                if shard not in self.pep.global_config\
                        .peers[link.peer].shards:
                    context.abort(grpc.StatusCode.PERMISSION_DENIED,
                            f"the peer {link.peer} of link #{i} "
                            f"doesn't hold the shard {shard}!")

            rs_p = schnorr.RSProof.unpack(link.peer_response.rs_proof)
            sB_p = schnorr.DHTProof.unpack(link.peer_response.sB_proof)
            sB = ed25519.Point.unpack(link.peer_response.sB)
            kB = ed25519.Point.B_times(1)
            s_inv_B = ed25519.Point.unpack(link.peer_response.s_inv_B)

            link_name_unpacked = elgamal.Triple.unpack(
                    link.peer_response.name.data)

            # check that s_inv_B is the inverse of sB
            if not sB_p.is_valid_proof_for(sB, s_inv_B, 
                    ed25519.Point.B_times(1)):
                context.abort(grpc.StatusCode.PERMISSION_DENIED,
                        f"could not verify the sB proof of link #{i}.")
            
            # check the rs-operation was performed correctly
            if not rs_p.is_valid_proof_for(name_unpacked, sB, 
                    link_name_unpacked):
                context.abort(grpc.StatusCode.PERMISSION_DENIED,
                        f"could not verify the rs proof of link #{i}.")

            # check that s_inv_B is indeed the product of their factors
            s_inv_B_factors = [ ed25519.Point.unpack(pp) for
                    pp in link.peer_response.s_inv_B_factors ]

            s_inv_B_p = schnorr.ProductProof.from_protobuf(
                    link.peer_response.s_inv_B_proof)

            if not s_inv_B_p.is_valid_proof_for(s_inv_B, s_inv_B_factors):
                context.abort(grpc.StatusCode.PERMISSION_DENIED,
                        "could not verify the s_inv_B product proof "
                        f"for link #{i}.")

            # make a lookup dictionary for the reminders
            reminders = {}
            for reminder in request.reminders:
                component = reminder.component
                if component in reminders:
                    context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                            "double reminder")
                reminders[component] = reminder

            # check that the provided factors are valid
            for j, shard in enumerate(link.which_shards):
                # check s_inv_B factor
                s_inv_B_factor_packed = link.peer_response.s_inv_B_factors[j]

                if shard in self.pep.config.shards:
                    # we can check s_inv_B by computing it ourselves
                    s_ = ed25519.scalar_unpack(self.pep.secrets\
                            .by_shard[shard].pseudonym_component_secret)
                    s_B = ed25519.Point.B_times(pow(s_, e, ed25519.l))
                    if s_B.pack() != s_inv_B_factor_packed:
                        context.abort(grpc.StatusCode.PERMISSION_DENIED,
                            f"s_inv_B factor #{j} (for shard {shard}, "
                            f"and common name {common_name}, e={e})"
                            f" of link #{i} is not correct: it should be "
                            f"{s_B.pack()}, but {s_inv_B_factor_packed} "
                            "was given.")
                else: # we need a reminder that s_inv_B is correct
                    if s_inv_B_factor_packed not in reminders:
                        context.abort(grpc.StatusCode.PERMISSION_DENIED,
                                f"missing reminder that s_inv_B factor #{j} "
                                f"of link #{i} is correct.")
                    rem = reminders[s_inv_B_factor_packed]
                    
                    assert(rem.component == s_inv_B_factor_packed)
                    error_message = None
                    if not rem.HasField("pseudonym"):
                        error_message = "reminder is for a key component"\
                                f" instead of a pseudonym component"
                    elif rem.shard != shard:
                        error_message = "reminder is for "\
                                f"the shard {rem.shard}"\
                                f" instead of the shard {shard}"
                    if error_message != None:
                        context.abort(grpc.StatusCode.PERMISSION_DENIED,
                                f"s_inv_B factor #{j} of link #{i} " 
                                "is not correct: " + error_message)

            name = link.peer_response.name
            name_unpacked = link_name_unpacked

        # the provided request seems to be in order;
        # let us prepare our response.

        response = pep3_pb2.DepseudonymizationResponse()


        # compute rekey and reshuffle components
        k = s_inv = 1
        s_inv_factors = []

        for shard in request.which_shards:
            s_inv_factor = pow(ed25519.scalar_unpack(self.pep.secrets\
                        .by_shard[shard].pseudonym_component_secret), 
                e, ed25519.l)
            s_inv_factors.append(s_inv_factor)

            s_inv *= s_inv_factor
            s_inv %= ed25519.l

        s = ed25519.scalar_inv(s_inv)
        r = ed25519.scalar_random()

        rs_proof, name_out = schnorr.RSProof.create(name_unpacked, s, r)
        response.rs_proof = rs_proof.pack()

        response.name.data = name_out.pack()
        response.name.state \
                = pep3_pb2.Pseudonymizable.ENCRYPTED_PSEUDONYM

        # compute proofs for the reshuffle components
        s_inv_B_proof, s_inv_B_factors, s_inv_B \
                = schnorr.ProductProof.create(s_inv_factors)
        s_inv_B_proof.to_protobuf(response.s_inv_B_proof)
        for s_inv_B_factor in s_inv_B_factors:
            response.s_inv_B_factors.append(s_inv_B_factor.pack())
        response.s_inv_B = s_inv_B.pack()

        sB = ed25519.Point.B_times(s)
        sB_proof = schnorr.DHTProof.create(s, s_inv_B, A=sB, 
                N=ed25519.Point.B_times(1))
        
        response.sB = sB.pack()
        response.sB_proof = sB_proof.pack()

        return response


    def RegisterComponents(self, request, context):
        common_name = common.authenticate(context)
        e = ed25519.scalar_unpack(common.sha256(common_name))

        response = pep3_pb2.ComponentsRegistrationResponse()

        for shard, by_shard in request.components.items():
            if not self.pep._cryptopu.certified_component_is_valid_for(
                    by_shard.pseudonym,
                    self.pep.global_config.components[shard].pseudonym.\
                            base_times_two_to_the_power_of, 
                    e):
                context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                        f'pseudonym component for shard {shard} '
                        'could not be verified')

            reminder = response.reminders.add()
            reminder.component = by_shard.pseudonym.component
            reminder.shard = shard
            reminder.pseudonym.SetInParent() # this sets reminder.pseudonym
            common.sign_protobuf(reminder, 
                    self.pep.secrets.reminders_hmac_secret)
            
            for domain, cc_msg in by_shard.keys.items():
                if not self.pep._cryptopu.certified_component_is_valid_for(
                        cc_msg,
                        self.pep.global_config.components[shard].\
                                keys[domain].base_times_two_to_the_power_of,
                        e):
                    context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                            f'{domain} key component for shard {shard} '
                            'could not be verified')

                reminder = response.reminders.add()
                reminder.component = cc_msg.component
                reminder.shard = shard
                reminder.key.domain = domain
                common.sign_protobuf(reminder, 
                        self.pep.secrets.reminders_hmac_secret)
                
        return response

    
    def Demo_Monitor(self, void, context):
        common.authenticate(context, must_be_one_of=(b"PEP3 demonstrator",))

        q = queue.SimpleQueue()

        with self.messages_lock:
            self.messages_queues.append(q)

        try:
            while True:
                yield q.get()
        finally:
            with self.messages_lock:
                self.messages_queues.remove(q)

    
    def Demo_SetMode(self, mode, context):
        common.authenticate(context, must_be_one_of=(b"PEP3 demonstrator",))

        self._mode = mode.mode
        self._dispatch_message(pep3_pb2.Message(text="Set mode", 
            code=pep3_pb2.Message.OK))
        
        return pep3_pb2.Void()

    def Demo_Ping(self, void, context):
        common.authenticate(context, must_be_one_of=(b"PEP3 demonstrator",))
        self._dispatch_message(pep3_pb2.Message(text="Pong", 
            code=pep3_pb2.Message.OK))

        return pep3_pb2.Void()

