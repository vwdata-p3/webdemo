import unittest
import argparse
import os
import sys
import concurrent

from OpenSSL import crypto

import pep3_pb2

import pep3
import elgamal
import ed25519
import common

class pep3test(unittest.TestCase):
    def setUp(self):
        config = pep3_pb2.Configuration()
        secrets = pep3_pb2.Secrets()

        pep3.fill_local_config_messages(config, secrets)

        executor_type = concurrent.futures.ThreadPoolExecutor

        self.g = pep3.RunServers(config, secrets, executor_type=executor_type)
        self.g.__enter__()

        self.researcher = self.g.contexts[('researcher',None)]
        self.collector = self.g.contexts[('collector',None)]
        self.sf = self.g.contexts[('storage_facility',None)]
        self.investigator = self.g.contexts[('investigator',None)]

        self.secrets = secrets
        self.config = config

    def tearDown(self):
        self.g.__exit__(None, None, None)

    def test_localization_of_pseudonym(self):
        name = b" a 16 byte name "
        target = b"PEP3 storage_facility"

        pp = pep3_pb2.Pseudonymizable(data=name,
                state=pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME)

        self.collector.pseudonymize([ pp ])
        self.collector.relocalize([ pp ], 
                self.config.collector.warrants.to_sf)

        sfp = elgamal.Triple.unpack(pp.data)\
                .decrypt(self.sf.private_keys['pseudonym'])
        
        pseudonym_secrets = {}
        for peer_secrets in self.secrets.peers.values():
            for shard, shard_secrets in peer_secrets.by_shard.items():
                pseudonym_secrets[shard] \
                        = shard_secrets.pseudonym_component_secret

        s = 1
        e = ed25519.scalar_unpack(common.sha256(target))
        for secret in pseudonym_secrets.values():
            s *= pow(ed25519.scalar_unpack(secret),e,ed25519.l)
            s %= ed25519.l

        self.assertEqual(
            sfp * ed25519.scalar_inv(s),
            ed25519.Point.lizard(name) )


    def test_store_and_retrieve(self):
        # first store a record with random source and target ip addresses,
        # and see if we can recover it.
        col_request = pep3_pb2.StoreRequest()
        col_request.id = os.urandom(16)

        flowrecord = col_request.records.add()
        flowrecord.source_ip.data = os.urandom(16)
        flowrecord.source_ip.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME
        flowrecord.destination_ip.data = os.urandom(16)
        flowrecord.destination_ip.state = \
                pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME

        flowrecord.anonymous_part.number_of_bytes = 123
        flowrecord.anonymous_part.number_of_packets = 456

        updates = list(self.collector.connect_to('collector').Store(
                iter([ col_request ])))
        self.assertEqual(len(updates),1)
        self.assertEqual(updates[0].stored_id, col_request.id)

        # store the same flowrecord twice, to see if that causes troubles
        col_request.id = os.urandom(16)
        updates = list(self.collector.connect_to('collector').Store(
                iter([ col_request ])))
        self.assertEqual(len(updates),1)
        self.assertEqual(updates[0].stored_id, col_request.id)

        query = pep3_pb2.SqlQuery()

        # manually compute storage_facility-local pseudonyms for query
        sf_name = b"PEP3 storage_facility"

        pseudonym_secrets = {}
        for peer_secrets in self.secrets.peers.values():
            for shard, shard_secrets in peer_secrets.by_shard.items():
                pseudonym_secrets[shard] \
                        = shard_secrets.pseudonym_component_secret

        s = 1
        e = ed25519.scalar_unpack(common.sha256(sf_name))
        for secret in pseudonym_secrets.values():
            s *= pow(ed25519.scalar_unpack(secret),e,ed25519.l)
            s %= ed25519.l

        # see if the record was stored correctly by querying the
        # database directly.
        query.query = """SELECT peped_flows.p_dst_ip FROM peped_flows
            WHERE peped_flows.p_src_ip=:ip"""
        ip = query.parameters['ip'].pseudonymizable_value
        ip.data = ( ed25519.Point.lizard(
                flowrecord.source_ip.data)*s ).pack()
        ip.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_PSEUDONYM
        
        row = self.sf.connect_to('database')\
                .Query(query).next().rows[0]


        self.assertEqual(row.cells[0].pseudonymizable_value.data,
                ( ed25519.Point.lizard(flowrecord.destination_ip.data)*s
                    ).pack())

        # manually compute researcher-local pseudonyms for query
        researcher_name = b"PEP3 researcher"

        pseudonym_secrets = {}
        for peer_secrets in self.secrets.peers.values():
            for shard, shard_secrets in peer_secrets.by_shard.items():
                pseudonym_secrets[shard] \
                        = shard_secrets.pseudonym_component_secret

        s = 1
        e = ed25519.scalar_unpack(common.sha256(researcher_name))
        for secret in pseudonym_secrets.values():
            s *= pow(ed25519.scalar_unpack(secret),e,ed25519.l)
            s %= ed25519.l

        # now query via the researcher
        query.parameters['ip'].pseudonymizable_value.data \
                = ( ed25519.Point.lizard(flowrecord.source_ip.data)*s ).pack()
        
        row = self.researcher.connect_to('researcher')\
                .Query(query).next().rows[0]

        self.assertEqual(row.cells[0].pseudonymizable_value.data,
                ( ed25519.Point.lizard(flowrecord.destination_ip.data)*s
                    ).pack())

    
    def test_depseudonymize(self):
        ip = os.urandom(16)

        # manually compute investigator-local pseudonym
        pseudonym_secrets = {}
        for peer_secrets in self.secrets.peers.values():
            for shard, shard_secrets in peer_secrets.by_shard.items():
                pseudonym_secrets[shard] \
                        = shard_secrets.pseudonym_component_secret

        s = 1
        e = ed25519.scalar_unpack(common.sha256(b"PEP3 investigator"))
        for secret in pseudonym_secrets.values():
            s *= pow(ed25519.scalar_unpack(secret),e,ed25519.l)
            s %= ed25519.l

        investigator_local_ip = ( ed25519.Point.lizard(ip)*s ).pack()

        # manually create warrant
        warrant = pep3_pb2.DepseudonymizationRequest.Warrant()
        warrant.act.actor = b"PEP3 investigator"
        warrant.act.name.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_PSEUDONYM
        warrant.act.name.data = investigator_local_ip

        self.investigator.encrypt([ warrant.act.name ], 
                self.investigator.public_keys['pseudonym'])

        warrant.signature = crypto.sign(
                crypto.load_privatekey(crypto.FILETYPE_PEM,
                    self.secrets.root_certificate_keys.warrants),
                warrant.act.SerializeToString(), 'sha256')

        result = self.investigator.connect_to("investigator")\
                .Depseudonymize(warrant)

        self.assertEqual(result.data, ip)


pep3.raise_nofile_limit()

if __name__=="__main__":
    unittest.main()

