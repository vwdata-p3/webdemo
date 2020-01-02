import pep3_pb2
import pep3_pb2_grpc

import common
import ed25519
import elgamal

class Researcher(pep3_pb2_grpc.ResearcherServicer):
    def __init__(self, pep):
        self.pep = pep

    def Query(self, query, context):
        common.authenticate(context,
                must_be_one_of=[b"PEP3 " 
                    + self.pep.my_type_name.encode('utf-8')])
        # \_ so we can call Query from Investigator

        secret_local_key = self.pep.private_keys['pseudonym']

        sf_name = b"PEP3 storage_facility"
        my_name = b"PEP3 researcher"

        # gather pseudonymizable parameters to the query
        names = []
        for parameter in query.parameters.values():
            if parameter.WhichOneof("kind")=='pseudonymizable_value':
                names.append(parameter.pseudonymizable_value)

        # encrypt, and localize from researcher to sf
        self.pep.encrypt(names)
        self.pep.relocalize(names, self.pep.config.warrants.from_me_to_sf)

        for chunk in self.pep.connect_to("storage_facility").Query(query):

            # localize from sf to researcher, and decrypt
            names.clear()
            for row in chunk.rows:
                for value in row.cells:
                    if value.WhichOneof("kind")=='pseudonymizable_value':
                        names.append(value.pseudonymizable_value)

            self.pep.relocalize(names, self.pep.config.warrants.from_sf_to_me)
            self.pep.decrypt(names, secret_local_key)

            yield chunk

    # More of an investigator power:
    def Depseudonymize(self, request, context):
        common.authenticate(context,
                must_be_one_of=[b"PEP3 "
                    + self.pep.my_type_name.encode('utf-8')])

        result = pep3_pb2.Pseudonymizable()
        
        self.pep.depseudonymize(request, result)

        return result
