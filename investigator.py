import pep3_pb2
import pep3_pb2_grpc

import common
import researcher

class Investigator(pep3_pb2_grpc.InvestigatorServicer):
    def __init__(self, pep):
        self.pep = pep

    Depseudonymize = researcher.Researcher.Depseudonymize
    Query = researcher.Researcher.Query



