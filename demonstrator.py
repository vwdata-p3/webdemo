import pep3_pb2_grpc

# only here for formal reasons;
# we're only interested in the demonstrator
# as a way for the webdemo to authenticate to the peers
class Demonstrator(pep3_pb2_grpc.DemonstratorServicer):
    def __init__(self, pep):
        self.pep = pep
