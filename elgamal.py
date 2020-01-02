import ed25519 

class Triple:
    def __init__(self, blinding, core, target):
        self.blinding = blinding
        self.core = core
        self.target = target

    def rerandomize(self, random_scalar=None):
        if random_scalar==None:
            random_scalar = ed25519.scalar_random()

        return Triple(
                self.blinding + ed25519.Point.B_times(random_scalar),
                self.core + self.target * random_scalar,
                self.target
            )

    def rekey(self, component):
        return Triple(
                self.blinding * ed25519.scalar_inv(component),
                self.core,
                self.target * component
            )

    def reshuffle(self, component):
        return Triple(
                self.blinding * component,
                self.core * component,
                self.target
            )

    def rsk(self, rekey_scalar, reshuffle_scalar, rerandomization_scalar=None):
        if rerandomization_scalar==None:
            rerandomization_scalar = ed25519.scalar_random()

        return Triple(
                blinding = self.blinding \
                        * (ed25519.scalar_inv(rekey_scalar) * reshuffle_scalar)
                + ed25519.Point.B_times(rerandomization_scalar),

                core = self.core * reshuffle_scalar 
                    + self.target * (rekey_scalar * rerandomization_scalar),

                target = self.target * rekey_scalar
            )

    def decrypt(self, private_key, check=True):
        if check and ed25519.Point.B_times(private_key) != self.target:
            raise WrongPrivateKey()

        return self.core - self.blinding * private_key

    def __eq__(self, other):
        if not isinstance(other, Triple):
            return NotImplemented

        return self.blinding==other.blinding \
                and self.core==other.core \
                and self.target==other.target

    def __repr__(self):
        return f"Triple({self.blinding},{self.core},{self.target})"

    @staticmethod
    def from_protobuf(message):
        return Triple(
                ed25519.Point.unpack(message.blinding),
                ed25519.Point.unpack(message.core),
                ed25519.Point.unpack(message.target)
            )

    def to_protobuf(self, message):
        message.blinding = bytes(self.blinding.pack())
        message.core = bytes(self.core.pack())
        message.target = bytes(self.target.pack())

    def pack(self):
        return self.blinding.pack() + \
                self.core.pack() + \
                self.target.pack()

    @staticmethod
    def unpack(data):
        if len(data)!=3*32:
            raise Error(f"to unpack a triple 96 bytes need to be given"
                    f" instead of {len(data)}")

        return Triple(
                blinding=ed25519.Point.unpack(data[0:32]),
                core=ed25519.Point.unpack(data[32:64]),
                target=ed25519.Point.unpack(data[64:96])
            )

class Error(Exception):
    pass

class WrongPrivateKey(Error):
    pass

def encrypt(point, public_key, random_scalar=None):
    return Triple(ed25519.Point.Zero(), point, public_key)\
            .rerandomize(random_scalar)


