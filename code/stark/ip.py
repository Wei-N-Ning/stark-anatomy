import pickle as pickle  # serialization
from hashlib import shake_256
from typing import Any


class ProofStream:

    def __init__(self):
        self.objects = []
        self.read_index = 0

    def push(self, obj: Any):
        self.objects += [obj]

    def pull(self) -> Any:
        assert (self.read_index < len(
            self.objects)), "ProofStream: cannot pull object; queue empty."
        obj = self.objects[self.read_index]
        self.read_index += 1
        return obj

    def serialize(self) -> bytes:
        return pickle.dumps(self.objects)

    def prover_fiat_shamir(self, num_bytes=32) -> bytes:
        return shake_256(self.serialize()).digest(num_bytes)

    def verifier_fiat_shamir(self, num_bytes=32) -> bytes:
        return shake_256(pickle.dumps(
            self.objects[:self.read_index])).digest(num_bytes)

    @staticmethod
    def deserialize(bb) -> 'ProofStream':
        ps = ProofStream()
        ps.objects = pickle.loads(bb)
        return ps
