import unittest
from os import urandom

from stark.merkle import Merkle


class TestMerkle(unittest.TestCase):
    def setUp(self) -> None:
        self.n = 64
        self.leafs = [urandom(int(urandom(1)[0])) for i in range(self.n)]
        self.root = Merkle.commit_(self.leafs)

    def test_opening_leaf_should_work(self):
        """opening any leaf should work
        """
        for i in range(self.n):
            path = Merkle.open_(i, self.leafs)
            self.assertTrue(Merkle.verify_(self.root, i, path, self.leafs[i]))

    def test_opening_nonleaf_should_not_work(self):
        """opening non-leafs should not work
        """
        for i in range(self.n):
            path = Merkle.open_(i, self.leafs)
            self.assertFalse(Merkle.verify_(self.root, i, path, urandom(51)))

    def test_opening_wrong_leaves_should_not_work(self):
        for i in range(self.n):
            path = Merkle.open_(i, self.leafs)
            j = (i + 1 + (int(urandom(1)[0] % (self.n - 1)))) % self.n
            self.assertFalse(Merkle.verify_(self.root, i, path, self.leafs[j]))

    def test_opening_leaves_with_wrong_index_should_not_work(self):
        for i in range(self.n):
            path = Merkle.open_(i, self.leafs)
            j = (i + 1 + (int(urandom(1)[0] % (self.n - 1)))) % self.n
            self.assertFalse(Merkle.verify_(self.root, j, path, self.leafs[i]))

    def test_opening_leaves_to_false_root_should_not_work(self):
        # opening leafs to a false root should not work
        for i in range(self.n):
            path = Merkle.open_(i, self.leafs)
            self.assertFalse(Merkle.verify_(urandom(32), i, path, self.leafs[i]))

    def test_opening_leaves_with_falsehood_in_the_path(self):
        # opening leafs with even one falsehood in the path should not work
        for i in range(self.n):
            path = Merkle.open_(i, self.leafs)
            for j in range(len(path)):
                fake_path = path[0:j] + [urandom(32)] + path[j + 1:]
                self.assertFalse(Merkle.verify_(self.root, i, fake_path, self.leafs[i]))

    def test_opening_leaves_to_different_root_should_not_work(self):
        # opening leafs to a different root should not work
        fake_root = Merkle.commit_([urandom(32) for i in range(self.n)])
        for i in range(self.n):
            path = Merkle.open_(i, self.leafs)
            self.assertFalse(Merkle.verify_(fake_root, i, path, self.leafs[i]))
