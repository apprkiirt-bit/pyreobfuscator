import ast
import random
import sys
import unittest

from pyreobfuscator import passes

SOURCE = """
def sum_loop(a):
    total = 0
    for i in range(a):
        if i % 2:
            total += i
        else:
            total -= i
    return total


def for_else(items, stop):
    found = None
    for item in items:
        if item == stop:
            found = item
            break
    else:
        return "none"
    return found


def while_else(n):
    i = 0
    while i < n:
        i += 1
    else:
        return i * 10
    return -1


def nested(n):
    out = []
    for i in range(n):
        if i == 2:
            continue
        for j in range(n):
            if j == 3:
                break
            out.append(i * 10 + j)
    return out


def make_counter(step):
    total = 0
    def add(x):
        nonlocal total
        total += x * step
        if total > 100:
            return -total
        return total
    return add


def use_closure(n):
    counter = make_counter(3)
    values = []
    for i in range(n):
        values.append(counter(i))
    return values


def fmt(x):
    return f"value={x:03d}"


def comp(n):
    return [i * i for i in range(n) if i % 2 == 0]


GLOBAL = 7


def read_global():
    return GLOBAL + 1


def maybe_del(x):
    values = [1, 2, 3]
    if x:
        del values[1]
    return values


def safe_div(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        return None


def gen(n):
    for i in range(n):
        yield i
"""

if sys.version_info >= (3, 10):
    SOURCE += """

def classify(x):
    match x:
        case 0:
            return "zero"
        case _:
            return "other"
"""


def build(transform):
    tree = ast.parse(SOURCE)
    rng = random.Random(1234)
    pool = passes.ConstantPool()
    passes.strip_docstrings(tree)
    if transform:
        passes.encrypt_constants(tree, pool, "_table", rng)
        passes.flatten(tree, threshold=1, rng=rng, iter_name="_iter",
                       next_name="_next", stop_name="_stop")
        passes.rename_private(tree, rng=rng)
    ast.fix_missing_locations(tree)
    namespace = {
        "_table": tuple(pool.values),
        "_iter": iter,
        "_next": next,
        "_stop": StopIteration,
    }
    exec(compile(tree, "<passes>", "exec"), namespace)
    return namespace


class PassesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plain = build(False)
        cls.obf = build(True)

    def check(self, name, *args):
        self.assertEqual(self.plain[name](*args), self.obf[name](*args))

    def test_loops(self):
        for value in (0, 1, 7, 10):
            self.check("sum_loop", value)

    def test_for_else(self):
        self.check("for_else", [1, 2, 3], 2)
        self.check("for_else", [1, 2, 3], 9)

    def test_while_else(self):
        self.check("while_else", 5)

    def test_nested_break_continue(self):
        self.check("nested", 5)

    def test_closure(self):
        self.check("use_closure", 8)

    def test_fstring(self):
        self.check("fmt", 42)

    def test_comprehension(self):
        self.check("comp", 10)

    def test_global(self):
        self.check("read_global")

    def test_del(self):
        self.check("maybe_del", True)
        self.check("maybe_del", False)

    def test_untouched_constructs(self):
        self.assertEqual(self.obf["safe_div"](10, 2), 5)
        self.assertIsNone(self.obf["safe_div"](1, 0))
        self.assertEqual(list(self.obf["gen"](4)), [0, 1, 2, 3])
        if sys.version_info >= (3, 10):
            self.assertEqual(self.obf["classify"](0), "zero")
            self.assertEqual(self.obf["classify"](5), "other")


if __name__ == "__main__":
    unittest.main()
