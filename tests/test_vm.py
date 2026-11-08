import ast
import random
import types
import unittest

from pyreobfuscator import runtime, vm

SOURCE = """
class Box:
    def __init__(self, value):
        self.value = value

    def bump(self, amount):
        self.value = self.value + amount
        return self.value


def arith(a, b):
    return (a + b) * 2 - a // b


def cond(x):
    if x > 0:
        return "pos"
    elif x == 0:
        return "zero"
    return "neg"


def loops(n):
    total = 0
    for i in range(n):
        if i == 2:
            continue
        total = total + i
    return total


def nested(n):
    out = []
    for i in range(n):
        for j in range(n):
            if j == 1:
                break
            out.append(i * 10 + j)
    return out


def while_break(n):
    i = 0
    while True:
        if i >= n:
            break
        i = i + 1
    else:
        return -1
    return i


def lists(a):
    values = [a, a + 1]
    values[0] = values[1]
    return values


def dicts(k, v):
    data = {k: v}
    data["x"] = v + 1
    return data


def attrs(obj):
    obj.value = obj.value + 2
    return obj.value


def calls(f, x):
    return f(x, b=3)


def kw(a, b=2, c=3):
    return a + b + c


def slicing(values):
    return values[1:3]


def membership(x, values):
    return (x in values), (x not in values)


def booleans(a, b):
    return (a and b), (a or b), (not a)


def ternary(x):
    return "yes" if x else "no"


def named(x):
    if (n := x + 1) > 2:
        return n
    return 0


def multi(a):
    x = y = a + 1
    return x + y


def unsupported_closure(step):
    total = 0
    def add(x):
        nonlocal total
        total = total + x
        return total
    return add


def guarded(value):
    try:
        if value < 0:
            raise ValueError("bad")
        return f"ok {value}"
    except ValueError as error:
        return f"bad {error}"
"""


def build(use_vm):
    tree = ast.parse(SOURCE)
    ops = {}
    programs = []
    if use_vm:
        vm.transform(tree, random.Random(7), "_vm", ops, programs, mode="all")
    ast.fix_missing_locations(tree)
    namespace = {}
    if use_vm:
        inverse = {index: name for name, index in ops.items()}
        namespace["_vm"] = runtime._pb_vm_make(programs, inverse)
    exec(compile(tree, "<vm>", "exec"), namespace)
    return namespace, programs


class VmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plain, _ = build(False)
        cls.obf, cls.programs = build(True)

    def check(self, name, *args):
        self.assertEqual(self.plain[name](*args), self.obf[name](*args))

    def test_programs_were_emitted(self):
        self.assertGreater(len(self.programs), 10)

    def test_arith_and_cond(self):
        self.check("arith", 7, 3)
        for value in (-2, 0, 5):
            self.check("cond", value)

    def test_loops(self):
        for value in (0, 1, 5):
            self.check("loops", value)
            self.check("nested", value)
            self.check("while_break", value)

    def test_containers(self):
        self.check("lists", 4)
        self.check("dicts", "k", 5)
        self.check("slicing", [0, 1, 2, 3, 4])

    def test_attributes_and_classes(self):
        plain = self.plain["Box"](3)
        obf = self.obf["Box"](3)
        self.assertEqual(plain.bump(4), obf.bump(4))
        self.assertEqual(self.plain["attrs"](plain), self.obf["attrs"](obf))

    def test_calls_and_kwargs(self):
        self.check("kw", 1)
        self.check("calls", self.plain["kw"], 4)
        self.assertEqual(self.obf["calls"](self.obf["kw"], 4), 4 + 3 + 3)
    def test_expressions(self):
        self.check("membership", 2, [1, 2, 3])
        self.check("membership", 9, [1, 2, 3])
        self.check("booleans", True, False)
        self.check("booleans", 0, 5)
        self.check("ternary", True)
        self.check("ternary", False)
        self.check("named", 5)
        self.check("named", -5)
        self.check("multi", 3)

    def test_try_and_fstring(self):
        self.check("guarded", 3)
        self.check("guarded", -1)

    def test_closure_is_left_alone(self):
        counter = self.obf["unsupported_closure"](2)
        self.assertEqual(counter(3), 3)


if __name__ == "__main__":
    unittest.main()
