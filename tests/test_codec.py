import types
import unittest

from pyreobfuscator import codec

SOURCE = """
def sample(a, b):
    total = 0
    for i in range(a):
        if i % 2:
            total += i
        else:
            total -= i
    try:
        total //= b
    except ZeroDivisionError:
        total = -1
    finally:
        pass
    return total


def make(step):
    total = 0
    def add(x):
        nonlocal total
        total += x * step
        return total
    return add


def gen(n):
    for i in range(n):
        yield i * i


def slicing(values):
    return values[-2:]
"""


class CodecTest(unittest.TestCase):
    def _namespace(self):
        namespace = {"__builtins__": __builtins__}
        code = codec.loads(codec.dumps(compile(SOURCE, "<codec>", "exec")))
        types.FunctionType(code, namespace)()
        return namespace

    def test_module_roundtrip(self):
        namespace = self._namespace()
        self.assertEqual(namespace["sample"](10, 2), 2)
        self.assertEqual(namespace["sample"](10, 0), -1)
        counter = namespace["make"](3)
        self.assertEqual(counter(2), 6)
        self.assertEqual(counter(3), 15)
        self.assertEqual(list(namespace["gen"](4)), [0, 1, 4, 9])
        self.assertEqual(namespace["slicing"]([1, 2, 3, 4]), [3, 4])

    def test_traceback_file_is_preserved(self):
        code = codec.loads(codec.dumps(compile("1 / 0", "weird.py", "exec")))
        with self.assertRaises(ZeroDivisionError):
            types.FunctionType(code, {})()
        self.assertEqual(code.co_filename, "weird.py")


if __name__ == "__main__":
    unittest.main()
