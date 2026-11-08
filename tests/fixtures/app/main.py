import asyncio
from dataclasses import dataclass

from pkg import NAME, square, timed


class Counter:
    def __init__(self, start=0):
        self.value = start

    def bump(self, n):
        for _ in range(n):
            self.value += 1
        return self.value


@dataclass
class Point:
    x: int
    y: int


@timed
def compute(n):
    total = 0
    for i in range(n):
        if i % 3 == 0:
            continue
        total += square(i)
    return total


def gen(n):
    for i in range(n):
        yield i * i


def safe_div(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        return None
    finally:
        pass


def nested_loops(n):
    out = []
    for i in range(n):
        if i == 2:
            continue
        for j in range(n):
            if j == 3:
                break
            out.append(i * 10 + j)
    return out


def for_else(items, stop):
    for item in items:
        if item == stop:
            return "found"
    else:
        return "none"


def while_else(n):
    i = 0
    while i < n:
        i += 1
    else:
        result = i * 10
    return result


def use_global():
    global GLOBAL_VALUE
    GLOBAL_VALUE += 1
    return GLOBAL_VALUE


GLOBAL_VALUE = 10


def outer(step):
    total = 0

    def inner(x):
        nonlocal total
        total += x * step
        return total

    return inner


async def add(a, b):
    return a + b


def main():
    counter = Counter(2)
    point = Point(3, 4)
    inner = outer(2)
    print("counter", counter.bump(3))
    print("point", point.x + point.y)
    print("compute", compute(10))
    print("gen", list(gen(5)))
    print("div", safe_div(10, 2), safe_div(1, 0))
    print("nested", nested_loops(5))
    print("for_else", for_else([1, 2, 3], 2), for_else([1], 9))
    print("while_else", while_else(4))
    print("global", use_global(), use_global())
    print("closure", inner(3), inner(4))
    print("module", NAME, square(6))
    print("async", asyncio.run(add(5, 7)))


if __name__ == "__main__":
    main()
