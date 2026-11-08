NAME = "util"


def square(x):
    return x * x


def timed(fn):
    def wrap(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrap
