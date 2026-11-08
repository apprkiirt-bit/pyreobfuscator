"""Register VM compiler.

The compiler lowers Python AST nodes to a compact register program. The
runtime interpreter lives in runtime.py; this module is build-time only.
"""

import ast

_BINOPS = {
    ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul", ast.Div: "truediv",
    ast.FloorDiv: "floordiv", ast.Mod: "mod", ast.Pow: "pow", ast.LShift: "lshift",
    ast.RShift: "rshift", ast.BitOr: "or_", ast.BitXor: "xor", ast.BitAnd: "and_",
    ast.MatMult: "matmul",
}
_UNARY = {ast.Not: "not_", ast.USub: "neg", ast.UAdd: "pos", ast.Invert: "invert"}
_COMPARE = {
    ast.Eq: "eq", ast.NotEq: "ne", ast.Lt: "lt", ast.LtE: "le",
    ast.Gt: "gt", ast.GtE: "ge", ast.Is: "is_", ast.IsNot: "is_not",
    ast.In: "contains", ast.NotIn: "not_contains",
}


class _Unsupported(Exception):
    pass


class _Label:
    __slots__ = ("pos",)

    def __init__(self):
        self.pos = None


class _Program:
    def __init__(self, ops):
        self.ops = ops
        self.code = []
        self.consts = []
        self.nregs = 0
        self.params = []

    def __getitem__(self, key):
        return getattr(self, key)

    def _op(self, name):
        index = self.ops.get(name)
        if index is None:
            index = len(self.ops) + 1
            self.ops[name] = index
        return index

    def emit(self, name, *args):
        self.code.append([self._op(name), *args])
        return len(self.code) - 1

    def const(self, value):
        self.consts.append(value)
        return len(self.consts) - 1

    def label(self):
        return _Label()

    def mark(self, label):
        label.pos = len(self.code)

    def finish(self):
        for instruction in self.code:
            for index in range(1, len(instruction)):
                value = instruction[index]
                if isinstance(value, _Label):
                    if value.pos is None:
                        raise _Unsupported("unresolved label")
                    instruction[index] = value.pos
        return {
            "code": self.code,
            "consts": self.consts,
            "nregs": self.nregs,
            "params": self.params,
        }


def _local_names(fn):
    names = set()
    globals_ = set()

    def walk(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        if isinstance(node, ast.Global):
            globals_.update(node.names)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                walk_target(target)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            walk_target(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            walk_target(node.target)
        elif isinstance(node, ast.NamedExpr):
            walk_target(node.target)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        for child in ast.iter_child_nodes(node):
            walk(child)

    def walk_target(target):
        if isinstance(target, ast.Name):
            names.add(target.id)

    args = fn.args
    for arg in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
        names.add(arg.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    for statement in fn.body:
        walk(statement)
    names -= globals_
    return names, globals_


class _Compiler:
    def __init__(self, ops, programs, fn):
        self.ops = ops
        self.programs = programs
        self.fn = fn
        self.locals = {}
        self.nregs = 0
        self.program = None
        self.loops = []
        self.params = []
        local_names, self.globals = _local_names(fn)
        args = fn.args
        for arg in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
            self.params.append(arg.arg)
        if args.vararg:
            self.params.append(args.vararg.arg)
        if args.kwarg:
            self.params.append(args.kwarg.arg)
        for name in self.params:
            self.reg(name)
        for name in sorted(local_names):
            self.reg(name)

    def reg(self, name):
        if name not in self.locals:
            self.locals[name] = self.nregs
            self.nregs += 1
        return self.locals[name]

    def alloc(self):
        result = self.nregs
        self.nregs += 1
        return result

    def const(self, value):
        result = self.alloc()
        self.program.emit("CONST", result, self.program.const(value))
        return result

    def emit(self, name, *args):
        return self.program.emit(name, *args)

    def label(self):
        return self.program.label()

    def mark(self, label):
        self.program.mark(label)

    def _sub(self, body, bind=None):
        saved = self.program
        saved_loops = self.loops
        program = _Program(self.ops)
        self.program = program
        self.loops = []
        if bind is not None:
            self.reg(bind)
        for statement in body:
            self.stmt(statement)
        program.nregs = self.nregs
        self.loops = saved_loops
        self.program = saved
        pid = len(self.programs)
        self.programs.append(program)
        return pid

    def load(self, name):
        result = self.alloc()
        if name in self.globals or name not in self.locals:
            self.emit("LOAD_GLOBAL", result, name)
        else:
            self.emit("LOAD_REG", result, self.reg(name))
        return result

    def store(self, target, source):
        if isinstance(target, ast.Name):
            if target.id in self.globals:
                self.emit("STORE_GLOBAL", target.id, source)
            else:
                self.emit("STORE_REG", self.reg(target.id), source)
        elif isinstance(target, ast.Attribute):
            obj = self.expr(target.value)
            self.emit("STORE_ATTR", obj, target.attr, source)
        elif isinstance(target, ast.Subscript):
            obj = self.expr(target.value)
            key = self.slice(target.slice)
            self.emit("STORE_SUBSCR", obj, key, source)
        else:
            raise _Unsupported(type(target).__name__)

    def slice(self, node):
        if isinstance(node, ast.Slice):
            lower = self.const(None) if node.lower is None else self.expr(node.lower)
            upper = self.const(None) if node.upper is None else self.expr(node.upper)
            step = self.const(None) if node.step is None else self.expr(node.step)
            result = self.alloc()
            self.emit("BUILD_SLICE", result, lower, upper, step)
            return result
        return self.expr(node)

    def expr(self, node, dst=None):
        if dst is None:
            dst = self.alloc()
        if isinstance(node, ast.Constant):
            self.emit("CONST", dst, self.program.const(node.value))
        elif isinstance(node, ast.Name):
            if node.id in self.globals or node.id not in self.locals:
                self.emit("LOAD_GLOBAL", dst, node.id)
            else:
                self.emit("LOAD_REG", dst, self.reg(node.id))
        elif isinstance(node, ast.BinOp):
            left = self.expr(node.left)
            right = self.expr(node.right)
            op = _BINOPS.get(type(node.op))
            if op is None:
                raise _Unsupported(type(node.op).__name__)
            self.emit("BINOP", dst, left, right, op)
        elif isinstance(node, ast.UnaryOp):
            value = self.expr(node.operand)
            op = _UNARY.get(type(node.op))
            if op is None:
                raise _Unsupported(type(node.op).__name__)
            self.emit("UNARY", dst, value, op)
        elif isinstance(node, ast.BoolOp):
            end = self.label()
            for index, value in enumerate(node.values):
                self.expr(value, dst)
                if index < len(node.values) - 1:
                    self.emit("JUMP_IF_FALSE" if isinstance(node.op, ast.And) else "JUMP_IF_TRUE",
                              dst, end)
            self.mark(end)
        elif isinstance(node, ast.Compare):
            left = self.expr(node.left)
            end = self.label()
            for index, (op_node, comparator) in enumerate(zip(node.ops, node.comparators)):
                right = self.expr(comparator)
                op = _COMPARE.get(type(op_node))
                if op is None:
                    raise _Unsupported(type(op_node).__name__)
                self.emit("COMPARE", dst, left, right, op)
                if index < len(node.ops) - 1:
                    self.emit("JUMP_IF_FALSE", dst, end)
                    left = right
            self.mark(end)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {
                    "eval", "exec", "compile", "locals", "vars", "globals", "__import__"}:
                raise _Unsupported("dynamic call")
            func = self.expr(node.func)
            args = []
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    raise _Unsupported("starred call")
                args.append(self.expr(arg))
            kwargs = []
            for keyword in node.keywords:
                if keyword.arg is None:
                    raise _Unsupported("star kwargs")
                kwargs.append([keyword.arg, self.expr(keyword.value)])
            self.emit("CALL", dst, func, args, kwargs)
        elif isinstance(node, ast.Attribute):
            obj = self.expr(node.value)
            self.emit("LOAD_ATTR", dst, obj, node.attr)
        elif isinstance(node, ast.Subscript):
            obj = self.expr(node.value)
            key = self.slice(node.slice)
            self.emit("LOAD_SUBSCR", dst, obj, key)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            items = []
            for item in node.elts:
                if isinstance(item, ast.Starred):
                    raise _Unsupported("starred literal")
                items.append(self.expr(item))
            kind = "BUILD_LIST" if isinstance(node, ast.List) else (
                "BUILD_TUPLE" if isinstance(node, ast.Tuple) else "BUILD_SET")
            self.emit(kind, dst, items)
        elif isinstance(node, ast.Dict):
            items = []
            for key, value in zip(node.keys, node.values):
                if key is None:
                    raise _Unsupported("dict unpack")
                items.append([self.expr(key), self.expr(value)])
            self.emit("BUILD_MAP", dst, items)
        elif isinstance(node, ast.IfExp):
            otherwise = self.label()
            end = self.label()
            test = self.expr(node.test)
            self.emit("JUMP_IF_FALSE", test, otherwise)
            self.expr(node.body, dst)
            self.emit("JUMP", end)
            self.mark(otherwise)
            self.expr(node.orelse, dst)
            self.mark(end)
        elif isinstance(node, ast.NamedExpr):
            value = self.expr(node.value)
            self.store(node.target, value)
            self.emit("STORE_REG", dst, value)
        elif isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(self.const(value.value))
                elif isinstance(value, ast.FormattedValue):
                    item = self.expr(value.value)
                    spec = self.const(None) if value.format_spec is None else self.expr(value.format_spec)
                    formatted = self.alloc()
                    self.emit("FORMAT", formatted, item, spec, value.conversion)
                    parts.append(formatted)
                else:
                    raise _Unsupported(type(value).__name__)
            self.emit("BUILD_STRING", dst, parts)
        elif isinstance(node, ast.FormattedValue):
            item = self.expr(node.value)
            spec = self.const(None) if node.format_spec is None else self.expr(node.format_spec)
            self.emit("FORMAT", dst, item, spec, node.conversion)
        else:
            raise _Unsupported(type(node).__name__)
        return dst

    def stmt(self, node):
        if isinstance(node, ast.Expr):
            self.expr(node.value)
        elif isinstance(node, ast.Assign):
            source = self.expr(node.value)
            for target in node.targets:
                self.store(target, source)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.store(node.target, self.expr(node.value))
        elif isinstance(node, ast.AugAssign):
            target = node.target
            if isinstance(target, ast.Name):
                current = self.load(target.id)
            elif isinstance(target, ast.Attribute):
                current = self.expr(target.value)
                self.emit("LOAD_ATTR", current, current, target.attr)
            elif isinstance(target, ast.Subscript):
                current = self.expr(target.value)
                key = self.slice(target.slice)
                value = self.alloc()
                self.emit("LOAD_SUBSCR", value, current, key)
                current = value
            else:
                raise _Unsupported(type(target).__name__)
            right = self.expr(node.value)
            result = self.alloc()
            op = _BINOPS.get(type(node.op))
            if op is None:
                raise _Unsupported(type(node.op).__name__)
            self.emit("BINOP", result, current, right, op)
            self.store(target, result)
        elif isinstance(node, ast.If):
            otherwise = self.label()
            end = self.label()
            test = self.expr(node.test)
            self.emit("JUMP_IF_FALSE", test, otherwise)
            for child in node.body:
                self.stmt(child)
            self.emit("JUMP", end)
            self.mark(otherwise)
            for child in node.orelse:
                self.stmt(child)
            self.mark(end)
        elif isinstance(node, ast.While):
            start = self.label()
            exhausted = self.label()
            end = self.label()
            self.mark(start)
            test = self.expr(node.test)
            self.emit("JUMP_IF_FALSE", test, exhausted)
            self.loops.append((end, start))
            for child in node.body:
                self.stmt(child)
            self.loops.pop()
            self.emit("JUMP", start)
            self.mark(exhausted)
            for child in node.orelse:
                self.stmt(child)
            self.mark(end)
        elif isinstance(node, ast.For):
            if not isinstance(node.target, ast.Name):
                raise _Unsupported("for target")
            iterable = self.expr(node.iter)
            iterator = self.alloc()
            self.emit("GET_ITER", iterator, iterable)
            start = self.label()
            exhausted = self.label()
            end = self.label()
            self.mark(start)
            item = self.alloc()
            self.emit("FOR_NEXT", item, iterator, exhausted)
            self.store(node.target, item)
            self.loops.append((end, start))
            for child in node.body:
                self.stmt(child)
            self.loops.pop()
            self.emit("JUMP", start)
            self.mark(exhausted)
            for child in node.orelse:
                self.stmt(child)
            self.mark(end)
        elif isinstance(node, ast.Return):
            value = self.const(None) if node.value is None else self.expr(node.value)
            self.emit("RETURN", value)
        elif isinstance(node, ast.Raise):
            if node.exc is None or node.cause is not None:
                raise _Unsupported("raise")
            self.emit("RAISE", self.expr(node.exc))
        elif isinstance(node, ast.Assert):
            end = self.label()
            test = self.expr(node.test)
            self.emit("JUMP_IF_TRUE", test, end)
            error = self.load("AssertionError")
            message = self.const(None) if node.msg is None else self.expr(node.msg)
            instance = self.alloc()
            self.emit("CALL", instance, error, [message], [])
            self.emit("RAISE", instance)
            self.mark(end)
        elif isinstance(node, ast.Pass):
            return
        elif isinstance(node, ast.Break):
            if not self.loops:
                raise _Unsupported("break")
            self.emit("JUMP", self.loops[-1][0])
        elif isinstance(node, ast.Continue):
            if not self.loops:
                raise _Unsupported("continue")
            self.emit("JUMP", self.loops[-1][1])
        elif isinstance(node, ast.Global):
            self.globals.update(node.names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                module = self.alloc()
                self.emit("IMPORT", module, alias.name, [], 0)
                name = alias.asname or alias.name.split(".")[0]
                self.store(ast.Name(id=name, ctx=ast.Store()), module)
        elif isinstance(node, ast.ImportFrom):
            names = [alias.name for alias in node.names if alias.name != "*"]
            if len(names) != len(node.names):
                raise _Unsupported("star import")
            module = self.alloc()
            self.emit("IMPORT", module, node.module or "", names, node.level)
            for alias in node.names:
                value = self.alloc()
                self.emit("IMPORT_FROM", value, module, alias.name)
                self.store(ast.Name(id=alias.asname or alias.name, ctx=ast.Store()), value)
        elif isinstance(node, ast.Try):
            body = self._sub(node.body)
            handlers = []
            for handler in node.handlers:
                names = self._exc_names(handler.type)
                bind = self.reg(handler.name) if handler.name else -1
                pid = self._sub(handler.body)
                handlers.append([names, bind, pid])
            otherwise = self._sub(node.orelse) if node.orelse else -1
            final = self._sub(node.finalbody) if node.finalbody else -1
            self.emit("TRY", body, handlers, otherwise, final)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            raise _Unsupported("nested scope")
        else:
            raise _Unsupported(type(node).__name__)

    def _exc_names(self, node):
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Tuple):
            names = []
            for item in node.elts:
                if not isinstance(item, ast.Name):
                    raise _Unsupported("exception tuple")
                names.append(item.id)
            return names
        raise _Unsupported("exception type")

    def build(self):
        program = _Program(self.ops)
        self.program = program
        for statement in self.fn.body:
            self.stmt(statement)
        end = self.alloc()
        self.emit("CONST", end, program.const(None))
        self.emit("RETURN", end)
        program.nregs = self.nregs
        program.params = [[name, self.locals[name]] for name in self.params]
        pid = len(self.programs)
        self.programs.append(program)
        return pid


def transform(tree, rng, vm_name, ops, programs, mode="auto"):
    if mode == "off":
        return tree

    def maybe(fn):
        if not isinstance(fn, ast.FunctionDef):
            return
        if any(isinstance(node, (ast.Yield, ast.YieldFrom, ast.Await, ast.AsyncFor,
                                 ast.AsyncWith, ast.Lambda, ast.ListComp, ast.SetComp,
                                 ast.DictComp, ast.GeneratorExp, ast.With, ast.Match,
                                 ast.TryStar))
               for node in ast.walk(fn)):
            return
        snapshot = dict(ops)
        start = len(programs)
        try:
            compiler = _Compiler(ops, programs, fn)
            pid = compiler.build()
            for index in range(start, len(programs)):
                programs[index] = programs[index].finish()
        except _Unsupported:
            ops.clear()
            ops.update(snapshot)
            del programs[start:]
            return
        fn.body = [ast.Return(value=ast.Call(
            func=ast.Name(id=vm_name, ctx=ast.Load()),
            args=[
                ast.Constant(value=pid),
                ast.Call(func=ast.Name(id="locals", ctx=ast.Load()), args=[], keywords=[]),
                ast.Call(func=ast.Name(id="globals", ctx=ast.Load()), args=[], keywords=[]),
            ],
            keywords=[],
        ))]
        fn._pyreobfuscator_vm = True

    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef):
            maybe(statement)
        elif isinstance(statement, ast.ClassDef):
            for child in statement.body:
                if isinstance(child, ast.FunctionDef):
                    maybe(child)
    return tree
