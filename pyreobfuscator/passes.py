"""AST passes: docstrings, private-name remapping, constant pools, CFF."""

import ast
import random
import string

_DYNAMIC_NAMES = {"locals", "vars", "eval", "exec", "globals"}

_MATCH_CASE = getattr(ast, "match_case", None)
_MATCH = getattr(ast, "Match", None)
_UNSUPPORTED = tuple(
    node for node in (
        ast.Try,
        getattr(ast, "TryStar", None),
        ast.With,
        ast.AsyncWith,
        getattr(ast, "Match", None),
        ast.Yield,
        ast.YieldFrom,
        ast.Await,
        ast.AsyncFor,
    ) if node is not None
)


def strip_docstrings(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr):
                value = body[0].value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    node.body = body[1:]
                    if not node.body and not isinstance(node, ast.Module):
                        node.body = [ast.Pass()]
    return tree


class ConstantPool:
    def __init__(self):
        self.values = []
        self._index = {}

    def add(self, value):
        key = (type(value), value)
        index = self._index.get(key)
        if index is None:
            index = len(self.values)
            self._index[key] = index
            self.values.append(value)
        return index


class _ConstantReplacer(ast.NodeTransformer):
    def __init__(self, pool, table_name, skip_ids, rng, split_numbers):
        self.pool = pool
        self.table_name = table_name
        self.skip_ids = skip_ids
        self.rng = rng
        self.split_numbers = split_numbers

    def _lookup(self, index, node):
        expr = ast.Subscript(
            value=ast.Name(id=self.table_name, ctx=ast.Load()),
            slice=ast.Constant(value=index),
            ctx=ast.Load(),
        )
        return ast.copy_location(expr, node)

    def visit_Constant(self, node):
        if id(node) in self.skip_ids:
            return node
        value = node.value
        if isinstance(value, str) or isinstance(value, bytes):
            return self._lookup(self.pool.add(value), node)
        if self.split_numbers and type(value) is int and (value > 1 or value < -1):
            mask = self.rng.randrange(1, 1 << 20)
            left = ast.BinOp(
                left=ast.Constant(value=value ^ mask),
                op=ast.BitXor(),
                right=ast.Constant(value=mask),
            )
            expr = ast.BinOp(left=left, op=ast.BitXor(), right=ast.Constant(value=mask))
            return ast.copy_location(expr, node)
        return node


def encrypt_constants(tree, pool, table_name, rng, split_numbers=False):
    skip = set()
    if _MATCH_CASE is not None:
        for node in ast.walk(tree):
            if isinstance(node, _MATCH_CASE):
                for pattern in ast.walk(node.pattern):
                    skip.add(id(pattern))
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for child in ast.walk(node):
                if isinstance(child, ast.Constant):
                    skip.add(id(child))
    return _ConstantReplacer(pool, table_name, skip, rng, split_numbers).visit(tree)


def _module_strings_and_attrs(tree):
    strings = set()
    attrs = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.add(node.value)
        elif isinstance(node, ast.Attribute):
            attrs.add(node.attr)
    return strings, attrs


def _module_bound_names(tree):
    bound = set()
    dynamic = False
    star_import = False

    def visit(node, nested=False):
        nonlocal dynamic, star_import
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
            for child in node.decorator_list:
                visit(child, True)
            for child in getattr(node, "bases", []):
                visit(child, True)
            return
        if isinstance(node, ast.Lambda):
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bound.add(alias.asname)
                elif "." not in alias.name:
                    bound.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    star_import = True
                elif alias.asname:
                    bound.add(alias.asname)
                else:
                    bound.add(alias.name)
        elif isinstance(node, ast.Global):
            bound.update(node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _DYNAMIC_NAMES:
                dynamic = True
        for child in ast.iter_child_nodes(node):
            visit(child, nested)

    for stmt in tree.body:
        visit(stmt)
    return bound, dynamic, star_import


def _new_name(rng, used):
    alphabet = string.ascii_lowercase + string.digits
    while True:
        name = "_" + "".join(rng.choice(alphabet) for _ in range(8))
        if name not in used:
            used.add(name)
            return name


def _all_arg_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.arg):
            names.add(node.arg)
    return names


def rename_private(tree, reserved=(), rng=None):
    rng = rng or random.Random()
    bound, dynamic, star_import = _module_bound_names(tree)
    strings, attrs = _module_strings_and_attrs(tree)
    if dynamic or star_import:
        return {}
    local_args = _all_arg_names(tree)
    candidates = {
        name for name in bound
        if name.startswith("_")
        and not name.startswith("__")
        and not name.endswith("__")
        and name != "_"
        and name not in reserved
        and name not in strings
        and name not in attrs
        and name not in local_args
    }
    if not candidates:
        return {}
    used = set(bound) | set(reserved)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            used.add(node.value)
    mapping = {name: _new_name(rng, used) for name in sorted(candidates)}

    class Renamer(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in mapping:
                node.id = mapping[node.id]
            return node

        def visit_Global(self, node):
            node.names = [mapping.get(name, name) for name in node.names]
            return node

        def visit_Nonlocal(self, node):
            node.names = [mapping.get(name, name) for name in node.names]
            return node

        def visit_ExceptHandler(self, node):
            if node.name in mapping:
                node.name = mapping[node.name]
            self.generic_visit(node)
            return node

        def visit_FunctionDef(self, node):
            if node.name in mapping:
                node.name = mapping[node.name]
            self.generic_visit(node)
            return node

        def visit_AsyncFunctionDef(self, node):
            if node.name in mapping:
                node.name = mapping[node.name]
            self.generic_visit(node)
            return node

        def visit_ClassDef(self, node):
            if node.name in mapping:
                node.name = mapping[node.name]
            self.generic_visit(node)
            return node

        def visit_Import(self, node):
            for alias in node.names:
                if alias.asname and alias.asname in mapping:
                    alias.asname = mapping[alias.asname]
                elif not alias.asname and "." not in alias.name and alias.name in mapping:
                    alias.asname = mapping[alias.name]
            return node

        def visit_ImportFrom(self, node):
            for alias in node.names:
                if alias.name == "*":
                    continue
                if alias.asname and alias.asname in mapping:
                    alias.asname = mapping[alias.asname]
                elif not alias.asname and alias.name in mapping:
                    alias.asname = mapping[alias.name]
            return node

    Renamer().visit(tree)
    return mapping


def _has_dynamic_calls(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else None)
            if name in {"locals", "vars", "eval", "exec"}:
                return True
    return False


def _has_nested_scope(node):
    for child in ast.walk(node):
        if child is node:
            continue
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef,
                              ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return True
    return False


def _has_unsupported_locals(node):
    for child in ast.walk(node):
        if isinstance(child, (ast.Global, ast.Nonlocal, ast.Import, ast.ImportFrom)):
            return True
        if _MATCH is not None and isinstance(child, _MATCH):
            return True
    return False


def rename_locals(tree, rng=None):
    rng = rng or random.Random()

    class Renamer(ast.NodeTransformer):
        def __init__(self, mapping):
            self.mapping = mapping

        def visit_Name(self, node):
            if node.id in self.mapping:
                node.id = self.mapping[node.id]
            return node

        def visit_ExceptHandler(self, node):
            if node.name in self.mapping:
                node.name = self.mapping[node.name]
            self.generic_visit(node)
            return node

    def process(fn):
        if _has_nested_scope(fn) or _has_dynamic_calls(fn) or _has_unsupported_locals(fn):
            return
        args = set()
        for arg in list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs):
            args.add(arg.arg)
        if fn.args.vararg:
            args.add(fn.args.vararg.arg)
        if fn.args.kwarg:
            args.add(fn.args.kwarg.arg)
        bound = set()
        strings = set()

        def walk(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                strings.add(node.value)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                bound.add(node.id)
            if isinstance(node, ast.ExceptHandler) and node.name:
                bound.add(node.name)
            for child in ast.iter_child_nodes(node):
                walk(child)

        for statement in fn.body:
            walk(statement)
        candidates = {
            name for name in bound
            if name not in args
            and name not in strings
            and not name.startswith("__")
            and not name.endswith("__")
            and name != "_"
        }
        if not candidates:
            return
        used = set(bound) | args | strings
        mapping = {name: _new_name(rng, used) for name in sorted(candidates)}
        renamer = Renamer(mapping)
        for statement in fn.body:
            renamer.visit(statement)

    class Walker(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            self.generic_visit(node)
            process(node)
            return node

        def visit_AsyncFunctionDef(self, node):
            self.generic_visit(node)
            process(node)
            return node

    Walker().visit(tree)
    return tree


class _Label:
    __slots__ = ("number",)

    def __init__(self, number):
        self.number = number


class _Block:
    __slots__ = ("label", "stmts", "term")

    def __init__(self, label, stmts, term):
        self.label = label
        self.stmts = stmts
        self.term = term


_SIMPLE = (
    ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Expr, ast.Pass, ast.Delete,
    ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal, ast.Assert,
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
)


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _has_loop(node):
    def scan(current):
        for child in ast.iter_child_nodes(current):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(child, (ast.For, ast.AsyncFor, ast.While)):
                return True
            if scan(child):
                return True
        return False

    return scan(node)


def _unsupported(fn):
    def scan(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            if isinstance(child, _UNSUPPORTED):
                return True
            if isinstance(child, ast.Call) and _call_name(child.func) in _DYNAMIC_NAMES:
                return True
            if scan(child):
                return True
        return False

    return scan(fn)


def _statement_count(stmts):
    total = 0
    for node in stmts:
        total += 1
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                total += _statement_count([child])
    return total


class _Flattener:
    def __init__(self, state_name, iter_name, next_name, stop_name, rng):
        self.state_name = state_name
        self.iter_name = iter_name
        self.next_name = next_name
        self.stop_name = stop_name
        self.rng = rng
        self.blocks = []
        self._label_counter = 0
        self._temp_counter = 0
        self._mask = rng.randrange(1 << 20, 1 << 30)

    def _label(self):
        label = _Label(self._label_counter)
        self._label_counter += 1
        return label

    def _add(self, stmts, term, label=None):
        label = label or self._label()
        self.blocks.append(_Block(label, stmts, term))
        return label

    def _temp(self):
        self._temp_counter += 1
        return "_%si%d" % (self.state_name[-6:], self._temp_counter)

    def _enc(self, value):
        return value ^ self._mask

    def _state_assign(self, label):
        target = label.number if label is not None else -1
        return ast.Assign(
            targets=[ast.Name(id=self.state_name, ctx=ast.Store())],
            value=ast.Constant(value=self._enc(target)),
        )

    def _goto_block(self, label):
        return [self._state_assign(label)]

    def _seq(self, stmts, next_label, loops):
        tail = next_label
        pending = []
        for node in reversed(stmts):
            if isinstance(node, _SIMPLE):
                pending.append(node)
                continue
            if pending:
                tail = self._add(list(reversed(pending)), ("goto", tail))
                pending = []
            tail = self._stmt(node, tail, loops)
        if pending:
            tail = self._add(list(reversed(pending)), ("goto", tail))
        return tail

    def _stmt(self, node, tail, loops):
        if isinstance(node, ast.If):
            body = self._seq(node.body, tail, loops)
            orelse = self._seq(node.orelse, tail, loops)
            return self._add([], ("if", node.test, body, orelse))
        if isinstance(node, ast.While):
            check = self._label()
            after = tail
            body = self._seq(node.body, check, loops + [(after, check)])
            orelse = self._seq(node.orelse, after, loops)
            self._add([], ("if", node.test, body, orelse), label=check)
            return check
        if isinstance(node, ast.For):
            check = self._label()
            after = tail
            iterator = self._temp()
            orelse = self._seq(node.orelse, after, loops)
            body = self._seq(node.body, check, loops + [(after, check)])
            try_node = ast.Try(
                body=[ast.Assign(
                    targets=[node.target],
                    value=ast.Call(
                        func=ast.Name(id=self.next_name, ctx=ast.Load()),
                        args=[ast.Name(id=iterator, ctx=ast.Load())],
                        keywords=[],
                    ),
                )],
                handlers=[ast.ExceptHandler(
                    type=ast.Name(id=self.stop_name, ctx=ast.Load()),
                    name=None,
                    body=[self._state_assign(orelse)],
                )],
                orelse=[self._state_assign(body)],
                finalbody=[],
            )
            self._add([try_node], ("none",), label=check)
            init = ast.Assign(
                targets=[ast.Name(id=iterator, ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id=self.iter_name, ctx=ast.Load()),
                    args=[node.iter],
                    keywords=[],
                ),
            )
            return self._add([init], ("goto", check))
        if isinstance(node, ast.Return):
            return self._add([node], ("none",))
        if isinstance(node, ast.Raise):
            return self._add([node], ("none",))
        if isinstance(node, ast.Break):
            if not loops:
                return tail
            return self._add([], ("goto", loops[-1][0]))
        if isinstance(node, ast.Continue):
            if not loops:
                return tail
            return self._add([], ("goto", loops[-1][1]))
        return self._add([node], ("goto", tail))

    def build(self, fn):
        body = fn.body
        if not body:
            return fn
        entry = self._seq(body, None, [])
        order = list(range(len(self.blocks)))
        self.rng.shuffle(order)
        dispatcher = []
        if not self.blocks:
            return fn
        chain = None
        for index in reversed(order):
            block = self.blocks[index]
            stmts = list(block.stmts)
            term = block.term
            if term[0] == "goto":
                stmts.append(self._state_assign(term[1]))
            elif term[0] == "if":
                stmts.append(ast.If(
                    test=term[1],
                    body=[self._state_assign(term[2])],
                    orelse=[self._state_assign(term[3])],
                ))
            if chain is None:
                chain = ast.If(
                    test=ast.Compare(
                        left=ast.Name(id=self.state_name, ctx=ast.Load()),
                        ops=[ast.Eq()],
                        comparators=[ast.Constant(value=self._enc(block.label.number))],
                    ),
                    body=stmts,
                    orelse=[ast.Break()],
                )
            else:
                chain = ast.If(
                    test=ast.Compare(
                        left=ast.Name(id=self.state_name, ctx=ast.Load()),
                        ops=[ast.Eq()],
                        comparators=[ast.Constant(value=self._enc(block.label.number))],
                    ),
                    body=stmts,
                    orelse=[chain],
                )
        dispatcher = [
            ast.Assign(
                targets=[ast.Name(id=self.state_name, ctx=ast.Store())],
                value=ast.Constant(value=self._enc(entry.number)),
            ),
            ast.While(test=ast.Constant(value=True), body=[chain], orelse=[]),
            ast.Return(value=ast.Constant(value=None)),
        ]
        fn.body = dispatcher
        return fn


def _collect_declarations(stmts, globals_, nonlocals):
    cleaned = []
    for stmt in stmts:
        if isinstance(stmt, ast.Global):
            globals_.update(stmt.names)
            continue
        if isinstance(stmt, ast.Nonlocal):
            nonlocals.update(stmt.names)
            continue
        if isinstance(stmt, ast.If):
            stmt.body = _collect_declarations(stmt.body, globals_, nonlocals)
            stmt.orelse = _collect_declarations(stmt.orelse, globals_, nonlocals)
        elif isinstance(stmt, ast.While):
            stmt.body = _collect_declarations(stmt.body, globals_, nonlocals)
            stmt.orelse = _collect_declarations(stmt.orelse, globals_, nonlocals)
        elif isinstance(stmt, ast.For):
            stmt.body = _collect_declarations(stmt.body, globals_, nonlocals)
            stmt.orelse = _collect_declarations(stmt.orelse, globals_, nonlocals)
        cleaned.append(stmt)
    return cleaned


class _CFF(ast.NodeTransformer):
    def __init__(self, threshold, rng, iter_name, next_name, stop_name, skip_loops=False):
        self.threshold = threshold
        self.rng = rng
        self.iter_name = iter_name
        self.next_name = next_name
        self.stop_name = stop_name
        self.skip_loops = skip_loops

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        return self._maybe_flatten(node)

    def visit_AsyncFunctionDef(self, node):
        self.generic_visit(node)
        return node

    def _maybe_flatten(self, node):
        if getattr(node, "_pyreobfuscator_vm", False):
            return node
        if self.skip_loops and _has_loop(node):
            return node
        if _unsupported(node):
            return node
        if _statement_count(node.body) < self.threshold:
            return node
        globals_ = set()
        nonlocals = set()
        node.body = _collect_declarations(node.body, globals_, nonlocals)
        state_name = "_" + "".join(self.rng.choice(string.ascii_lowercase) for _ in range(8)) + "s"
        flattener = _Flattener(state_name, self.iter_name, self.next_name, self.stop_name, self.rng)
        flattened = flattener.build(node)
        prefix = []
        if globals_:
            prefix.append(ast.Global(names=sorted(globals_)))
        if nonlocals:
            prefix.append(ast.Nonlocal(names=sorted(nonlocals)))
        if prefix:
            flattened.body = prefix + flattened.body
        return flattened


def flatten(tree, threshold=3, rng=None, iter_name="__pb_iter", next_name="__pb_next",
            stop_name="__pb_stop", skip_loops=False):
    rng = rng or random.Random()
    if threshold <= 0:
        return tree
    return _CFF(threshold, rng, iter_name, next_name, stop_name, skip_loops).visit(tree)
