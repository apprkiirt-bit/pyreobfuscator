"""Command line entry point."""

import argparse
import subprocess
import sys

from . import builder


def _build_parser():
    parser = argparse.ArgumentParser(prog="pyreobfuscator")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="obfuscate a project")
    build.add_argument("path")
    build.add_argument("-o", "--out", default="")
    build.add_argument("--entry", default="")
    build.add_argument("--cff", choices=("auto", "all", "off"), default="auto")
    build.add_argument("--vm", choices=("auto", "all", "off"), default="auto")
    build.add_argument("--threshold", type=int, default=0)
    build.add_argument("--numbers", action="store_true")
    build.add_argument("--no-rename", action="store_true")
    build.add_argument("--no-rename-locals", action="store_true")
    build.add_argument("--no-checks", action="store_true")
    build.add_argument("--no-selfhash", action="store_true")
    build.add_argument("--no-antidebug", action="store_true")
    build.add_argument("--no-audit", action="store_true")
    build.add_argument("--no-strict-env", action="store_true")
    build.add_argument("--watchdog", type=float, default=5.0)
    build.add_argument("--seed", type=int, default=None)

    run = sub.add_parser("run", help="build and run")
    run.add_argument("path")
    run.add_argument("--entry", default="")
    run.add_argument("--seed", type=int, default=None)
    return parser


def _options(args):
    return builder.BuildOptions(
        path=args.path,
        out=getattr(args, "out", ""),
        entry=getattr(args, "entry", ""),
        cff=getattr(args, "cff", "auto"),
        vm=getattr(args, "vm", "auto"),
        threshold=getattr(args, "threshold", 0),
        numbers=getattr(args, "numbers", False),
        rename=not getattr(args, "no_rename", False),
        rename_locals=not getattr(args, "no_rename_locals", False),
        checks=not getattr(args, "no_checks", False),
        selfhash=not getattr(args, "no_selfhash", False),
        antidebug=not getattr(args, "no_antidebug", False),
        audit=not getattr(args, "no_audit", False),
        strict_env=not getattr(args, "no_strict_env", False),
        watchdog=getattr(args, "watchdog", 5.0),
        seed=getattr(args, "seed", None),
    )


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "build":
        out = builder.build(_options(args))
        print(out)
        return 0
    out = builder.build(_options(args))
    return subprocess.call([sys.executable, str(out)])


if __name__ == "__main__":
    raise SystemExit(main())
