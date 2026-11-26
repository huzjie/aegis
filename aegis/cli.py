"""Command-line interface for aegis."""

from __future__ import annotations

import argparse
import json
import sys

from aegis import __version__
from aegis.api import Aegis


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="aegis", description="Linux runtime shielding engine (eBPF/seccomp).")
    ap.add_argument("--version", action="version", version=f"aegis {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("doctor", help="self-check the engine")
    p = sub.add_parser("list", help="list builtin profiles and signatures")
    p = sub.add_parser("signatures", help="list exploit signatures")

    p = sub.add_parser("compile", help="compile a policy to backend artifacts")
    p.add_argument("--policy", required=True)

    p = sub.add_parser("apply", help="compile + (dry-run) apply a policy")
    p.add_argument("--policy", required=True)
    p.add_argument("--backend", default="auto")

    p = sub.add_parser("diff", help="diff two policy files")
    p.add_argument("--old", required=True)
    p.add_argument("--new", required=True)

    p = sub.add_parser("scan", help="scan a process snapshot against signatures")
    p.add_argument("--cmdline", default="")
    p.add_argument("--argv", nargs="*", default=[])
    p.add_argument("--process", default="")

    p = sub.add_parser("gen", help="generate a shield from a natural-language instruction")
    p.add_argument("text", nargs="+")

    p = sub.add_parser("serve", help="start the HTTP control plane")
    p.add_argument("--port", type=int, default=8700)

    args = ap.parse_args(argv)
    engine = Aegis()

    if args.cmd == "doctor":
        results = engine.doctor()
        failed = False
        for k, v in results.items():
            ok = not str(v).startswith("FAIL")
            if not ok:
                failed = True
            print(f"{'✅' if ok else '❌'} {k}: {v}")
        return 1 if failed else 0

    if args.cmd == "list":
        from aegis.policy.defaults import builtin_names
        print("builtin profiles:", builtin_names())
        print("signatures:", [s.id for s in engine._detector.signatures])
        from aegis.backend.factory import BackendFactory
        print("backends:", BackendFactory.available())
        return 0

    if args.cmd == "signatures":
        for s in engine._detector.signatures:
            print(f"  {s.id:<16} {s.severity:<8} {s.cve:<18} {s.name}")
        return 0

    if args.cmd == "compile":
        policy = engine.load(args.policy)
        artifacts = engine.compile(policy)
        for name, art in artifacts.items():
            print(f"  {name}: {art.summary()}")
        return 0

    if args.cmd == "apply":
        policy = engine.load(args.policy)
        artifacts = engine.compile(policy, backend=args.backend)
        for name, art in artifacts.items():
            from aegis.backend.factory import BackendFactory
            status = BackendFactory.create(name).apply(art)
            print(f"  {name}: {status}")
        return 0

    if args.cmd == "diff":
        old = engine.load(args.old)
        new = engine.load(args.new)
        for line in engine.diff(old, new):
            print(f"  {line}")
        return 0

    if args.cmd == "scan":
        snapshot = {"cmdline": args.cmdline, "argv": list(args.argv),
                    "process": args.process}
        dets = engine.scan(snapshot)
        if not dets:
            print("  no signatures matched")
            return 0
        for d in dets:
            print(f"  {d}")
            print(f"    -> shield: {engine.recommend(d)['name']}")
        return 0

    if args.cmd == "gen":
        from aegis.nlgen.parser import NlParser
        from aegis.nlgen.compiler import compile_intent
        text = " ".join(args.text)
        intent = NlParser().parse(text)
        policy = compile_intent(intent)
        print(json.dumps(policy, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "serve":
        from aegis.gateway.server import serve
        serve(port=args.port)
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
