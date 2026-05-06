"""Command-line interface for the JEP authority reference runtime."""

from __future__ import annotations

import argparse
import json
import sys

from .runtime import replay_archive


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jep-authority",
        description="Replay and verify JEP-compatible authority semantics archives.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command in ("replay", "verify"):
        subparser = subcommands.add_parser(command, help=f"{command} archive.jsonl")
        subparser.add_argument("archive", help="Path to a JSON Lines authority archive")
        subparser.add_argument(
            "--json",
            action="store_true",
            help="Emit a machine-readable JSON report",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = replay_archive(args.archive, verify_only=args.command == "verify")
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        status = "ok" if report.ok else "violations"
        print(f"{args.command}: {status} ({report.events} events)")
        for violation in report.violations:
            print(f"line {violation.line}: {violation.event}: {violation.reason}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
