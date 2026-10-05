"""SafeCI command line entry point."""
import argparse
import json
import sys
from pathlib import Path

from .agents import load_agent
from .core import evaluate
from .reports import build_report, compare_reports, write_report
from .scenarios import builtin_scenarios, export_scenarios, load_scenarios, select_adaptive


def main(argv=None):
    parser = argparse.ArgumentParser(prog="safeci", description="Adaptive safety evaluation for AI agents")
    parser.add_argument("--version", action="version", version="SafeCI 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List built-in scenarios")
    export = commands.add_parser("export", help="Export editable scenario fixtures")
    export.add_argument("path", type=Path)
    run = commands.add_parser("run", help="Evaluate an agent and generate JSON + HTML")
    run.add_argument("--agent", default="cautious", help="cautious, vulnerable, or module:factory")
    run.add_argument("--scenarios", type=Path)
    run.add_argument("--output", type=Path, default=Path("reports/latest"))
    run.add_argument("--mode", choices=("enforce", "observe"), default="enforce")
    run.add_argument("--adaptive", action="store_true")
    run.add_argument("--history", type=Path)
    run.add_argument("--step-limit", type=int, default=50)
    run.add_argument("--min-score", type=float, default=100)
    compare = commands.add_parser("compare", help="Compare two reports for CI regressions")
    compare.add_argument("current", type=Path)
    compare.add_argument("baseline", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            for scenario in builtin_scenarios():
                print(f"{scenario.id:38} difficulty={scenario.difficulty} budget={scenario.max_calls}")
            return 0
        if args.command == "export":
            args.path.parent.mkdir(parents=True, exist_ok=True)
            args.path.write_text(json.dumps(export_scenarios(), indent=2) + "\n", encoding="utf-8")
            print(f"Exported 15 scenarios to {args.path}")
            return 0
        if args.command == "compare":
            result = compare_reports(json.loads(args.current.read_text()), json.loads(args.baseline.read_text()))
            print(json.dumps(result, indent=2))
            return 1 if any(result.values()) else 0
        if not 0 <= args.min_score <= 100 or args.step_limit < 1:
            raise ValueError("Score must be 0–100 and step limit must be positive")
        if args.history and not args.adaptive:
            raise ValueError("--history requires --adaptive")
        scenarios = load_scenarios(args.scenarios) if args.scenarios else builtin_scenarios()
        history = json.loads(args.history.read_text()) if args.history else None
        if args.adaptive:
            scenarios = select_adaptive(scenarios, history)
        results = [evaluate(load_agent(args.agent), s, args.mode, args.step_limit) for s in scenarios]
        report = build_report(results, args.agent, args.adaptive)
        write_report(report, args.output)
        print(json.dumps(report["summary"], indent=2))
        print(f"Reports: {args.output / 'report.json'} and {args.output / 'report.html'}")
        return 0 if all(r["safety_score"] >= args.min_score and r["task_success"] for r in results) else 1
    except (OSError, ValueError, KeyError, TypeError, ImportError, AttributeError) as exc:
        print(f"safeci: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
