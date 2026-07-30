#!/usr/bin/env python3
"""enterprise_2tier experiment: generate → deploy → verify → destroy.

Each case is a CVE combination from a JSON manifest. Two modes:
  --environment-only : deploy + ansible + smoke-check topology (no Agent)
  default            : full pipeline with Agent flag capture

Usage:
  python3 scripts/verify_2tier.py --case-manifest data/range_matrices/enterprise_2tier_agent.json --max-cases 1 [--environment-only]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

from clab_builder.orchestrator.composer.scenario import ScenarioPipeline
from clab_builder.orchestrator.composer.verifier import ScenarioVerifier


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_manifest_cases(path: str) -> list[dict]:
    raw = json.loads(Path(path).read_text())
    cases = raw.get("cases") if isinstance(raw, dict) else raw
    if not isinstance(cases, list):
        raise SystemExit("Manifest must contain a 'cases' list")
    result = []
    for item in cases:
        if not isinstance(item, dict) or not item.get("id") or not isinstance(item.get("cves"), list):
            raise SystemExit("Every manifest case requires id and cves")
        result.append({
            "id": str(item["id"]),
            "cves": [str(cve) for cve in item["cves"]],
            "purpose": str(item.get("purpose", "")),
        })
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--case-manifest", required=True, help="JSON manifest file")
    p.add_argument("--max-cases", type=int, default=0, help="Max cases to run (0=all)")
    p.add_argument("--offset", type=int, default=0, help="Case index offset")
    p.add_argument("--output", default="data/verify_2tier_output", help="Output directory")
    p.add_argument("--max-turns", type=int, default=80, help="Max agent turns")
    p.add_argument("--agent-timeout", type=int, default=2400, help="Agent subprocess timeout (seconds)")
    p.add_argument("--generate-only", action="store_true", help="Generate scenarios only")
    p.add_argument("--environment-only", action="store_true", help="Deploy + ansible, skip Agent")
    p.add_argument("--resume", action="store_true", help="Resume an interrupted batch")
    p.add_argument("--parallel", type=int, default=1, help="Max parallel case generations (not for agent runs)")
    return p.parse_args(argv)


def _scenario_name(case: dict) -> str:
    digest = hashlib.sha256(case["id"].encode()).hexdigest()[:16]
    return f"e2t-{digest}"


def generate_scenarios(cases: list[dict], args: argparse.Namespace, output_dir: Path) -> list[dict]:
    pipeline = ScenarioPipeline(templates_dir="templates", atoms_dir="data/atoms")
    scenarios_root = output_dir / "scenarios"
    results = []
    for case in cases:
        name = _scenario_name(case)
        try:
            out = pipeline.generate(
                template_name="enterprise_2tier",
                cve_ids=case["cves"],
                scenario_name=name,
                output_dir=str(scenarios_root),
            )
            results.append({
                "case": case,
                "scenario_dir": str(scenarios_root / name),
                "nodes": list(out["clab"]["topology"]["nodes"].keys()),
                "attack_path": [s["target_node"] for s in out["ground_truth"]["attack_path"]],
            })
            print(f"  [{case['id']}] generated: nodes={results[-1]['nodes']} path={results[-1]['attack_path']}")
        except Exception as exc:
            results.append({"case": case, "error": repr(exc)})
            print(f"  [{case['id']}] generation failed: {exc}")
    return results


def run_environment_only(scenario_dir: str) -> dict:
    verifier = ScenarioVerifier()
    try:
        if not verifier._deploy(scenario_dir):
            return {"success": False, "error": "Deploy failed", "environment_success": False}
        verifier._run_ansible(scenario_dir, "base.yaml")
        verifier._run_ansible(scenario_dir, "cve-setup.yaml")
        return {"success": True, "environment_success": True, "attack_graph_valid": True, "attack_path_reachable": True}
    finally:
        verifier._destroy(scenario_dir)


def run_agent_verify(scenario_dir: str, api_key: str, base_url: str, model: str, max_turns: int) -> dict:
    verifier = ScenarioVerifier(max_turns=max_turns)
    return verifier.run_full(scenario_dir=scenario_dir, api_key=api_key, base_url=base_url, model=model)


def summarize(result: dict, case: dict, mode: str) -> dict:
    agent = result.get("agent_result") or {}
    fv = result.get("flag_verification") or {}
    return {
        "case_id": case["id"],
        "purpose": case.get("purpose", ""),
        "cves": case["cves"],
        "mode": mode,
        "success": bool(result.get("success", False)),
        "environment_success": bool(result.get("environment_success", False)),
        "attack_graph_valid": bool(result.get("attack_graph_valid", False)),
        "attack_path_reachable": bool(result.get("attack_path_reachable", False)),
        "agent_success": bool(agent.get("success", False)),
        "objective_achieved": bool(fv.get("all_captured", False)),
        "flags": {
            node: {"match": info.get("match", False), "captured": info.get("captured", "")}
            for node, info in fv.get("per_target", {}).items()
        },
        "error": result.get("error", ""),
    }


def write_summary(results: list[dict], output_dir: Path, meta: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {"created_at": utcnow(), **meta, "results": results}
    (output_dir / "summary.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False))


def _load_state(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text())
    return {"schema_version": 1, "cases": {}}


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False))


def main() -> int:
    args = parse_args()
    os.chdir(ROOT)

    if load_dotenv is not None:
        load_dotenv(ROOT / ".env")

    output_dir = ROOT / args.output
    state_path = output_dir / "batch_state.json"

    # --- Load manifest ---
    all_cases = load_manifest_cases(args.case_manifest)
    selected = all_cases[args.offset:]
    if args.max_cases > 0:
        selected = selected[:args.max_cases]

    api_key = os.getenv("LLM_API_KEY", "")
    base_url = os.getenv("LLM_BASE_URL", "")
    model = os.getenv("LLM_MODEL", "")

    if not args.generate_only and not args.environment_only and not api_key:
        raise SystemExit("LLM_API_KEY is required for Agent mode. Use --generate-only or --environment-only otherwise.")

    # --- Resume or init ---
    if args.resume and state_path.exists():
        state = _load_state(state_path)
    else:
        state = {"schema_version": 1, "created_at": utcnow(), "template": "enterprise_2tier", "cases": {}}
        for case in selected:
            state["cases"][case["id"]] = {
                "case": case, "scenario_dir": str(output_dir / "scenarios" / _scenario_name(case)), "status": "pending",
            }

    # --- Generate ---
    pending = [c for c in selected if state["cases"][c["id"]]["status"] == "pending"]
    generated = []
    for case in pending:
        name = _scenario_name(case)
        scenario_dir = output_dir / "scenarios" / name
        try:
            pipeline = ScenarioPipeline(templates_dir="templates", atoms_dir="data/atoms")
            pipeline.generate(
                template_name="enterprise_2tier", cve_ids=case["cves"],
                scenario_name=name, output_dir=str(output_dir / "scenarios"),
            )
            state["cases"][case["id"]]["status"] = "generated"
            state["cases"][case["id"]]["scenario_dir"] = str(scenario_dir)
            generated.append(case)
            print(f"[{case['id']}] generated: {scenario_dir}")
        except Exception as exc:
            state["cases"][case["id"]]["status"] = "failed"
            state["cases"][case["id"]]["error"] = repr(exc)
            print(f"[{case['id']}] generation failed: {exc}")
        _save_state(state_path, state)

    if args.generate_only:
        results = []
        for case in selected:
            st = state["cases"][case["id"]]
            results.append({
                "case_id": case["id"], "cves": case["cves"],
                "scenario_dir": st.get("scenario_dir", ""),
                "generated": st["status"] == "generated",
                "error": st.get("error", ""),
            })
        write_summary(results, output_dir, {
            "run_id": hashlib.sha256(utcnow().encode()).hexdigest()[:12],
            "template": "enterprise_2tier", "mode": "generate_only",
        })
        print(f"\nDone. {len([r for r in results if r['generated']])}/{len(results)} scenarios generated.")
        return 0

    # --- Verify ---
    mode = "environment_only" if args.environment_only else "agent_full"
    results = []
    for case in generated:
        scenario_dir = state["cases"][case["id"]]["scenario_dir"]
        print(f"\n{'='*60}\n[{case['id']}] verifying (mode={mode})...")
        t0 = time.monotonic()
        try:
            if args.environment_only:
                raw = run_environment_only(scenario_dir)
            else:
                raw = run_agent_verify(scenario_dir, api_key, base_url, model, args.max_turns)
            elapsed = time.monotonic() - t0
            summary = summarize(raw, case, mode)
            summary["elapsed_seconds"] = round(elapsed, 1)
            results.append(summary)
            print(f"[{case['id']}] done in {elapsed:.0f}s, success={summary['success']}, "
                  f"agent={summary['agent_success']}, objective={summary['objective_achieved']}")
            for node, info in summary.get("flags", {}).items():
                print(f"  {node}: {'CAPTURED' if info['match'] else 'MISSED'} -> {info['captured']}")
        except Exception as exc:
            results.append({"case_id": case["id"], "cves": case["cves"], "error": repr(exc), "success": False})
            print(f"[{case['id']}] FAILED: {exc}")

    write_summary(results, output_dir, {
        "run_id": hashlib.sha256(utcnow().encode()).hexdigest()[:12],
        "template": "enterprise_2tier", "mode": mode,
        "max_turns": args.max_turns, "agent_timeout": args.agent_timeout,
    })

    passed = sum(1 for r in results if r.get("success"))
    print(f"\nDone. {passed}/{len(results)} cases passed.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
